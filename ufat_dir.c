/* uFAT -- small flexible VFAT implementation
 * Copyright (C) 2012 TracMap Holdings Ltd
 *
 * Author: Daniel Beer <dlbeer@gmail.com>, www.dlbeer.co.nz
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <string.h>
#include "ufat.h"
#include "ufat_internal.h"

void ufat_open_root(struct ufat *uf, struct ufat_directory *dir)
{
	if (uf->bpb.root_cluster)
		dir->start = cluster_to_block(&uf->bpb, uf->bpb.root_cluster);
	else
		dir->start = uf->bpb.root_start;

	dir->uf = uf;
	dir->cur_block = dir->start;
	dir->cur_pos = 0;
}

int ufat_open_subdir(struct ufat *uf, struct ufat_directory *dir,
		     const struct ufat_dirent *ent)
{
	if (!(ent->attributes & UFAT_ATTR_DIRECTORY))
		return -UFAT_ERR_NOT_DIRECTORY;

	if (!ent->first_cluster) {
		ufat_open_root(uf, dir);
		return 0;
	}

	dir->start = cluster_to_block(&uf->bpb, ent->first_cluster);
	dir->cur_block = dir->start;
	dir->cur_pos = 0;

	return 0;
}

void ufat_dir_rewind(struct ufat_directory *dir)
{
	dir->cur_block = dir->start;
	dir->cur_pos = 0;
}

static int next_block_in_chain(struct ufat *uf,
			       ufat_block_t blk, ufat_block_t *next_out)
{
	const struct ufat_bpb *bpb = &uf->bpb;
	ufat_block_t next = blk + 1;

	if ((next ^ blk) >> bpb->log2_blocks_per_cluster) {
		ufat_cluster_t c = 0;
		int err = ufat_read_fat(uf, block_to_cluster(bpb, blk), &c);

		if (err < 0)
			return err;

		if (UFAT_CLUSTER_IS_PTR(c))
			next = cluster_to_block(bpb, c);
		else
			next = UFAT_BLOCK_NONE;
	}

	*next_out = next;
	return 0;
}

static int read_raw_dirent(struct ufat_directory *dir, uint8_t *data)
{
	int idx;

	if (dir->cur_block == UFAT_BLOCK_NONE)
		return 1;

	idx = ufat_cache_open(dir->uf, dir->cur_block);
	if (idx < 0)
		return idx;

	memcpy(data, ufat_cache_data(dir->uf, idx) +
	       dir->cur_pos * UFAT_DIRENT_SIZE,
	       UFAT_DIRENT_SIZE);

	/* Advance the dirent pointer and check for a block overrun */
	dir->cur_pos++;
	if (dir->cur_pos * UFAT_DIRENT_SIZE >=
	    (1 << dir->uf->dev->log2_block_size)) {
		dir->cur_pos = 0;

		if (dir->cur_block < dir->uf->bpb.cluster_start) {
			/* FAT12/16 root directory */
			dir->cur_block++;
			if (dir->cur_block >= dir->uf->bpb.cluster_start)
				dir->cur_block = UFAT_BLOCK_NONE;
		} else {
			int err = next_block_in_chain(dir->uf,
						      dir->cur_block,
						      &dir->cur_block);

			if (err < 0)
				return err;
		}
	}

	return 0;
}

struct lfn_state {
	int		len;
	int		seq;
	uint16_t	buf[UFAT_LFN_MAX_CHARS];
};

static inline void lfn_parse_reset(struct lfn_state *s)
{
	s->seq = -1;
}

static void lfn_parse_ent(struct lfn_state *s, const uint8_t *data)
{
	const int fr_seq = data[0];
	uint16_t frag_data[13];
	int fr_pos;
	int fr_len;
	int i;

	fr_pos = ((fr_seq & 0x3f) - 1) * 13;
	fr_len = 13;
	if (fr_pos + fr_len > UFAT_LFN_MAX_CHARS)
		fr_len = UFAT_LFN_MAX_CHARS - fr_pos;

	/* Check against expected sequence number */
	if (fr_seq & 0x40) {
		s->seq = fr_seq & 0x3f;
		s->len = fr_pos + fr_len;
	} else if (fr_seq != s->seq) {
		lfn_parse_reset(s);
		return;
	}
	s->seq--;

	/* Unpack and copy fragment */
	for (i = 0; i < 5; i++)
		frag_data[i] = r16(data + 0x01 + i * 2);
	for (i = 0; i < 6; i++)
		frag_data[i + 5] = r16(data + 0x0e + i * 2);
	frag_data[11] = r16(data + 0x1c);
	frag_data[12] = r16(data + 0x1e);

	for (i = 0; i < fr_len; i++)
		s->buf[fr_pos + i] = frag_data[i];

	/* Trim trailing spaces */
	if (fr_seq & 0x40)
		while (s->len && s->buf[s->len - 1] == ' ')
			s->len--;
}

static inline int lfn_parse_ok(const struct lfn_state *s)
{
	return s->seq == 0;
}

static void sn_copy(const uint8_t *src, char *dst, int len)
{
	int i;

	for (i = 0; i < len && src[i] > ' '; i++)
		dst[i] = src[i];

	dst[i] = 0;
}

static void parse_dirent(ufat_fat_type_t type,
			 const uint8_t *data, struct ufat_dirent *inf)
{
	sn_copy(data, inf->short_name, 8);
	sn_copy(data + 0x08, inf->short_ext, 3);

	inf->attributes = data[0x0b];
	inf->create_time = r16(data + 0x0e);
	inf->create_date = r16(data + 0x10);
	inf->access_date = r16(data + 0x12);
	inf->modify_time = r16(data + 0x16);
	inf->modify_date = r16(data + 0x18);
	inf->file_size = r32(data + 0x1c);
	inf->first_cluster = r16(data + 0x1a);

	if (type == UFAT_TYPE_FAT32) {
		uint32_t high = r16(data + 0x14);

		inf->first_cluster |= high << 16;
	}
}

static int ucs2_to_utf8(const uint16_t *src, int src_len,
			char *dst, int dst_len)
{
	int i;
	int j = 0;

	for (i = 0; i < src_len; i++) {
		uint16_t c = src[i];

		if (c >= 0x800) {
			if (j + 3 >= dst_len)
				return -1;

			dst[j++] = 0xe0 | (c >> 12);
			dst[j++] = 0x80 | ((c >> 6) & 0x3f);
			dst[j++] = 0x80 | (c & 0x3f);
		} else if (c >= 0x80) {
			if (j + 2 >= dst_len)
				return -1;

			dst[j++] = 0xc0 | c >> 6;
			dst[j++] = 0x80 | (c & 0x3f);
		} else {
			if (j + 1 >= dst_len)
				return -1;

			dst[j++] = c;
		}
	}

	if (j >= dst_len)
		return -1;

	dst[j] = 0;
	return 0;
}

static int format_short(const char *name, const char *ext,
			char *out, int max_len)
{
	int i;

	while (*name) {
		if (i >= max_len)
			return -1;

		out[i++] = *(name++);
	}

	if (*ext) {
		if (i >= max_len)
			return -1;
		out[i++] = '.';

		while (*ext) {
			if (i >= max_len)
				return -1;
			out[i++] = *(ext++);
		}
	}

	if (i >= max_len)
		return -1;

	out[i] = 0;
	return 0;
}

static int format_name(const struct lfn_state *lfn,
		       const struct ufat_dirent *inf,
		       char *lfn_buf, int max_len)
{
	if (lfn_parse_ok(lfn)) {
		if (ucs2_to_utf8(lfn->buf, lfn->len,
				 lfn_buf, max_len) < 0)
			return -UFAT_ERR_NAME_TOO_LONG;
	} else {
		if (format_short(inf->short_name,
				 inf->short_ext,
				 lfn_buf, max_len) < 0)
			return -UFAT_ERR_NAME_TOO_LONG;
	}

	return 0;
}

int ufat_dir_read(struct ufat_directory *dir, struct ufat_dirent *inf,
		  char *lfn_buf, int max_len)
{
	struct lfn_state lfn;

	lfn_parse_reset(&lfn);

	for (;;) {
		uint8_t data[UFAT_DIRENT_SIZE];
		int err;

		inf->dirent_block = dir->cur_block;
		inf->dirent_pos = dir->cur_pos;

		err = read_raw_dirent(dir, data);
		if (err)
			return err;

		if (data[0x0b] == 0x0f && data[0] != 0xe5) {
			lfn_parse_ent(&lfn, data);
		} else if (data[0] && data[0] != 0xe5) {
			parse_dirent(dir->uf->bpb.type, data, inf);

			if (inf->attributes & 0x08)
				continue;

			if (lfn_buf &&
			    format_name(&lfn, inf, lfn_buf, max_len) < 0)
				return -UFAT_ERR_NAME_TOO_LONG;

			return 0;
		} else {
			lfn_parse_reset(&lfn);
		}
	}

	return 0;
}

int ufat_dir_find(struct ufat_directory *dir,
		  const char *target, struct ufat_dirent *inf)
{
	ufat_dir_rewind(dir);

	for (;;) {
		char name[UFAT_LFN_MAX_UTF8];
		int err = ufat_dir_read(dir, inf, name, sizeof(name));

		if (err)
			return err;

		if (!strcasecmp(name, target))
			break;
	}

	return 0;
}

int ufat_dir_find_path(struct ufat_directory *dir,
		       const char *path, struct ufat_dirent *ent)
{
	struct ufat_directory dir_local;
	int at_root = 1;

	memcpy(&dir_local, dir, sizeof(dir_local));
	ufat_dir_rewind(dir);

	while (*path) {
		int len = 0;

		while (path[len] && path[len] != '/' && path[len] != '\\')
			len++;

		/* Ignore blank components */
		if (!len) {
			path++;
			continue;
		}

		/* Descend if necessary */
		if (!at_root) {
			int err = ufat_open_subdir(dir_local.uf, &dir_local,
						   ent);

			if (err < 0)
				return err;
		}

		/* Search for this component */
		for (;;) {
			char name[UFAT_LFN_MAX_UTF8];
			int err = ufat_dir_read(&dir_local, ent,
						name, sizeof(name));

			if (err)
				return err;

			if (!strncasecmp(name, path, len) && !name[len])
				break;
		}

		/* Skip over this component */
		path += len;
		if (*path)
			path++;
		at_root = 0;
	}

	if (at_root) {
		/* Pseudo-dirent for root directory */
		memset(ent, 0, sizeof(*ent));
		ent->dirent_block = UFAT_BLOCK_NONE;
		ent->attributes = UFAT_ATTR_DIRECTORY;
	}

	return 0;
}
