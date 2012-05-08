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
#include <ctype.h>
#include <stdlib.h>
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

	dir->uf = uf;
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

static int write_raw_dirent(struct ufat_directory *dir,
			    const uint8_t *data, unsigned int len)
{
	int idx;

	if (dir->cur_block == UFAT_BLOCK_NONE)
		return -UFAT_ERR_IO;

	idx = ufat_cache_open(dir->uf, dir->cur_block);
	if (idx < 0)
		return idx;

	ufat_cache_write(dir->uf, idx);
	memcpy(ufat_cache_data(dir->uf, idx) +
	       dir->cur_pos * UFAT_DIRENT_SIZE,
	       data, len);

	return 0;
}

static int init_dirent_cluster(struct ufat *uf, ufat_cluster_t c)
{
	const struct ufat_bpb *bpb = &uf->bpb;
	const ufat_block_t start = cluster_to_block(bpb, c);
	const unsigned int count =
		1 << bpb->log2_blocks_per_cluster;
	const unsigned int block_size = 1 << uf->dev->log2_block_size;
	int i;

	for (i = count - 1; i >= 0; i--) {
		int idx = ufat_cache_open(uf, start + i);

		if (idx < 0)
			return idx;

		ufat_cache_write(uf, idx);
		memset(ufat_cache_data(uf, idx), 0, block_size);
	}

	return 0;
}

static int advance_block_in_chain(struct ufat_directory *dir, int can_alloc)
{
	const struct ufat_bpb *bpb = &dir->uf->bpb;
	const ufat_cluster_t cur_cluster =
		block_to_cluster(bpb, dir->cur_block);
	ufat_block_t next_block = dir->cur_block + 1;
	ufat_cluster_t next_cluster = block_to_cluster(bpb, next_block);
	int err;

	if (cur_cluster == next_cluster) {
		dir->cur_block = next_block;
		return 0;
	}

	/* We've crossed a cluster boundary. Look up the next cluster in
	 * the FAT.
	 */
	err = ufat_read_fat(dir->uf, cur_cluster, &next_cluster);
	if (err < 0)
		return err;

	if (UFAT_CLUSTER_IS_PTR(next_cluster)) {
		dir->cur_block = cluster_to_block(bpb, next_cluster);
		return 0;
	}

	/* This is the end of the chain. If we can't allocate, we're done. */
	if (!can_alloc) {
		dir->cur_block = UFAT_BLOCK_NONE;
		return 0;
	}

	/* Try to get a new cluster */
	err = ufat_alloc_chain(dir->uf, 1, &next_cluster);
	if (err < 0)
		return err;

	err = init_dirent_cluster(dir->uf, next_cluster);
	if (err < 0) {
		ufat_free_chain(dir->uf, next_cluster);
		return err;
	}

	err = ufat_write_fat(dir->uf, cur_cluster, next_cluster);
	if (err < 0) {
		ufat_free_chain(dir->uf, next_cluster);
		return err;
	}

	dir->cur_block = cluster_to_block(bpb, next_cluster);
	return 0;
}

static int advance_raw_dirent(struct ufat_directory *dir, int can_alloc)
{
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

			return 0;
		}

		return advance_block_in_chain(dir, can_alloc);
	}

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

	return 0;
}

static int allocate_raw_dirent(struct ufat_directory *dir, unsigned int count)
{
	ufat_block_t empty_start;
	int empty_pos;
	int empty_count = 0;

	ufat_dir_rewind(dir);

	for (;;) {
		uint8_t data[UFAT_DIRENT_SIZE];
		int err;

		err = read_raw_dirent(dir, data);
		if (err < 0)
			return -1;

		/* Check to see if this raw dirent is empty. Keep track
		 * of contiguous chains of empty dirents.
		 */
		if (!data[0] || data[0] == 0xe5) {
			if (!empty_count) {
				empty_start = dir->cur_block;
				empty_pos = dir->cur_pos;
			}

			empty_count++;
		} else {
			empty_count = 0;
		}

		/* Is this chain long enough? */
		if (empty_count >= count)
			break;

		err = advance_raw_dirent(dir, 1);
		if (err < 0)
			return -1;

		if (dir->cur_block == UFAT_BLOCK_NONE)
			return -UFAT_ERR_DIRECTORY_FULL;
	}

	/* Reposition at the start of the empty chain */
	dir->cur_block = empty_start;
	dir->cur_pos = empty_pos;

	return 0;
}

static void pack_dirent(const struct ufat_dirent *ent, uint8_t *data)
{
	memset(data, 0x20, 11);
	memcpy(data, ent->short_name, strlen(ent->short_name));
	memcpy(data + 0x08, ent->short_ext, strlen(ent->short_ext));

	data[0x0b] = ent->attributes;
	data[0x0c] = 0;
	data[0x0d] = 0;
	w16(data + 0x0e, ent->create_time);
	w16(data + 0x10, ent->create_date);
	w16(data + 0x12, ent->access_date);
	w16(data + 0x14, ent->first_cluster >> 16);
	w16(data + 0x16, ent->modify_time);
	w16(data + 0x18, ent->modify_date);
	w16(data + 0x1a, ent->first_cluster & 0xffff);
	w32(data + 0x1c, ent->file_size);
}

struct lfn_state {
	ufat_block_t	start_block;
	unsigned int	start_pos;

	int		len;
	int		seq;
	uint16_t	buf[UFAT_LFN_MAX_CHARS];
};

static inline void lfn_parse_reset(struct lfn_state *s)
{
	s->seq = -1;
}

static void lfn_parse_ent(struct lfn_state *s, const uint8_t *data,
			  ufat_block_t blk, unsigned int pos)
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
		s->start_block = blk;
		s->start_pos = pos;
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

		err = advance_raw_dirent(dir, 0);
		if (err)
			return err;

		if (data[0x0b] == 0x0f && data[0] != 0xe5) {
			lfn_parse_ent(&lfn, data,
				      inf->dirent_block, inf->dirent_pos);
		} else if (data[0] && data[0] != 0xe5) {
			parse_dirent(dir->uf->bpb.type, data, inf);

			if (inf->attributes & 0x08)
				continue;

			if (lfn_parse_ok(&lfn)) {
				inf->lfn_block = lfn.start_block;
				inf->lfn_pos = lfn.start_pos;
			} else {
				inf->lfn_block = UFAT_BLOCK_NONE;
				inf->lfn_pos = 0;
			}

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

static int verify_empty_dir(struct ufat *uf, struct ufat_dirent *ent)
{
	struct ufat_directory dir;
	int err;

	err = ufat_open_subdir(uf, &dir, ent);
	if (err < 0)
		return err;

	for (;;) {
		struct ufat_dirent e;

		err = ufat_dir_read(&dir, &e, NULL, 0);
		if (err < 0)
			return err;

		if (err)
			break;

		if (e.short_name[0] != '.')
			return -UFAT_ERR_DIRECTORY_NOT_EMPTY;
	}

	return 0;
}

static int delete_entry(struct ufat *uf, struct ufat_dirent *ent)
{
	const static uint8_t del_marker = 0xe5;
	struct ufat_directory dir;

	dir.uf = uf;

	if (ent->lfn_block == UFAT_BLOCK_NONE) {
		dir.cur_block = ent->dirent_block;
		dir.cur_pos = ent->dirent_pos;
	} else {
		dir.cur_block = ent->lfn_block;
		dir.cur_pos = ent->lfn_pos;
	}

	for (;;) {
		int err;

		err = write_raw_dirent(&dir, &del_marker, 1);
		if (err < 0)
			return -1;

		if (dir.cur_block == ent->dirent_block &&
		    dir.cur_pos == ent->dirent_pos)
			break;

		err = advance_raw_dirent(&dir, 0);
		if (err < 0)
			return -1;
	}

	return 0;
}

int ufat_dir_delete(struct ufat *uf, struct ufat_dirent *ent)
{
	int err;

	if (!ent->first_cluster || ent->short_name[0] == '.')
		return -UFAT_ERR_IMMUTABLE;

	if (ent->attributes & UFAT_ATTR_DIRECTORY) {
		err = verify_empty_dir(uf, ent);
		if (err < 0)
			return err;
	}

	err = delete_entry(uf, ent);
	if (err < 0)
		return err;

	return ufat_free_chain(uf, ent->first_cluster);
}

/* Create a new empty subdirectory and return it. */
static int create_empty_dir(struct ufat_directory *parent,
			    ufat_cluster_t *out,
			    const struct ufat_dirent *downptr)
{
	struct ufat_dirent ent;
	ufat_cluster_t c;
	int err = ufat_alloc_chain(parent->uf, 1, &c);
	int idx;

	if (err < 0)
		return err;

	/* Clear all entries */
	err = init_dirent_cluster(parent->uf, c);
	if (err < 0) {
		ufat_free_chain(parent->uf, c);
		return err;
	}

	/* Get the first block of the dirent */
	idx = ufat_cache_open(parent->uf,
			      cluster_to_block(&parent->uf->bpb, c));
	if (idx < 0) {
		ufat_free_chain(parent->uf, c);
		return idx;
	}

	ufat_cache_write(parent->uf, idx);

	/* Create "." */
	memcpy(&ent, downptr, sizeof(ent));
	ent.short_name[0] = '.';
	ent.short_name[1] = 0;
	ent.short_ext[0] = 0;
	ent.attributes = UFAT_ATTR_DIRECTORY;
	ent.first_cluster = c;
	ent.file_size = 0;
	pack_dirent(&ent, ufat_cache_data(parent->uf, idx));

	/* Create ".." */
	ent.short_name[1] = '.';
	ent.short_name[2] = 0;

	if (parent->start >= parent->uf->bpb.cluster_start)
		ent.first_cluster = block_to_cluster(&parent->uf->bpb,
						     parent->start);
	else
		ent.first_cluster = 0;

	pack_dirent(&ent, ufat_cache_data(parent->uf, idx) + UFAT_DIRENT_SIZE);

	*out = c;
	return 0;
}

static int is_legal_name(const char *name)
{
	if (!*name)
		return 0;

	if (name[0] == '.') {
		if (!name[1])
			return 0;
		if (name[1] == '.' && !name[2])
			return 0;
	}

	while (*name) {
		if (*name == '\\' || *name == '/' || *name < ' ')
			return 0;

		name++;
	}

	return 1;
}

static int is_legal_dos_char(char c)
{
	return isalnum(c) ||
		(c >= '!' && c <= ')') ||
		(c == '-') ||
		(c == '@') ||
		(c >= '^' && c <= '`') ||
		(c == '{' || c == '}' || c == '~');
}

static void short_enum_first(const char *long_name,
			     char *short_name, char *ext_text)
{
	int len = strlen(long_name);
	int ext = len;
	int i, j;

	while (ext >= 0 && long_name[ext] != '.')
		ext--;
	if (ext > 0)
		ext++;
	else
		ext = len;

	j = 0;
	for (i = ext; j < 3 && long_name[i]; i++) {
		char c = long_name[i];

		if (is_legal_dos_char(c))
			ext_text[j++] = toupper(c);
	}
	ext_text[j] = 0;

	j = 0;
	for (i = 0; j < 8 && i < ext; i++) {
		char c = long_name[i];

		if (is_legal_dos_char(c))
			short_name[j++] = toupper(c);
	}

	if (!j) {
		for (i = 0; i < 8; i++)
			short_name[i] = '~';
		short_name[8] = 0;
	}
}

static void short_enum_next(char *short_name)
{
	int len = strlen(short_name);
	int tilde = strlen(short_name);
	unsigned int suffix_num;
	int i;

	while (tilde >= 0 && short_name[tilde] != '~')
		tilde--;
	if (tilde < 0)
		tilde = len;
	else
		tilde++;

	suffix_num = atoi(short_name + tilde) + 1;
	short_name[8] = 0;

	i = 7;
	while (suffix_num && i >= 0) {
		short_name[i] = (suffix_num % 10) + '0';
		suffix_num /= 10;
		i--;
	}

	if (i >= 0)
		short_name[i--] = '~';

	while (i >= tilde)
		short_name[i--] = '~';
}

static int has_short(struct ufat_directory *dir, const char *short_name,
		     const char *short_ext)
{
	struct ufat_dirent ent;

	ufat_dir_rewind(dir);
	for (;;) {
		int err = ufat_dir_read(dir, &ent, NULL, 0);

		if (err < 0)
			return err;

		if (err)
			break;

		if (!strcasecmp(ent.short_name, short_name) &&
		    !strcasecmp(ent.short_ext, short_ext))
			return 1;
	}

	return 0;
}

static inline uint8_t cksum_next(uint8_t cur, char c)
{
	return (((cur & 1) << 7) | (cur >> 1)) + c;
}

static uint8_t lfn_checksum(const char *short_name, const char *short_ext)
{
	uint8_t sum = 0;
	int i;

	for (i = 0; short_name[i]; i++)
		sum = cksum_next(sum, short_name[i]);
	for (; i < 8; i++)
		sum = cksum_next(sum, ' ');

	for (i = 0; short_ext[i]; i++)
		sum = cksum_next(sum, short_ext[i]);
	for (; i < 3; i++)
		sum = cksum_next(sum, ' ');

	return sum;
}

static int utf8_to_ucs2(const char *src, uint16_t *dst)
{
	int len = 0;
	int i;

	while (*src && len < UFAT_LFN_MAX_CHARS) {
		unsigned int c = *src;

		if ((c & 0xf0) == 0xf0)
			return -UFAT_ERR_ILLEGAL_NAME;

		if ((c & 0xe0) == 0xe0) {
			unsigned int b = src[1];
			unsigned int a = src[2];

			if ((a & 0xc0) != 0xc0 ||
			    (b & 0xc0) != 0xc0)
				return -UFAT_ERR_BAD_ENCODING;

			dst[len++] = ((c & 0xf) << 12) |
				((b & 0x3f) << 6) |
				(a & 0x3f);
			src += 3;
		} else if ((c & 0xc0) == 0xc0) {
			unsigned int b = src[1];

			if ((b & 0xc0) != 0xc0)
				return -UFAT_ERR_BAD_ENCODING;

			dst[len++] = ((c & 0x1f) << 6) | (b & 0x3f);
			src += 2;
		} else if (c & 0x80) {
			return -UFAT_ERR_BAD_ENCODING;
		} else {
			dst[len++] = c;
			src++;
		}
	}

	if (*src)
		return -UFAT_ERR_NAME_TOO_LONG;

	/* Pad out with spaces */
	for (i = len; i < UFAT_LFN_MAX_CHARS; i++)
		dst[i] = 0x20;

	return len;
}

static void pack_lfn_fragment(const uint16_t *ucs, int seq, int is_first,
			      uint8_t *data, uint8_t checksum)
{
	int i;

	data[0] = seq;
	if (is_first)
		data[0] |= 0x40;

	for (i = 0; i < 5; i++)
		w16(data + 0x01 + i * 2, ucs[i]);

	data[0x0b] = UFAT_ATTR_LFN_FRAGMENT;
	data[0x0c] = 0;
	data[0x0d] = checksum;

	for (i = 0; i < 6; i++)
		w16(data + 0x0e + i * 2, ucs[i + 5]);

	data[0x1a] = 0;
	data[0x1b] = 0;

	w16(data + 0x1c, ucs[11]);
	w16(data + 0x1e, ucs[12]);
}

static int insert_dirent(struct ufat_directory *dir, struct ufat_dirent *ent,
			 const char *long_name)
{
	uint16_t ucs2_name[UFAT_LFN_MAX_CHARS];
	uint8_t data[UFAT_DIRENT_SIZE];
	uint8_t checksum;
	int ucs2_len = utf8_to_ucs2(long_name, ucs2_name);
	int num_lfn_frags;
	int err;
	int i;

	/* Check that the UTF8 was encoded correctly */
	if (ucs2_len < 0)
		return ucs2_len;
	num_lfn_frags = (ucs2_len + 12) / 13;

	/* Choose a suitable short-name */
	short_enum_first(long_name, ent->short_name, ent->short_ext);
	for (;;) {
		err = has_short(dir, ent->short_name, ent->short_ext);
		if (err < 0)
			return err;

		if (!err)
			break;

		short_enum_next(ent->short_name);
	}

	checksum = lfn_checksum(ent->short_name, ent->short_ext);

	/* Find a space in the directory */
	err = allocate_raw_dirent(dir, num_lfn_frags + 1);
	if (err < 0)
		return -1;

	/* Write LFN fragments and the DOS dirent */
	for (i = 0; i < num_lfn_frags; i++) {
		pack_lfn_fragment(ucs2_name + (num_lfn_frags - i - 1) * 13,
				  num_lfn_frags - i, !i,
				  data, checksum);

		err = write_raw_dirent(dir, data, sizeof(data));
		if (err < 0)
			return err;

		err = advance_raw_dirent(dir, 0);
		if (err < 0)
			return err;
	}

	pack_dirent(ent, data);
	return write_raw_dirent(dir, data, sizeof(data));
}

int ufat_dir_create(struct ufat_directory *dir, struct ufat_dirent *ent,
		    const char *name)
{
	struct ufat_dirent check;
	int err;

	if (!is_legal_name(name))
		return -UFAT_ERR_ILLEGAL_NAME;

	if (!ufat_dir_find(dir, name, &check))
		return -UFAT_ERR_FILE_EXISTS;

	err = create_empty_dir(dir, &ent->first_cluster, ent);
	if (err < 0)
		return err;

	ent->file_size = 0;
	ent->attributes = (ent->attributes & UFAT_ATTR_USER) |
		UFAT_ATTR_DIRECTORY;

	err = insert_dirent(dir, ent, name);
	if (err < 0) {
		ufat_free_chain(dir->uf, ent->first_cluster);
		return err;
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
		       const char *path, struct ufat_dirent *ent,
		       const char **path_out)
{
	int at_root = 1;

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
			int err = ufat_open_subdir(dir->uf, dir, ent);

			if (err < 0)
				return err;
		}

		/* Search for this component */
		for (;;) {
			char name[UFAT_LFN_MAX_UTF8];
			int err = ufat_dir_read(dir, ent,
						name, sizeof(name));

			if (err < 0)
				return err;

			if (err) {
				if (path_out)
					*path_out = path;
				return 1;
			}

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
