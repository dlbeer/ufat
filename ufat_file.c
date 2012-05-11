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

int ufat_open_file(struct ufat *uf, struct ufat_file *f,
		   const struct ufat_dirent *ent)
{
	if (ent->attributes & UFAT_ATTR_DIRECTORY)
		return -UFAT_ERR_NOT_FILE;

	f->uf = uf;
	f->dirent_block = ent->dirent_block;
	f->dirent_pos = ent->dirent_pos;
	f->start = ent->first_cluster;
	f->file_size = ent->file_size;
	f->prev_cluster = 0;
	f->cur_cluster = f->start;
	f->cur_pos = 0;

	return 0;
}

void ufat_file_rewind(struct ufat_file *f)
{
	f->prev_cluster = 0;
	f->cur_cluster = f->start;
	f->cur_pos = 0;
}

static int advance_ptr(struct ufat_file *f, ufat_size_t nbytes)
{
	const unsigned int log2_cluster_size =
		f->uf->dev->log2_block_size +
		f->uf->bpb.log2_blocks_per_cluster;
	ufat_size_t end_pos;
	unsigned int nclusters;
	ufat_cluster_t c = f->cur_cluster;
	ufat_cluster_t prev = f->prev_cluster;

	end_pos = f->cur_pos + nbytes;

	nclusters = (end_pos >> log2_cluster_size) -
		(f->cur_pos >> log2_cluster_size);

	while (nclusters) {
		ufat_cluster_t next;
		int i;

		i = ufat_read_fat(f->uf, c, &next);
		if (i < 0)
			return i;

		prev = c;
		c = next;
		nclusters--;
	}

	f->prev_cluster = prev;
	f->cur_cluster = c;
	f->cur_pos += nbytes;

	return 0;
}

int ufat_file_advance(struct ufat_file *f, ufat_size_t nbytes)
{
	if (nbytes > f->file_size - f->cur_pos)
		nbytes = f->file_size - f->cur_pos;

	return advance_ptr(f, nbytes);
}

static int read_block_fragment(struct ufat_file *f, char *buf, ufat_size_t size)
{
	const struct ufat_bpb *bpb = &f->uf->bpb;
	const unsigned int log2_block_size = f->uf->dev->log2_block_size;
	const unsigned int block_size = 1 << log2_block_size;
	const unsigned int offset = f->cur_pos & (block_size - 1);
	const unsigned int remainder = block_size - offset;
	const ufat_block_t cur_block =
		cluster_to_block(bpb, f->cur_cluster) +
		((f->cur_pos >> log2_block_size) &
		 ((1 << bpb->log2_blocks_per_cluster) - 1));
	int i;

	if (size > remainder)
		size = remainder;
	size &= (block_size - 1);
	if (!size)
		return 0;

	if (!UFAT_CLUSTER_IS_PTR(f->cur_cluster))
		return -UFAT_ERR_INVALID_CLUSTER;

	i = ufat_cache_open(f->uf, cur_block);
	if (i < 0)
		return i;

	memcpy(buf, ufat_cache_data(f->uf, i) + offset, size);
	i = advance_ptr(f, size);
	if (i < 0)
		return i;

	return size;
}

static int read_blocks(struct ufat_file *f, char *buf, ufat_size_t size)
{
	struct ufat *uf = f->uf;
	const struct ufat_bpb *bpb = &uf->bpb;
	const unsigned int log2_block_size = uf->dev->log2_block_size;
	const unsigned int blocks_per_cluster =
		1 << bpb->log2_blocks_per_cluster;
	const unsigned int block_offset =
		(f->cur_pos >> log2_block_size) & (blocks_per_cluster - 1);
	const unsigned int block_remainder =
		blocks_per_cluster - block_offset;
	ufat_block_t starting_block;
	unsigned int requested_blocks = size >> log2_block_size;
	int i;

	if (requested_blocks > block_remainder)
		requested_blocks = block_remainder;
	if (!requested_blocks)
		return 0;

	if (!UFAT_CLUSTER_IS_PTR(f->cur_cluster))
		return -UFAT_ERR_INVALID_CLUSTER;

	/* We're reading contiguous whole blocks, so we can bypass the
	 * cache and perform a single large read.
	 */
	starting_block = cluster_to_block(bpb, f->cur_cluster) + block_offset;
	i = ufat_cache_evict(uf, starting_block, requested_blocks);
	if (i < 0)
		return i;

	i = uf->dev->read(uf->dev, starting_block, requested_blocks,
			  (uint8_t *)buf);
	if (i < 0)
		return -UFAT_ERR_IO;

	uf->stat.read++;
	uf->stat.read_blocks += requested_blocks;

	i = advance_ptr(f, requested_blocks << log2_block_size);
	if (i < 0)
		return i;

	return requested_blocks << log2_block_size;
}

int ufat_file_read(struct ufat_file *f, char *buf, ufat_size_t size)
{
	ufat_size_t total;
	int len;

	if (size > f->file_size - f->cur_pos)
		size = f->file_size - f->cur_pos;
	total = size;

	/* Read partial block ends */
	len = read_block_fragment(f, buf, size);
	if (len < 0)
		return len;

	buf += len;
	size -= len;

	/* Read contiguous blocks within a cluster */
	for (;;) {
		int ret = read_blocks(f, buf, size);

		if (ret < 0)
			return ret;

		if (!ret)
			break;

		buf += ret;
		size -= ret;
	}

	/* Read remaining block fragment */
	len = read_block_fragment(f, buf, size);
	if (len < 0)
		return len;

	buf += len;
	size -= len;

	return total;
}

static int set_size(struct ufat_file *f, ufat_size_t s)
{
	int idx = ufat_cache_open(f->uf, f->dirent_block);

	if (idx < 0)
		return idx;

	ufat_cache_write(f->uf, idx);
	w32(ufat_cache_data(f->uf, idx) +
	    f->dirent_pos * UFAT_DIRENT_SIZE + 0x1c, s);

	f->file_size = s;
	return 0;
}

static int set_start(struct ufat_file *f, ufat_cluster_t s)
{
	int idx = ufat_cache_open(f->uf, f->dirent_block);
	uint8_t *data;

	if (idx < 0)
		return idx;

	ufat_cache_write(f->uf, idx);
	data = ufat_cache_data(f->uf, idx) + f->dirent_pos * UFAT_DIRENT_SIZE;
	w16(data + 0x14, s >> 16);
	w16(data + 0x1a, s & 0xffff);

	f->start = s;
	return 0;
}

static int ensure_room(struct ufat_file *f)
{
	ufat_cluster_t c;
	int err;

	if (UFAT_CLUSTER_IS_PTR(f->cur_cluster))
		return 0;

	err = ufat_alloc_chain(f->uf, 1, &c);
	if (err < 0)
		return err;

	if (UFAT_CLUSTER_IS_PTR(f->prev_cluster))
		err = ufat_write_fat(f->uf, f->prev_cluster, c);
	else
		err = set_start(f, c);

	if (err < 0) {
		ufat_free_chain(f->uf, c);
		return err;
	}

	f->cur_cluster = c;
	return 0;
}

static int write_block_fragment(struct ufat_file *f, const char *buf,
				ufat_size_t size)
{
	const struct ufat_bpb *bpb = &f->uf->bpb;
	const unsigned int log2_block_size = f->uf->dev->log2_block_size;
	const unsigned int block_size = 1 << log2_block_size;
	const unsigned int offset = f->cur_pos & (block_size - 1);
	const unsigned int remainder = block_size - offset;
	ufat_block_t cur_block;
	int i;

	if (size > remainder)
		size = remainder;
	size &= (block_size - 1);
	if (!size)
		return 0;

	i = ensure_room(f);
	if (i < 0)
		return i;

	cur_block =
		cluster_to_block(bpb, f->cur_cluster) +
		((f->cur_pos >> log2_block_size) &
		 ((1 << bpb->log2_blocks_per_cluster) - 1));

	i = ufat_cache_open(f->uf, cur_block);
	if (i < 0)
		return i;

	ufat_cache_write(f->uf, i);
	memcpy(ufat_cache_data(f->uf, i) + offset, buf, size);

	i = advance_ptr(f, size);
	if (i < 0)
		return i;

	return size;
}

static int write_blocks(struct ufat_file *f, const char *buf, ufat_size_t size)
{
	struct ufat *uf = f->uf;
	const struct ufat_bpb *bpb = &uf->bpb;
	const unsigned int log2_block_size = uf->dev->log2_block_size;
	const unsigned int blocks_per_cluster =
		1 << bpb->log2_blocks_per_cluster;
	const unsigned int block_offset =
		(f->cur_pos >> log2_block_size) & (blocks_per_cluster - 1);
	const unsigned int block_remainder =
		blocks_per_cluster - block_offset;
	ufat_block_t starting_block;
	unsigned int requested_blocks = size >> log2_block_size;
	int i;

	if (requested_blocks > block_remainder)
		requested_blocks = block_remainder;
	if (!requested_blocks)
		return 0;

	i = ensure_room(f);
	if (i < 0)
		return -1;

	/* We're writing contiguous whole blocks, so we can bypass the
	 * cache and perform a single large write.
	 */
	starting_block = cluster_to_block(bpb, f->cur_cluster) + block_offset;
	i = ufat_cache_evict(uf, starting_block, requested_blocks);
	if (i < 0)
		return i;

	i = uf->dev->write(uf->dev, starting_block, requested_blocks,
			   (const uint8_t *)buf);
	if (i < 0)
		return -UFAT_ERR_IO;

	uf->stat.write++;
	uf->stat.write_blocks += requested_blocks;

	i = advance_ptr(f, requested_blocks << log2_block_size);
	if (i < 0)
		return i;

	return requested_blocks << log2_block_size;
}

int ufat_file_write(struct ufat_file *f, const char *buf, ufat_size_t len)
{
	const ufat_size_t max_write = ~f->cur_pos;
	ufat_size_t total;
	int i;

	if (len > max_write)
		len = max_write;
	total = len;

	/* Write a partial block fragment */
	i = write_block_fragment(f, buf, len);
	if (i < 0)
		return i;

	buf += i;
	len -= i;

	/* Write complete blocks */
	for (;;) {
		i = write_blocks(f, buf, len);

		if (i < 0)
			return i;

		if (!i)
			break;

		buf += i;
		len -= i;
	}

	/* Write a partial block fragment */
	i = write_block_fragment(f, buf, len);
	if (i < 0)
		return i;

	if (f->cur_pos > f->file_size) {
		i = set_size(f, f->cur_pos);
		if (i < 0)
			return i;
	}

	return total;
}

int ufat_file_truncate(struct ufat_file *f)
{
	const unsigned int
		cluster_size = 1 << (f->uf->bpb.log2_blocks_per_cluster +
				     f->uf->dev->log2_block_size);
	int err;

	err = set_size(f, f->cur_pos);
	if (err < 0)
		return err;

	if (!f->file_size) {
		err = set_start(f, 0);
		if (err < 0)
			return err;

		if (UFAT_CLUSTER_IS_PTR(f->start)) {
			err = ufat_free_chain(f->uf, f->start);
			if (err < 0)
				return err;
		}

		f->cur_cluster = 0;
		return 0;
	}

	if (f->file_size & (cluster_size - 1)) {
		ufat_cluster_t tail;

		err = ufat_read_fat(f->uf, f->cur_cluster, &tail);
		if (err < 0)
			return err;

		err = ufat_write_fat(f->uf, f->cur_cluster, UFAT_CLUSTER_EOC);
		if (err < 0)
			return err;

		if (UFAT_CLUSTER_IS_PTR(tail))
			return ufat_free_chain(f->uf, tail);

		return 0;
	}

	if (UFAT_CLUSTER_IS_PTR(f->cur_cluster)) {
		err = ufat_write_fat(f->uf, f->prev_cluster, UFAT_CLUSTER_EOC);
		if (err < 0)
			return err;

		ufat_free_chain(f->uf, f->cur_cluster);
		f->cur_cluster = 0;
		return 0;
	}

	return 0;
}
