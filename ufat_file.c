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
	f->start = ent->first_cluster;
	f->file_size = ent->file_size;
	f->cur_cluster = f->start;
	f->cur_pos = 0;

	return 0;
}

void ufat_file_rewind(struct ufat_file *f)
{
	f->cur_cluster = f->start;
	f->cur_pos = 0;
}

int ufat_file_advance(struct ufat_file *f, ufat_size_t nbytes)
{
	const unsigned int log2_cluster_size =
		f->uf->dev->log2_block_size +
		f->uf->bpb.log2_blocks_per_cluster;
	ufat_size_t end_pos;
	unsigned int nclusters;
	ufat_cluster_t c = f->cur_cluster;

	if (nbytes > f->file_size - f->cur_pos)
		nbytes = f->file_size - f->cur_pos;
	end_pos = f->cur_pos + nbytes;

	nclusters = (end_pos >> log2_cluster_size) -
		(f->cur_pos >> log2_cluster_size);

	while (nclusters) {
		int i = ufat_read_fat(f->uf, c, &c);

		if (i < 0)
			return i;

		nclusters--;
	}

	f->cur_cluster = c;
	f->cur_pos += nbytes;

	return 0;
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
	i = ufat_file_advance(f, size);
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
	i = uf->dev->read(uf->dev,
			  cluster_to_block(bpb, f->cur_cluster) + block_offset,
			  requested_blocks, (uint8_t *)buf);
	if (i < 0)
		return -UFAT_ERR_IO;

	uf->stat.read++;
	uf->stat.read_blocks += requested_blocks;

	i = ufat_file_advance(f, requested_blocks << log2_block_size);
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
