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

#ifndef UFAT_INTERNAL_H_
#define UFAT_INTERNAL_H_

#define UFAT_CLUSTER_MASK		0x0fffffff
#define UFAT_DIRENT_SIZE		32

static inline uint16_t r16(const uint8_t *offset)
{
	const uint16_t l = offset[0];
	const uint16_t h = offset[1];

	return (h << 8) | l;
}

static inline uint32_t r32(const uint8_t *offset)
{
	const uint32_t l = r16(offset);
	const uint32_t h = r16(offset + 2);

	return (h << 16) | l;
}

static inline ufat_block_t cluster_to_block(const struct ufat_bpb *bpb,
					    ufat_cluster_t c)
{
	return ((c - 2) << bpb->log2_blocks_per_cluster) +
		bpb->cluster_start;
}

static inline ufat_cluster_t block_to_cluster(const struct ufat_bpb *bpb,
					      ufat_block_t b)
{
	return ((b - bpb->cluster_start) >> bpb->log2_blocks_per_cluster) + 2;
}

/* Block IO via internal cache */
int ufat_cache_open(struct ufat *uf, ufat_block_t blk_index);

static inline void ufat_cache_write(struct ufat *uf, unsigned int cache_index)
{
	uf->stat.cache_write++;
	uf->cache_desc[cache_index].flags |= UFAT_CACHE_FLAG_DIRTY;
}

static inline uint8_t *ufat_cache_data(struct ufat *uf,
				       unsigned int cache_index)
{
	return uf->cache_data + (cache_index << uf->dev->log2_block_size);
}

/* FAT entry IO */
int ufat_read_fat(struct ufat *uf, ufat_cluster_t index,
		  ufat_cluster_t *out);

#endif
