/* uFAT -- small flexible VFAT implementation
 * Copyright (C) 2012 TracMap Holdings Ltd
 *
 * Author: Daniel Beer <dlbeer@gmail.com>, www.dlbeer.co.nz
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef UFAT_H_
#define UFAT_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif	/* def __cplusplus */

/** Block counts and indices are held in this type. */
typedef unsigned long long ufat_block_t;

#define UFAT_BLOCK_NONE ((ufat_block_t)0xffffffffffffffffLL)

/**
 * This structure is the interface to a block device. All fields must be
 * provided.
 */

struct ufat_device {
	/** Base-2 logarithm of size of block, bytes */
	unsigned int	log2_block_size;
	/**
	 * Pointer to function used to read data from block device. Should
	 * return 0 on success or -1 if an error occurs.
	 */
	int		(*read)(const struct ufat_device *dev, ufat_block_t start,
				ufat_block_t count, void *buffer);
	/**
	 * Pointer to function used to write data to block device. Should
	 * return 0 on success or -1 if an error occurs.
	 */
	int		(*write)(const struct ufat_device *dev, ufat_block_t start,
				ufat_block_t count, const void *buffer);
};

/* Cache parameters. The more cache is used, the fewer filesystem reads/writes
 * have to be performed. The cache must be able to hold at least one block.
 */
#define UFAT_CACHE_MAX_BLOCKS		16
#define UFAT_CACHE_BYTES		8192

#define UFAT_CACHE_FLAG_DIRTY		0x01
#define UFAT_CACHE_FLAG_PRESENT		0x02

struct ufat_cache_desc {
	int		flags;
	unsigned int	seq;
	ufat_block_t	index;
};

/** Performance accounting statistics. */
struct ufat_stat {
	unsigned int		read;
	unsigned int		write;

	unsigned int		read_blocks;
	unsigned int		write_blocks;

	unsigned int		cache_hit;
	unsigned int		cache_miss;
	unsigned int		cache_write;
	unsigned int		cache_flush;
};

typedef uint32_t		ufat_cluster_t;
typedef uint32_t		ufat_size_t;

#define UFAT_CLUSTER_FREE	((ufat_cluster_t)0)
#define UFAT_CLUSTER_RESERVED	((ufat_cluster_t)1)
#define UFAT_CLUSTER_BAD	((ufat_cluster_t)0xffffff7)
#define UFAT_CLUSTER_EOC	((ufat_cluster_t)0xffffff8)
#define UFAT_CLUSTER_IS_PTR(c)	((c) >= 2 && (c) < 0xffffff0)

typedef enum {
	UFAT_TYPE_FAT12		= 12,
	UFAT_TYPE_FAT16		= 16,
	UFAT_TYPE_FAT32		= 32
} ufat_fat_type_t;

/** Data read/calculated from the BIOS Parameter Block (read-only) */
struct ufat_bpb {
	ufat_fat_type_t		type;
	unsigned int		log2_blocks_per_cluster;

	ufat_block_t		fat_start;
	ufat_block_t		fat_size;
	unsigned int		fat_count;

	ufat_block_t		cluster_start;
	ufat_cluster_t		num_clusters;

	ufat_block_t		root_start;
	ufat_block_t		root_size;
	ufat_cluster_t		root_cluster;
};

/** This structure holds the data for an open filesystem. */
struct ufat {
	const struct ufat_device	*dev;

	struct ufat_stat		stat;
	struct ufat_bpb			bpb;

	unsigned int			next_seq;
	unsigned int			cache_size;
	ufat_cluster_t			alloc_ptr;

	struct ufat_cache_desc		cache_desc[UFAT_CACHE_MAX_BLOCKS];
	uint8_t				cache_data[UFAT_CACHE_BYTES];
};

/** Error codes. */
typedef enum {
	UFAT_OK = 0,
	UFAT_ERR_IO,
	UFAT_ERR_BLOCK_SIZE,
	UFAT_ERR_INVALID_BPB,
	UFAT_ERR_BLOCK_ALIGNMENT,
	UFAT_ERR_INVALID_CLUSTER,
	UFAT_ERR_NAME_TOO_LONG,
	UFAT_ERR_NOT_DIRECTORY,
	UFAT_ERR_NOT_FILE,
	UFAT_ERR_IMMUTABLE,
	UFAT_ERR_DIRECTORY_NOT_EMPTY,
	UFAT_ERR_ILLEGAL_NAME,
	UFAT_ERR_FILE_EXISTS,
	UFAT_ERR_BAD_ENCODING,
	UFAT_ERR_DIRECTORY_FULL,
	UFAT_ERR_NO_CLUSTERS,
	UFAT_MAX_ERR
} ufat_error_t;

const char *ufat_strerror(int err);

/* Open/close a filesystem. Returns 0 on success or a negative error
 * code if an error occurs. The ufat_dev pointer must remain valid for
 * the lifetime of the ufat object.
 */
int ufat_open(struct ufat *uf, const struct ufat_device *dev);
int ufat_sync(struct ufat *uf);

/**
 * \brief Count number of free clusters.
 *
 * The total number of available clusters is `uf->bpb.num_clusters - 2` (first
 * two clusters are reserved). `uf->bpb.log2_blocks_per_cluster` can be used to
 * convert number of clusters to number of blocks and these can be converted to
 * bytes by multiplying with `1 << uf->dev->log2_block_size`.
 *
 * \pre Both `uf` and `free_clusters` are valid pointers.
 * \pre File system pointed by `uf` is opened.
 *
 * \param [in] uf is a pointer to `ufat` struct
 * \param [out] free_clusters is a pointer to a variable into which the count
 * of free clusters will be written
 *
 * \return 0 on success, negative error code (`ufat_error_t`) otherwise
 */

int ufat_count_free_clusters(struct ufat *uf, ufat_cluster_t *free_clusters);
void ufat_close(struct ufat *uf);

/* Directory reading. */
typedef enum {
	UFAT_ATTR_READONLY	= 0x01,
	UFAT_ATTR_HIDDEN	= 0x02,
	UFAT_ATTR_SYSTEM	= 0x04,
	UFAT_ATTR_VOLLABEL	= 0x08,
	UFAT_ATTR_DIRECTORY	= 0x10,
	UFAT_ATTR_ARCHIVE	= 0x20,
	UFAT_ATTR_LFN_FRAGMENT	= 0x0f,
	UFAT_ATTR_USER		= 0x27
} ufat_attr_t;

typedef uint16_t ufat_time_t;

#define UFAT_TIME(h, m, s) (((h) << 11) | ((m) << 5) | ((s) >> 1))
#define UFAT_TIME_H(t) (((t) >> 11) & 0x1f)
#define UFAT_TIME_M(t) (((t) >> 5) & 0x3f)
#define UFAT_TIME_S(t) (((t) & 0x1f) << 1)

typedef uint16_t ufat_date_t;

#define UFAT_DATE(y, m, d) ((((y) - 1980) << 9) | ((m) << 5) | (d))
#define UFAT_DATE_Y(d) (((d) >> 9) + 1980)
#define UFAT_DATE_M(d) (((d) >> 5) & 0xf)
#define UFAT_DATE_D(d) ((d) & 0x1f)

struct ufat_dirent {
	ufat_block_t		dirent_block;
	unsigned int		dirent_pos;

	/* Start of LFN fragment chain, if any */
	ufat_block_t		lfn_block;
	unsigned int		lfn_pos;

	char			short_name[9];
	char			short_ext[4];

	ufat_attr_t		attributes;
	ufat_date_t		create_date;
	ufat_time_t		create_time;
	ufat_date_t		modify_date;
	ufat_time_t		modify_time;
	ufat_date_t		access_date;

	ufat_cluster_t		first_cluster;
	ufat_size_t		file_size;
};

struct ufat_directory {
	struct ufat		*uf;
	unsigned int		cur_pos;
	ufat_block_t		cur_block;
	ufat_block_t		start;
};

#define UFAT_LFN_MAX_CHARS	255
#define UFAT_LFN_MAX_UTF8	768

void ufat_open_root(struct ufat *uf, struct ufat_directory *dir);
int ufat_open_subdir(struct ufat *uf, struct ufat_directory *dir,
		     const struct ufat_dirent *ent);

void ufat_dir_rewind(struct ufat_directory *dir);
int ufat_dir_read(struct ufat_directory *dir,
		  struct ufat_dirent *inf,
		  char *name_buf, int max_len);
int ufat_dir_delete(struct ufat *uf, struct ufat_dirent *ent);
int ufat_dir_create(struct ufat_directory *dir, struct ufat_dirent *ent,
		    const char *name);
int ufat_dir_mkfile(struct ufat_directory *dir, struct ufat_dirent *ent,
		    const char *name);

/* Search for a file by name. These functions return 0 on success, 1 if
 * the file doesn't exist, or -1 if an error occurs.
 */
int ufat_dir_find(struct ufat_directory *dir,
		  const char *name, struct ufat_dirent *inf);
int ufat_dir_find_path(struct ufat_directory *dir,
		       const char *path, struct ufat_dirent *inf,
		       const char **path_out);

/* Read the canonical long filename for a dirent. */
int ufat_get_filename(struct ufat *uf,
		      const struct ufat_dirent *ent,
		      char *name_buf, int max_len);

/* Alter the dates, times and attributes a directory entry */
int ufat_update_attributes(struct ufat *uf, struct ufat_dirent *ent);

/* Remove a file from its containing directory and reinsert it in (possibly
 * the same) directory. The dirent structure will be modified.
 */
int ufat_move(struct ufat_dirent *ent, struct ufat_directory *dst,
	      const char *new_name);

/* File IO */
struct ufat_file {
	struct ufat		*uf;

	ufat_block_t		dirent_block;
	unsigned int		dirent_pos;

	ufat_cluster_t		start;
	ufat_size_t		file_size;

	ufat_cluster_t		prev_cluster;

	ufat_cluster_t		cur_cluster;
	ufat_size_t		cur_pos;
};

int ufat_open_file(struct ufat *uf, struct ufat_file *f,
		   const struct ufat_dirent *ent);
void ufat_file_rewind(struct ufat_file *f);
int ufat_file_advance(struct ufat_file *f, ufat_size_t nbytes);
int ufat_file_read(struct ufat_file *f, void *buf, ufat_size_t max_size);
int ufat_file_write(struct ufat_file *f, const void *buf, ufat_size_t len);
int ufat_file_truncate(struct ufat_file *f);

/* Filesystem creation */
int ufat_mkfs(struct ufat_device *dev, ufat_block_t nblk);

#ifdef __cplusplus
}	/* extern "C" */
#endif	/* def __cplusplus */

#endif
