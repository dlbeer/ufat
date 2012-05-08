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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include "ufat.h"

struct command;

#define OPTION_STATISTICS	0x01
#define OPTION_RANDOMIZE	0x02

struct options {
	int			flags;
	unsigned int		log2_bs;
	unsigned int		seed;

	const char		*filename;
	const struct command	*command;
	char			**argv;
	int			argc;
};

struct command {
	const char		*name;
	int			(*func)(struct ufat *uf,
					const struct options *opt);
};

struct file_device {
	struct ufat_device	base;
	FILE			*f;
	int			is_read_only;
};

static int file_device_read(const struct ufat_device *dev, ufat_block_t start,
			    ufat_block_t count, unsigned char *buffer)
{
	struct file_device *f = (struct file_device *)dev;

	if (fseek(f->f, start << f->base.log2_block_size, SEEK_SET) < 0) {
		perror("file_device_read: fseek");
		return -1;
	}

	if (fread(buffer, 1 << f->base.log2_block_size,
		  count, f->f) != count) {
		if (feof(f->f))
			fprintf(stderr, "file_device_read: "
				"read out of bounds\n");
		else
			perror("file_device_read: fread");

		return -1;
	}

	return 0;
}

static int file_device_write(const struct ufat_device *dev, ufat_block_t start,
			     ufat_block_t count, const unsigned char *buffer)
{
	struct file_device *f = (struct file_device *)dev;

	if (f->is_read_only) {
		fprintf(stderr, "file_device_write: read-only device\n");
		return -1;
	}

	if (fseek(f->f, start << f->base.log2_block_size, SEEK_SET) < 0) {
		perror("file_device_write: fseek");
		return -1;
	}

	if (fwrite(buffer, 1 << f->base.log2_block_size,
		  count, f->f) != count) {
		perror("file_device_write: fwrite");
		return -1;
	}

	return 0;
}

static int file_device_open(struct file_device *dev, const char *fname,
			    unsigned int log2_bs)
{
	dev->base.log2_block_size = log2_bs;
	dev->base.read = file_device_read;
	dev->base.write = file_device_write;
	dev->is_read_only = 0;

	dev->f = fopen(fname, "r+");
	if (!dev->f && errno == EACCES) {
		dev->is_read_only = 1;
		dev->f = fopen(fname, "r");
	}

	if (!dev->f) {
		perror("open");
		return -1;
	}

	return 0;
}

static void file_device_close(struct file_device *dev)
{
	fclose(dev->f);
}

static void print_date(ufat_date_t d)
{
	printf("%04d-%02d-%02d",
	       UFAT_DATE_Y(d), UFAT_DATE_M(d), UFAT_DATE_D(d));
}

static void print_time(ufat_time_t t)
{
	printf("%2d:%02d:%02d",
	       UFAT_TIME_H(t), UFAT_TIME_M(t), UFAT_TIME_S(t));
}

static void print_attributes(ufat_attr_t a)
{
	printf("%c%c%c%c%c",
	       (a & UFAT_ATTR_ARCHIVE) ? 'A' : ' ',
	       (a & UFAT_ATTR_SYSTEM) ? 'S' : ' ',
	       (a & UFAT_ATTR_HIDDEN) ? 'H' : ' ',
	       (a & UFAT_ATTR_READONLY) ? 'R' : ' ',
	       (a & UFAT_ATTR_DIRECTORY) ? 'D' : ' ');
}

static int list_dir(struct ufat_directory *dir)
{
	for (;;) {
		struct ufat_dirent inf;
		char lfn[UFAT_LFN_MAX_UTF8];
		int err;

		err = ufat_dir_read(dir, &inf, lfn, sizeof(lfn));
		if (err < 0) {
			fprintf(stderr, "list_dir: ufat_dir_read: %s\n",
				ufat_strerror(err));
			return err;
		}

		if (err)
			break;

		print_date(inf.modify_date);
		printf(" ");
		print_time(inf.modify_time);
		printf(" ");
		print_attributes(inf.attributes & ~UFAT_ATTR_DIRECTORY);
		if (inf.attributes & UFAT_ATTR_DIRECTORY)
			printf(" %9s", "<DIR>");
		else
			printf(" %9u", inf.file_size);
		printf(" %s\n", lfn);
	}

	return 0;
}

static int cmd_dir(struct ufat *uf, const struct options *opt)
{
	struct ufat_directory dir;

	ufat_open_root(uf, &dir);

	if (opt->argc) {
		struct ufat_dirent ent;
		int err = ufat_dir_find_path(&dir, opt->argv[0], &ent, NULL);

		if (err < 0) {
			fprintf(stderr, "ufat_dir_find_path: %s\n",
				ufat_strerror(err));
			return -1;
		}

		if (err) {
			fprintf(stderr, "No such file or directory: %s\n",
				opt->argv[0]);
			return -1;
		}

		err = ufat_open_subdir(uf, &dir, &ent);
		if (err < 0) {
			fprintf(stderr, "ufat_open_subdir: %s\n",
				ufat_strerror(err));
			return -1;
		}
	}

	return list_dir(&dir);
}

static int cmd_fstat(struct ufat *uf, const struct options *opt)
{
	struct ufat_directory dir;
	struct ufat_dirent ent;
	int err;

	if (!opt->argc) {
		fprintf(stderr, "You must specify a file path\n");
		return -1;
	}

	ufat_open_root(uf, &dir);
	err = ufat_dir_find_path(&dir, opt->argv[0], &ent, NULL);

	if (err < 0) {
		fprintf(stderr, "ufat_dir_find_path: %s\n",
			ufat_strerror(err));
		return -1;
	}

	if (err) {
		fprintf(stderr, "No such file or directory: %s\n",
			opt->argv[0]);
		return -1;
	}

	printf("Entry block/offset:     %llu/%d\n",
	       ent.dirent_block, ent.dirent_pos);

	if (ent.lfn_block != UFAT_BLOCK_NONE)
		printf("LFN start block/offset: %llu/%d\n",
		       ent.lfn_block, ent.lfn_pos);

	printf("Short name:             %s", ent.short_name);
	if (ent.short_ext[0])
		printf(".%s\n", ent.short_ext);
	else
		printf("\n");
	printf("Attributes:             0x%02x (", ent.attributes);
	print_attributes(ent.attributes);
	printf(")\n");
	printf("Creation date/time:     ");
	print_date(ent.create_date);
	printf(" ");
	print_time(ent.create_time);
	printf("\n");
	printf("Modification date/time: ");
	print_date(ent.modify_date);
	printf(" ");
	print_time(ent.modify_time);
	printf("\n");
	printf("Last access date:       ");
	print_date(ent.access_date);
	printf("\n");
	printf("First cluster:          %u\n", ent.first_cluster);
	printf("Size:                   %u\n", ent.file_size);

	return 0;
}

static int cmd_read(struct ufat *uf, const struct options *opt)
{
	struct ufat_directory dir;
	struct ufat_dirent ent;
	struct ufat_file file;
	int err;

	if (!opt->argc) {
		fprintf(stderr, "You must specify a file path\n");
		return -1;
	}

	ufat_open_root(uf, &dir);
	err = ufat_dir_find_path(&dir, opt->argv[0], &ent, NULL);

	if (err < 0) {
		fprintf(stderr, "ufat_dir_find_path: %s\n",
			ufat_strerror(err));
		return -1;
	}

	if (err) {
		fprintf(stderr, "No such file or directory: %s\n",
			opt->argv[0]);
		return -1;
	}

	err = ufat_open_file(uf, &file, &ent);
	if (err < 0) {
		fprintf(stderr, "ufat_open_file: %s\n", ufat_strerror(err));
		return -1;
	}

	for (;;) {
		char buf[16384];
		int req_size = sizeof(buf);
		int len;

		if (opt->flags & OPTION_RANDOMIZE)
			req_size = random() % sizeof(buf) + 1;

		len = ufat_file_read(&file, buf, req_size);
		if (len < 0) {
			fprintf(stderr, "ufat_file_read: %s\n",
				ufat_strerror(len));
			return -1;
		}

		if (!len)
			break;

		fwrite(buf, len, 1, stdout);
	}

	return 0;
}

static int cmd_rm(struct ufat *uf, const struct options *opt)
{
	struct ufat_directory dir;
	struct ufat_dirent ent;
	int err;

	if (!opt->argc) {
		fprintf(stderr, "You must specify a file path\n");
		return -1;
	}

	ufat_open_root(uf, &dir);
	err = ufat_dir_find_path(&dir, opt->argv[0], &ent, NULL);

	if (err < 0) {
		fprintf(stderr, "ufat_dir_find_path: %s\n",
			ufat_strerror(err));
		return -1;
	}

	if (err) {
		fprintf(stderr, "No such file or directory: %s\n",
			opt->argv[0]);
		return -1;
	}

	err = ufat_dir_delete(uf, &ent);
	if (err < 0) {
		fprintf(stderr, "ufat_dir_delete: %s\n", ufat_strerror(err));
		return -1;
	}

	return 0;
}

static void show_info(const struct ufat_bpb *bpb)
{
	printf("Type:                       FAT%d\n", bpb->type);
	printf("Blocks per cluster:         %u\n",
	       1 << bpb->log2_blocks_per_cluster);
	printf("FAT size (blocks):          %llu\n", bpb->fat_size);
	printf("FAT offset (block):         %llu\n", bpb->fat_start);
	printf("FAT count:                  %u\n", bpb->fat_count);
	printf("Cluster starting block:     %llu\n", bpb->cluster_start);
	printf("Clusters:                   %u\n", bpb->num_clusters);
	printf("Root directory block start: %llu\n", bpb->root_start);
	printf("Root directory block count: %llu\n", bpb->root_size);
	printf("Root directory cluster:     %u\n", bpb->root_cluster);
}

static void usage(const char *progname)
{
	printf(
"Usage: %s [options] <image file> [command [args]]\n"
"\n"
"Options may be any of the following:\n"
"  -b block-size        Set the simulated block size\n"
"  -S                   Show performance statistics\n"
"  -R seed              Randomize file IO request sizes\n"
"  --help               Show this text\n"
"  --version            Show version information\n"
"\n"
"With no command, basic information is printed. Available commands are:\n"
"  dir [directory]      Show a directory listing\n"
"  fstat [path]         Show directory entry details\n"
"  read [file]          Dump the contents of the given file\n"
"  rm [path]            Remove a directory or file\n",
progname);
}

static void version_banner(void)
{
	printf(
"ufat version 20120507\n"
"Copyright (C) 2012 TracMap Holdings Ltd\n"
"This is free software; see the source for copying conditions. There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
	       );
}

static int parse_blocksize(const char *arg, unsigned int *out)
{
	unsigned int target = atoi(arg);
	unsigned int c = 0;

	if (!target) {
		fprintf(stderr, "Block size must be greater than 0\n");
		return -1;
	}

	while (target > 1) {
		if (target & 1) {
			fprintf(stderr, "Block size must be a power of 2\n");
			return -1;
		}

		target >>= 1;
		c++;
	}

	*out = c;
	return 0;
}

static const struct command command_table[] = {
	{"dir",		cmd_dir},
	{"fstat",	cmd_fstat},
	{"read",	cmd_read},
	{"rm",		cmd_rm}
};

static const struct command *find_command(const char *name)
{
	int i;

	for (i = 0; i < sizeof(command_table) /
		     sizeof(command_table[0]); i++) {
		const struct command *c = &command_table[i];

		if (!strcasecmp(c->name, name))
			return c;
	}

	return NULL;
}

static int parse_options(int argc, char **argv, struct options *opt)
{
	static const struct option longopts[] = {
		{"help",	0, 0, 'H'},
		{"version",	0, 0, 'V'},
		{NULL, 0, 0, 0}
	};
	int o;

	memset(opt, 0, sizeof(*opt));
	opt->log2_bs = 9;

	while ((o = getopt_long(argc, argv, "b:SR:", longopts, NULL)) >= 0)
		switch (o) {
		case 'R':
			opt->flags |= OPTION_RANDOMIZE;
			opt->seed = atoi(optarg);
			break;

		case 'S':
			opt->flags |= OPTION_STATISTICS;
			break;

		case 'H':
			usage(argv[0]);
			exit(0);

		case 'V':
			version_banner();
			exit(0);

		case 'b':
			if (parse_blocksize(optarg, &opt->log2_bs) < 0)
				return -1;
			break;

		case '?':
			fprintf(stderr, "Try --help for usage.\n");
			return -1;
		}

	argc -= optind;
	argv += optind;

	if (argc <= 0) {
		fprintf(stderr, "Expected an image name\n");
		return -1;
	}

	opt->filename = argv[0];

	if (argc >= 2) {
		opt->command = find_command(argv[1]);
		opt->argv = argv + 2;
		opt->argc = argc - 2;

		if (!opt->command) {
			fprintf(stderr, "Unknown command: %s\n", argv[1]);
			return -1;
		}
	} else {
		opt->command = NULL;
		opt->argv = NULL;
		opt->argc = 0;
	}

	return 0;
}

static void dump_stats(const struct ufat_stat *st)
{
	fprintf(stderr, "\n");
	fprintf(stderr,
		"Reads:             %6d comprising %6d blocks\n",
		st->read, st->read_blocks);
	fprintf(stderr,
		"Writes:            %6d comprising %6d blocks\n",
		st->write, st->write_blocks);

	fprintf(stderr,	"Cache write/flush: %6d/%6d\n",
		st->cache_write, st->cache_flush);
	fprintf(stderr, "Cache hit/miss:    %6d/%6d",
		st->cache_hit, st->cache_miss);

	if (st->cache_hit + st->cache_miss)
		fprintf(stderr, " (%02d%% hit rate)\n",
			st->cache_hit * 100 / (st->cache_hit + st->cache_miss));
	else
		fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
	struct file_device dev;
	struct ufat uf;
	struct options opt;
	int err;

	if (parse_options(argc, argv, &opt) < 0)
		return -1;

	srandom(opt.seed);

	if (file_device_open(&dev, opt.filename, opt.log2_bs) < 0)
		return -1;

	err = ufat_open(&uf, &dev.base);
	if (err) {
		fprintf(stderr, "ufat_open: %s\n", ufat_strerror(err));
		file_device_close(&dev);
		return -1;
	}

	if (!opt.command) {
		show_info(&uf.bpb);
		err = 0;
	} else {
		err = opt.command->func(&uf, &opt);
	}

	ufat_close(&uf);
	file_device_close(&dev);

	if (opt.flags & OPTION_STATISTICS)
		dump_stats(&uf.stat);

	return err;
}
