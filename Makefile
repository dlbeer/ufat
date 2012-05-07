# uFAT -- small flexible VFAT implementation
# Copyright (C) 2012 TracMap Holdings Ltd
#
# Author: Daniel Beer <dlbeer@gmail.com>, www.dlbeer.co.nz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

CC ?= gcc
UFAT_CFLAGS = -O1 -Wall -ggdb

all: ufat

ufat: ufat.o ufat_dir.o ufat_file.o main.o
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(UFAT_CFLAGS) -o $*.o -c $*.c

clean:
	rm -f *.o
	rm -f ufat
