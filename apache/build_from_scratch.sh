#!/bin/sh -e

# Check to see if build environment is setup correctly
if [ ! -e Makefile ]; then
    # Set up the build environment
    libtoolize
    aclocal
    autoconf
    automake -a
    ./configure --with-apache=/usr
else
    # Remove exising code
    make clean
fi

# Compile
make CFLAGS=-lsqlite3
