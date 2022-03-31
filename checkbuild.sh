#!/bin/bash

mkdir -p host-build
echo "build host version"
make -C host-build -f $(pwd)/Makefile BUILD_TARGET=$(uname)  -j4

mkdir -p win32-build
echo "build win32 version"
make -C win32-build -f $(pwd)/Makefile TARGET=i686-w64-mingw32 BUILD_TARGET=mingw -j4

mkdir -p win64-build
echo "build win32 version"
make -C win64-build -f $(pwd)/Makefile TARGET=x86_64-w64-mingw32 BUILD_TARGET=mingw -j4
