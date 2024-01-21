#!/bin/sh

gcc ./exploitable.c
patchelf --set-rpath ./ --set-interpreter ./ld-linux-x86-64.so.2 ./a.out
