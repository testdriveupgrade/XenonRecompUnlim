@echo off

clang -target powerpc-unknown-linux-gnu -fuse-ld=lld -nostdlib -m32 -o %1.elf %1