@echo off

clang -target powerpc-unknown-linux-gnu -fuse-ld=lld -nostdlib -m32 -o %~n1.elf %1