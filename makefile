ml:ml.c makefile; xcrun clang -g3 -Wl,-no_pie -pagezero_size 0x1000 -o ml ml.c
