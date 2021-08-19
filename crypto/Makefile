CC = gcc
CFLAGS := -g 

test.o:test.c
	$(CC) $(CFLAGS) -c test.c -o test.o

base.o:base.c
	$(CC) $(CFLAGS) -c base.c -o base.o
all: base.o test.o
	$(CC)  $(CFLAGS) base.o test.o -o test
