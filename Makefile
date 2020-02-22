CC=gcc
CFLAGS=-Wall -Wextra -c

SRC=mem_allocator.c
EXE=mem_allocator

build: mem_allocator.o
	$(CC) $^ -o $(EXE)

mem_allocator.o: $(SRC)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf mem_allocator.o $(EXE)


