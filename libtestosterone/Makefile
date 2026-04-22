CC=gcc

all: libtestosterone.so

# Requirement: build exactly like:
#   gcc -shared -fPIC -ldl -o libtestosterone.so testosterone.c
libtestosterone.so: testosterone.c
	$(CC) -shared -fPIC -ldl -o libtestosterone.so testosterone.c

clean:
	rm -f libtestosterone.so

.PHONY: all clean

