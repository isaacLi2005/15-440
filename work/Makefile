CC := gcc
CFLAGS := -Wall -Wextra -O2 -g -fPIC
SO_LDFLAGS := -shared
LDLIBS := -ldl

.PHONY: all clean

all: mylib.so server

mylib.o: mylib.c
	gcc -Wall -fPIC -DPIC -c mylib.c

mylib.so: mylib.o
	gcc -shared -nostartfiles -o mylib.so mylib.o -ldl

server.o: server.c
	$(CC) -Wall -Wextra -O2 -g -c -o $@ $<

server: server.o
	$(CC) -o $@ $^

clean:
	rm -f *.o mylib.so server
