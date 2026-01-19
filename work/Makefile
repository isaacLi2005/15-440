CFLAGS  := -Wall -Wextra -O2 -g -fPIC
LDFLAGS := -L../lib -Wl,-rpath,$(abspath ../lib)
LDLIBS  := -ldl -ldirtree

.PHONY: all clean
all: mylib.so server

mylib.o: mylib.c
	gcc -Wall -fPIC -DPIC -c mylib.c

mylib.so: mylib.o
	gcc -shared -nostartfiles -o mylib.so mylib.o -ldl

server.o: server.c
	gcc $(CFLAGS) -c -o $@ $<

server: server.o
	gcc $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o mylib.so server
