CC = gcc
CFLAGS = -Wall -Wextra -g -fPIC -I../include
LDFLAGS_SO = -shared -ldl
# You likely won't need -L../lib yet for CP1 unless you directly link to libdirtree,
# but keeping include path is correct.

all: server mylib.so

server: server.c
	$(CC) -Wall -Wextra -g -o server server.c

mylib.so: mylib.c
	$(CC) $(CFLAGS) $(LDFLAGS_SO) -o mylib.so mylib.c

clean:
	rm -f server mylib.so
