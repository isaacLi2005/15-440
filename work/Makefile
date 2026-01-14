CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS =

all: server

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(LDFLAGS)

clean:
	rm -f server
