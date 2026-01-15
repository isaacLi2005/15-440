#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <arpa/inet.h>


#include "../include/dirtree.h"

#define MAXMSGLEN 100



// TCP client
int sockfd; 
int rv;

// The following line declares a function pointer with the same prototype as the open function.  
int (*orig_open)(const char *pathname, int flags, ...);  // mode_t mode is needed when flags includes O_CREAT
int (*orig_close)(int fd);
ssize_t (*orig_write)(int filedes, const void* buf, size_t nbyte);
off_t (*orig_lseek)(int fd, off_t offset, int whence);
int (*orig_stat)(const char *restrict path, struct stat *restrict statbuf);
int (*orig_unlink)(const char *pathname);
ssize_t (*orig_read)(int fd, void *buf, size_t count);


// This is our replacement for the open function from libc.
int open(const char *pathname, int flags, ...) {
	mode_t m=0;
	if (flags & O_CREAT) {
		va_list a;
		va_start(a, flags);
		m = va_arg(a, mode_t);
		va_end(a);
	}

	const char* msg = "open\n";

	rv = send(sockfd, msg, strlen(msg), 0);
	return orig_open(pathname, flags, m);
}

int close(int fd) {
	const char* msg = "close\n";

	rv = send(sockfd, msg, strlen(msg), 0);
	return orig_close(fd);
}

ssize_t read(int fd, void *buf, size_t count) {
	const char* msg = "read\n";

	rv = send(sockfd, msg, strlen(msg), 0);
	return orig_read(fd, buf, count);
}

ssize_t write(int filedes, const void* buf, size_t nbyte) {
	const char* msg = "write\n";

	rv = send(sockfd, msg, strlen(msg), 0);
	return orig_write(filedes, buf, nbyte);
}

off_t lseek(int fd, off_t offset, int whence) {
	const char* msg = "lseek\n";

	rv = send(sockfd, msg, strlen(msg), 0);
	return orig_lseek(fd, offset, whence);
}

int stat(const char *restrict path, struct stat *restrict statbuf) {
	const char* msg = "stat\n";

	rv = send(sockfd, msg, strlen(msg), 0);
	return orig_stat(path, statbuf);
}

int unlink(const char *pathname) {
	const char* msg = "unlink\n";

	rv = send(sockfd, msg, strlen(msg), 0);
	return orig_unlink(pathname);
}



// This function is automatically called when program is started
void _init(void) {
	// set function pointer orig_open to point to the original open function
	orig_open = dlsym(RTLD_NEXT, "open");
	orig_close = dlsym(RTLD_NEXT, "close");
	orig_write = dlsym(RTLD_NEXT, "write");
	orig_lseek = dlsym(RTLD_NEXT, "lseek");
	orig_stat = dlsym(RTLD_NEXT, "stat");
	orig_unlink = dlsym(RTLD_NEXT, "unlink");
	orig_read = dlsym(RTLD_NEXT, "read");




	// Create a socket fd
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in srv; // address structure
	memset(&srv, 0, sizeof(srv)); // zero it out
	srv.sin_family = AF_INET; // will be IP address and port
	char* serverIP = getenv("server15440");
	srv.sin_addr.s_addr = inet_addr(serverIP); // server IP
	unsigned short serverPort = atoi(getenv("serverport15440"));
	srv.sin_port = htons(serverPort); // port 15440 TODO: avoid hardcode. 
	rv = connect(sockfd, (struct sockaddr *) &srv,
	sizeof(struct sockaddr)); // connect to server

}

void _fini(void) {
	orig_close(sockfd);  
}


//TODO: read and the two directory trees. 
