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
int (*orig___xstat)(int ver, const char *path, struct stat *statbuf);
int (*orig_unlink)(const char *pathname);
ssize_t (*orig_read)(int fd, void *buf, size_t count);
struct dirtreenode* (*orig_getdirtree)(const char *path);
void (*orig_freedirtree)(struct dirtreenode *dt);
ssize_t (*orig_getdirentries)(int fd, char *buf, size_t nbytes, off_t *basep);




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

int __xstat(int ver, const char *path, struct stat *statbuf) {
    const char *msg = "__xstat\n";

    send(sockfd, msg, strlen(msg), 0);
    return orig___xstat(ver, path, statbuf);
}

int unlink(const char *pathname) {
	const char* msg = "unlink\n";

	rv = send(sockfd, msg, strlen(msg), 0);
	return orig_unlink(pathname);
}

struct dirtreenode* getdirtree(const char *path) {
    const char *msg = "getdirtree\n";

    send(sockfd, msg, strlen(msg), 0);
    return orig_getdirtree(path);
}

void freedirtree(struct dirtreenode *dt) {
    const char *msg = "freedirtree\n";
	
    send(sockfd, msg, strlen(msg), 0);
    orig_freedirtree(dt);
}


ssize_t getdirentries(int fd, char *buf, size_t nbytes, off_t *basep) {
    const char *msg = "getdirentries\n";

    int saved_errno = errno;
    send(sockfd, msg, strlen(msg), 0);
    errno = saved_errno;

    return orig_getdirentries(fd, buf, nbytes, basep);
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
	orig_getdirtree  = dlsym(RTLD_NEXT, "getdirtree");
	orig_freedirtree = dlsym(RTLD_NEXT, "freedirtree");
	orig___xstat  = dlsym(RTLD_NEXT, "__xstat");
	orig_getdirentries = dlsym(RTLD_NEXT, "getdirentries");





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


//TODO: Dealing with errno and failure checks. 
