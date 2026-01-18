// Code for converting a server_fd to a client_fd was taken from Gemini. 


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
#include <stdint.h>


#include "../include/dirtree.h"


#define REMOTE_FD_OFFSET 100000


struct remote_fd_entry {
	bool in_use; 
	int server_fd; 
}; 
static struct remote_fd_entry* remote_entries = NULL; 
static size_t remote_entry_capacity = 0; 

static int ensure_remote_size(size_t num_needed) {
	if (remote_entry_capacity >= num_needed) {
		return 0; 
	}

	size_t cap; 
	if (remote_entry_capacity == 0) {
		cap = 1; 
	} else {
		cap = remote_entry_capacity; 
	}

	while (cap < num_needed) {
		cap *= 2; 
	}

	struct remote_fd_entry* new_remote_entries =
		(struct remote_fd_entry*)malloc(cap * sizeof(struct remote_fd_entry)); 
	if (new_remote_entries == NULL) {
		return -1; 
	}
	if (remote_entries != NULL && remote_entry_capacity > 0) {
		memcpy(new_remote_entries, remote_entries, remote_entry_capacity * sizeof(struct remote_fd_entry)); 
	}
	for (size_t i = remote_entry_capacity; i < cap; i++) {
		new_remote_entries[i].in_use = false; 
		new_remote_entries[i].server_fd = -1; 
	}

	free(remote_entries); 
	remote_entries = new_remote_entries; 
	remote_entry_capacity = cap; 
	return 0; 

}

static int record_remote_fd(int server_fd) {
	if (remote_entry_capacity == 0) {
		if (ensure_remote_size(1) < 0) {
			return -1; 
		}
	}

	// Find a free slot and record 
	for (size_t i = 0; i < remote_entry_capacity; i++) {
		if (remote_entries[i].in_use == false) {
			remote_entries[i].in_use = true; 
			remote_entries[i].server_fd = server_fd; 
			return (int)(REMOTE_FD_OFFSET + (int)i);
		}
	}

	// Resize if nothing was found. 
	size_t old_size = remote_entry_capacity;
	if (ensure_remote_size(old_size + 1) < 0) {
		return -1; 
	}

	for (size_t i = old_size; i < remote_entry_capacity; i++) {
		if (remote_entries[i].in_use == false) {
			remote_entries[i].in_use = true; 
			remote_entries[i].server_fd = server_fd; 
			return (int)(REMOTE_FD_OFFSET + (int)i);
		}
	}

	return -1; 	

}

static bool is_remote_fd(int fd) {
	if (fd < REMOTE_FD_OFFSET) {
		return false; 
	} 
	size_t index = (size_t)(fd) - (size_t)(REMOTE_FD_OFFSET);
	if (index >= remote_entry_capacity) {
		return false; 
	} else {
		return remote_entries[index].in_use;
	}
}

static void free_remote_fd(int client_fd) {
	if (is_remote_fd(client_fd) == false) {
		return; 
	}
	size_t index = (size_t)(client_fd) - (size_t)(REMOTE_FD_OFFSET); 
	remote_entries[index].in_use = false; 
	remote_entries[index].server_fd = -1; 
}

static int client_fd_to_server_fd(int client_fd) {
	if (is_remote_fd(client_fd) == false) {
		return -1; 
	}
	size_t index = (size_t)(client_fd - REMOTE_FD_OFFSET); 
	return remote_entries[index].server_fd; 
}

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


// Op codes 
enum {
	OP_OPEN = 1, 
	OP_WRITE = 2, 
	OP_CLOSE = 3, 
	OP_LSEEK = 4, 
	OP_READ = 5
};

static int send_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t rv = send(fd, p + sent, n - sent, 0);
        if (rv <= 0) {
            return -1;
        }
        sent += (size_t)rv;
    }
    return 0;
}

static int recv_all(int fd, void* buf, size_t n) {
    uint8_t* p = (uint8_t*)buf; 
    size_t got = 0; 

    while (got < n) {
        ssize_t rv = recv(fd, p + got, n - got, 0); 
        if (rv < 0) {
            return -1;
        } else if (rv == 0) {
            return 0; 
        }
        got += (size_t)rv; 
    }
    return 1; 
}

static uint8_t* create_rpc_buf(uint32_t total_size) {
	
	uint8_t* buf = (uint8_t*)malloc(total_size); 
	if (buf == NULL) {
		fprintf(stderr, "Malloc fails in create_rpc_buf \n");
		return NULL; 
	}

	return buf; 	
}

static void free_rpc_buf(uint8_t* rpc_buf) {
	free(rpc_buf);
}

static int rpc_send_open(int sockfd, const char* pathname, int flags, mode_t mode) {
	// Include end '\0'
	uint32_t path_len = (uint32_t)strlen(pathname) + 1; 

	// Payload = flags + mode + path_len + pathname 
	uint32_t payload_len = (uint32_t)(4 + 4 + 4 + path_len); 
	uint32_t total_len = 8 + payload_len; 

	uint8_t* buf = create_rpc_buf(total_len); 

	size_t buf_offset = 0;

	// Header start
	uint32_t op_number_network = htonl((uint32_t)OP_OPEN);
	memcpy(buf + buf_offset, &op_number_network, 4);
	buf_offset += 4;

	uint32_t payload_length_network = htonl(payload_len);
	memcpy(buf + buf_offset, &payload_length_network, 4); 
	buf_offset += 4;

	// Payload start
	uint32_t flags_network = htonl((uint32_t)flags); 
	memcpy(buf + buf_offset, &flags_network, 4);
	buf_offset += 4;

	uint32_t mode_network = htonl((uint32_t)mode); 
	memcpy(buf + buf_offset, &mode_network, 4);
	buf_offset += 4;

	uint32_t path_len_network = htonl(path_len);
	memcpy(buf + buf_offset, &path_len_network, 4);
	buf_offset += 4; 

	memcpy(buf + buf_offset, pathname, path_len); 
	buf_offset += path_len; 

	// Send the buffer. 
	int rc = send_all(sockfd, buf, total_len); 

	free_rpc_buf(buf); 

	if (rc < 0) {
		return -1;
	}

	return 0;

}

static int rpc_recv_int_and_errno_response(int sockfd) {
	// Response in form of [int, 4][errno, 4] in network byte order. 
	// Assumes this is a function like read, write, close where the int 
	// implies whether the errno is used. 
	uint32_t int_network, errno_network; 
	int rc; 

	rc = recv_all(sockfd, &int_network, 4); 
	if (rc <= 0) {
		return -1; 
	}

	rc = recv_all(sockfd, &errno_network, 4); 
	if (rc <= 0) {
		return -1; 
	}

	int32_t int_result = (int32_t)(ntohl(int_network));
	int32_t received_errno = (int32_t)(ntohl(errno_network)); 

	if (int_result < 0) {
		errno = received_errno; 
		return -1; 
	} else {
		return (int)int_result; 
	}
}

// This is our replacement for the open function from libc.
int open(const char *pathname, int flags, ...) {
	mode_t m=0;
	if (flags & O_CREAT) {
		va_list a;
		va_start(a, flags);
		m = va_arg(a, mode_t);
		va_end(a);
	}

	
	int rv = rpc_send_open(sockfd, pathname, flags, m);
	if (rv < 0) {
		errno = EIO; 
		return -1; 
	}
	
	int server_fd = rpc_recv_int_and_errno_response(sockfd);

	if (server_fd < 0) {
		return -1; 
	} else {
		int client_fd = record_remote_fd(server_fd);
		if (client_fd < 0) {
			return -1; 
		}
		return client_fd; 
	}

}

static int rpc_send_close(int sockfd, int fd) {
	if (is_remote_fd(fd) == false) {
		return -1; 
	}

	int server_fd = client_fd_to_server_fd(fd); 

	uint32_t payload_len = (uint32_t)(4);
	uint32_t total_len = (uint32_t)(8) + payload_len; 

	uint8_t* buf = create_rpc_buf(total_len); 

	size_t buf_offset = 0; 

	// Header start
	uint32_t op_number_network = htonl((uint32_t)OP_CLOSE);
	memcpy(buf + buf_offset, &op_number_network, 4);
	buf_offset += 4;

	uint32_t payload_length_network = htonl(payload_len);
	memcpy(buf + buf_offset, &payload_length_network, 4); 
	buf_offset += 4;

	// Payload start 
	uint32_t fd_network = htonl((uint32_t)(int32_t)server_fd); 
	memcpy(buf + buf_offset, &fd_network, 4); 
	buf_offset += 4; 


	// Send the buffer. 
	int rc = send_all(sockfd, buf, total_len); 

	free_rpc_buf(buf); 

	if (rc < 0) {
		return -1;
	}

	return 0;
}

int close(int fd) {
	if (is_remote_fd(fd) == false) {
		return orig_close(fd); 
	}

	if (rpc_send_close(sockfd, fd) < 0) {
		return -1; 
	}

	int close_return = rpc_recv_int_and_errno_response(sockfd); 
	if (close_return < 0) {
		return -1; 
	} else {
		free_remote_fd(fd); 
		return close_return; 
	}

}

static int rpc_send_write(int sockfd, int server_fd, const void* write_buf, size_t n_bytes) {
	//[server_fd, 4][n_bytes, 8][write_buf, n_bytes]

	if (n_bytes > UINT32_MAX) {
		fprintf(stderr, "Too many bytes in write call \n"); 
		return -1; 
	}

	// Payload = fd + payload
	uint32_t payload_len = (uint32_t)(4 + 8 + n_bytes); 
	uint32_t total_len = 8 + payload_len; 

	uint8_t* buf = create_rpc_buf(total_len); 

	size_t buf_offset = 0;

	// Header start
	uint32_t op_number_network = htonl((uint32_t)OP_WRITE); 
	memcpy(buf + buf_offset, &op_number_network, 4); 
	buf_offset += 4; 

	uint32_t payload_len_network = htonl((uint32_t)(payload_len));
	memcpy(buf+buf_offset, &payload_len_network, 4); 
	buf_offset += 4; 

	// Payload start
	uint32_t server_fd_network = htonl((uint32_t)(int32_t)(server_fd)); 
	memcpy(buf + buf_offset, &server_fd_network, 4); 
	buf_offset += 4; 

	memcpy(buf + buf_offset, &n_bytes, 8); 
	buf_offset += 8; 

	memcpy(buf + buf_offset, write_buf, n_bytes); 
	buf_offset += n_bytes; 


	// Send the buffer. 
	int rc = send_all(sockfd, buf, total_len); 

	free_rpc_buf(buf); 

	if (rc < 0) {
		return -1;
	}

	return 0;
}

//TODO: size_t is actually 64 bits. 

static ssize_t rpc_recv_write_response(int sockfd) {
	// Response in form of [ssize_t, 8][errno, 4] in network byte order. 
	// Assumes this is a function like read, write, close where the int 
	// implies whether the errno is used. 
	int64_t size;
	uint32_t errno_network; 
	int rc; 

	rc = recv_all(sockfd, &size, 8); 
	if (rc <= 0) {
		return -1; 
	}

	rc = recv_all(sockfd, &errno_network, 4); 
	if (rc <= 0) {
		return -1; 
	}

	int32_t received_errno = (int32_t)(ntohl(errno_network)); 

	if (size < 0) {
		errno = received_errno; 
		return -1; 
	} else {
		return (ssize_t)size; 
	}
}

ssize_t write(int fd, const void* buf, size_t n_bytes) {
	if (is_remote_fd(fd) == false) {
		return orig_write(fd, buf, n_bytes); 
	}

	int server_fd = client_fd_to_server_fd(fd); 

	if (rpc_send_write(sockfd, server_fd, buf, n_bytes) < 0) {
		return -1; 
	}

	ssize_t write_return = (ssize_t)rpc_recv_write_response(sockfd); 
	return write_return; 
}

static int rpc_send_read(int sockfd, int server_fd, size_t count) {
	// [server_fd, 4][count, 8]
	// Note we don't send the buf. That will be copied in the recv function. 

	if (count > UINT32_MAX) {
		fprintf(stderr, "Too many bytes in read call \n"); 
		return -1; 
	}

	// Payload = fd + payload
	uint32_t payload_len = (uint32_t)(4 + 8); 
	uint32_t total_len = 8 + payload_len; 
 
	uint8_t* buf = create_rpc_buf(total_len); 
	size_t buf_offset = 0;

	// Header start
	uint32_t op_number_network = htonl((uint32_t)OP_READ); 
	memcpy(buf + buf_offset, &op_number_network, 4); 
	buf_offset += 4; 

	uint32_t payload_len_network = htonl((uint32_t)(payload_len));
	memcpy(buf+buf_offset, &payload_len_network, 4); 
	buf_offset += 4; 

	// Payload start
	uint32_t server_fd_network = htonl((uint32_t)(int32_t)(server_fd)); 
	memcpy(buf + buf_offset, &server_fd_network, 4); 
	buf_offset += 4; 

	memcpy(buf + buf_offset, &count, 8); 
	buf_offset += 8; 

	// Send the buffer. 
	int rc = send_all(sockfd, buf, total_len); 

	free_rpc_buf(buf); 

	if (rc < 0) {
		return -1;
	}

	return 0;
}

static ssize_t rpc_recv_read_response(int sockfd, void* buf) {
	// [read_result, 8][errno_network, 4][read_buf, count]

	int64_t read_result;
	uint32_t errno_network; 

	int rc; 

	rc = recv_all(sockfd, &read_result, 8); 
	if (rc <= 0) {
		return -1; 
	}

	rc = recv_all(sockfd, &errno_network, 4); 
	if (rc <= 0) {
		return -1; 
	}

	int32_t received_errno = (int32_t)(ntohl(errno_network)); 


	if (read_result < 0) {
		errno = received_errno; 
		return -1; 
	} 

	void* read_bytes = malloc(read_result); 
	rc = recv_all(sockfd, read_bytes, read_result); 
	if (rc < 0) {
		return -1; 
	}

	memcpy(buf, read_bytes, read_result); 
	

	free(read_bytes); 
	return (ssize_t)read_result; 
	
}

ssize_t read(int fd, void *buf, size_t count) {
	if (is_remote_fd(fd) == false) {
		return orig_read(fd, buf, count); 
	}
	int server_fd = client_fd_to_server_fd(fd); 

	if (rpc_send_read(sockfd, server_fd, count) < 0) {
		return -1; 
	}

	ssize_t read_return = (ssize_t)rpc_recv_read_response(sockfd, buf); 
	return read_return; 
}

static int rpc_send_lseek(int sockfd, int server_fd, off_t offset, int whence) {
	//[server_fd, 4][offset, 8][whence, 4]

	// Payload = int + off_t + int
	uint32_t payload_len = (uint32_t)(4 + 8 + 4); 
	uint32_t total_len = 8 + payload_len; 

	uint8_t* buf = create_rpc_buf(total_len); 

	size_t buf_offset = 0;

	// Header start
	uint32_t op_number_network = htonl((uint32_t)OP_LSEEK); 
	memcpy(buf + buf_offset, &op_number_network, 4); 
	buf_offset += 4; 

	uint32_t payload_len_network = htonl((uint32_t)(payload_len));
	memcpy(buf+buf_offset, &payload_len_network, 4); 
	buf_offset += 4; 

	// Payload start
	uint32_t server_fd_network = htonl((uint32_t)(int32_t)(server_fd)); 
	memcpy(buf + buf_offset, &server_fd_network, 4); 
	buf_offset += 4; 

	//TODO: There is no htonll function so we have to just hope this works. 
	off_t off = offset;
	memcpy(buf + buf_offset, &off, 8);
	buf_offset += 8;

	uint32_t whence_network = htonl((uint32_t)whence);
	memcpy(buf + buf_offset, &whence_network, 4); 
	buf_offset += 4; 


	// Send the buffer. 
	int rc = send_all(sockfd, buf, total_len); 

	free_rpc_buf(buf); 

	if (rc < 0) {
		return -1;
	}

	return 0; 
}

static off_t rpc_recv_lseek_response(int sockfd) {
	// [off_t, 8][errno, 4]
	off_t seeked; 
	uint32_t errno_network; 

	int rc; 

	rc = recv_all(sockfd, &seeked, 8); 
	if (rc <= 0) {
		return -1; 
	}

	rc = recv_all(sockfd, &errno_network, 4); 
	if (rc <= 0) {
		return -1; 
	}

	int32_t received_errno = (int32_t)(ntohl(errno_network)); 

	if (seeked == (off_t)(-1)) {
		errno = received_errno; 
		return (off_t)(-1); 
	} else {
		return seeked; 
	}
}

off_t lseek(int fd, off_t offset, int whence) {
	// const char* msg = "lseek\n";
	if (is_remote_fd(fd) == false) {
		return orig_lseek(fd, offset, whence); 
	}

	int server_fd = client_fd_to_server_fd(fd); 

	if (rpc_send_lseek(sockfd, server_fd, offset, whence) < 0) {
		return -1; 
	}

	off_t lseek_return = rpc_recv_lseek_response(sockfd); 
	return lseek_return; 
}

int stat(const char *restrict path, struct stat *restrict statbuf) {
	// const char* msg = "stat\n";

	// rv = send(sockfd, msg, strlen(msg), 0);
	return orig_stat(path, statbuf);
}

int unlink(const char *pathname) {
	// const char* msg = "unlink\n";

	// rv = send(sockfd, msg, strlen(msg), 0);
	return orig_unlink(pathname);
}

ssize_t getdirentries(int fd, char *buf, size_t nbytes, off_t *basep) {
    //const char *msg = "getdirentries\n";

    //int saved_errno = errno;
    //send(sockfd, msg, strlen(msg), 0);
    //errno = saved_errno;

    return orig_getdirentries(fd, buf, nbytes, basep);
}

struct dirtreenode* getdirtree(const char *path) {
    // const char *msg = "getdirtree\n";

    // send(sockfd, msg, strlen(msg), 0);
    return orig_getdirtree(path);
}

void freedirtree(struct dirtreenode *dt) {
    // const char *msg = "freedirtree\n";
	
    // send(sockfd, msg, strlen(msg), 0);
    orig_freedirtree(dt);
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
