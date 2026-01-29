/**
 * server.c 
 * 
 * This file sets up the server for the assignment that is able to take in RPCs from clients. It sets up a socket and 
 * listens to clients, forking off child processes so that we can handle those clients in parallel. This file also 
 * includes all the helper functions necessary to interpret messages from the client. 
 * 
 * The format for requests from the client and responses to the client is standardized so that both sides can 
 * understand the meaning of raw bytes sent back and forth. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#include <stdbool.h>
#include <errno.h>
#include <stdint.h>

#include <fcntl.h> 
#include <sys/types.h>
#include <sys/stat.h> 

#include "../include/dirtree.h"

#include <dirent.h>

#include <assert.h>

#include <signal.h>  
#include <sys/wait.h> 

/**
 * The integer opcodes we define here are understood to be the same across the server and the client. 
 * These allow the server and the client to agree on the meaning of bytes in packages sent across the network. 
 */
enum {
	OP_OPEN = 1, 
	OP_WRITE = 2, 
	OP_CLOSE = 3, 
	OP_LSEEK = 4, 
	OP_READ = 5, 
	OP_STAT = 6, 
	OP_UNLINK = 7,
	OP_GETDIRENTRIES = 8, 
	OP_GETDIRTREE = 9 
};

void sigchld_handler(int sig) {
    /**
     * This function handles the SIGCHLD signal, for when a forked child process has finished running, by reaping any 
     * child processes that have finished. 
     * 
     * Parameters: 
     *  - int sig: A dummy input, used to make sure this function fits a required template for handlers. 
     * 
     * This function was heavily inspired by a similiar function from the 15-213 textbook, Computer Systems - A 
     * Programmer's Perspective, Bryant et. al. 
     */

    (void)sig; 

    int olderrno = errno; 

    while (waitpid(-1, 0, WNOHANG) > 0); 

    errno = olderrno; 

    return;
}

static int recv_all(int fd, void* buf, size_t n) {
    /**
     * This function makes sure that the entirety of n requested bytes is read from a particular file 
     * (usually a socket). This is used to prevent short reads. 
     * 
     * Parameters: 
     *  - int fd: The file descriptor we want to receive bytes on. 
     *  - void* buf: The buffer we want to read bytes to. 
     *  - size_t n: The number of bytes we want to receive. 
     * 
     * Returns 1 on success, 0 on an end of file, and -1 on failure. 
     */

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

static int send_all(int fd, const void *buf, size_t n) {
    /**
     * This function makes sure that the entirety of n requested bytes are sent to a particular file (usually a socket). 
     * This is used to prevent short writes. 
     * 
     * Parameters: 
     *  - int fd: The file descriptpor we want to send bytes to. 
     *  - const void *buf: The buffer we want to send bytes from. 
     *  - size_t n: The number of bytes we want to send to the file descriptor. 
     * 
     * Returns 0 on success and -1 on failure. 
     */

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

static void copy_in(uint8_t* dest_buf, const void* source, size_t num_bytes, 
					  bool convert_to_network_endianness, size_t* dest_offset) {
	/**
	 * A helper function that handles copying data from a source into a destination at a particular offset. 
	 * 
	 * Parameters
	 * 	- dest_buf: The buffer we are copying to. 
	 * 	- source: The source of the data we want to copy over. 
	 * 	- num_bytes: The number of bytes we want to copy over. 
	 * 	- convert_to_network: Whether the converted bytes should be converted to network endianness. 
	 * 	- dest_offset: Pointer to the offset in the destination we should be writing to. 
	 * 
	 * Has no return value. 
	 * 
	 * Has the effect of copying bytes over from source to dest_buf. 
	 */

	assert(dest_buf != NULL); 
	assert(source != NULL); 
	assert(dest_offset != NULL); 

	if (convert_to_network_endianness == true) {
		assert(num_bytes == sizeof(uint32_t));

		uint32_t network_bytes; 
		memcpy(&network_bytes, source, sizeof(uint32_t)); 
		network_bytes = htonl(network_bytes); 
		memcpy(dest_buf + *dest_offset, &network_bytes, num_bytes); 
	} else {
		memcpy(dest_buf + *dest_offset, source, num_bytes); 
	}

	*dest_offset += num_bytes;

}

static void copy_out(void* dest, const uint8_t* source_buf, size_t num_bytes, 
					  bool convert_from_network_endianness, size_t* source_offset) {
	/**
	 * A helper function that handles copying data from a source into a destination at a particular offset from the 
     * source. 
	 * 
	 * Parameters
	 * 	- dest_buf: The buffer we are copying to. 
	 * 	- source: The source of the data we want to copy over. 
	 * 	- num_bytes: The number of bytes we want to copy over. 
	 * 	- convert_to_local_endianness: Whether the converted bytes should be converted from network endianness. 
	 * 	- source_offset: Pointer to the offset in the source we should be writing from. 
	 * 
	 * Has no return value. 
	 * 
	 * Has the effect of copying bytes over from source to dest_buf. 
	 */

	assert(dest != NULL); 
	assert(source_buf != NULL); 
	assert(source_offset != NULL); 

	if (convert_from_network_endianness == true) {
		assert(num_bytes == sizeof(uint32_t));

		uint32_t network_bytes; 
		memcpy(&network_bytes, source_buf + *source_offset, sizeof(uint32_t)); 
		network_bytes = ntohl(network_bytes); 
		memcpy(dest, &network_bytes, sizeof(uint32_t)); 
	} else {
		memcpy(dest, source_buf + *source_offset, num_bytes); 
	}

	*source_offset += num_bytes;

}

static int handle_open_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    /**
     * This function interprets the payload of an open RPC from the client into local arguments, passes those local 
     * arguments to the standard library open() function, and then responds to the client with the output of the 
     * standard library call. 
     * 
     * Parameters: 
     *  - int sessfd: A file descriptor corresponding to the client being serviced. 
     *  - const uint8_t* payload: The payload containing arguments for the open() function from the clients. 
     *  - uint32_t payload_len: The length in bytes of the payload. 
     * 
     * Returns 0 on success and -1 on failure. 
     * 
     * The payload from the client is understood to have the following contiguous order: 
     * 1. [flags, 4 bytes]
     * 2. [mode, 4 bytes]
     * 3. [path_len, 4 bytes]
     * 4. [pathname, path_len bytes]
     * 
     * The response back to the client is formatted in this contiguous order: 
     * 1. [fd, 4 bytes]
     * 2. [errno, 4 bytes]
     */

    //[flags, 4][mode, 4][path_len, 4][pathname, path_len]
    if (payload_len < sizeof(int) + sizeof(int) + sizeof(uint32_t)) {
        fprintf(stderr, "Open payload too short in server.c: %u\n", payload_len);
        return -1;
    }

    size_t out_offset = 0; 
    uint32_t flags, mode, pathlen; 
    copy_out(&flags, payload, sizeof(uint32_t), true, &out_offset); 
    copy_out(&mode, payload, sizeof(uint32_t), true, &out_offset);
    copy_out(&pathlen, payload, sizeof(uint32_t), true, &out_offset); 

    if ((uint32_t)(sizeof(int) + sizeof(int) + sizeof(uint32_t)) + pathlen != payload_len) {
        fprintf(stderr, "OPEN payload mismatch: payload_len is %u, pathlen is %u \n", payload_len, pathlen);
        return -1;
    }

    const char* pathname = (const char*)(payload+ (sizeof(int) + sizeof(int) + sizeof(uint32_t)));
    if (pathlen == 0 || pathname[pathlen - 1] != '\0') {
        fprintf(stderr, "OPEN pathname not NUL-terminated (pathlen=%u) \n", pathlen);
        return -1;
    }


    int fd; 
    if (flags & O_CREAT) {
        fd = open(pathname, flags, (mode_t)mode);
    } else {
        fd = open(pathname, flags);
    }

    int32_t ret_fd = (int32_t)fd; 
    int32_t ret_errno = 0; 
    if (fd < 0) {
        ret_errno = (int32_t)errno; 
    } else {
        ret_errno = 0;
    }
    // Open response: [fd, 4][errno, 4]
    uint8_t* response_buf = (uint8_t*)malloc(sizeof(int32_t) + sizeof(int32_t));
    if (response_buf == NULL) {
        return -1; 
    }

    size_t in_offset = 0; 
    copy_in(response_buf, &ret_fd, sizeof(int32_t), true, &in_offset); 
    copy_in(response_buf, &ret_errno, sizeof(int32_t), true, &in_offset); 

    if (send_all(sessfd, response_buf, sizeof(int) + sizeof(int)) < 0) {
        free(response_buf);
        return -1;
    } else {
        free(response_buf);
        return 0;
    }
}

static int handle_write_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    /**
     * This function interprets the payload of an write RPC from the client into local arguments, passes those local 
     * arguments to the standard library write() function, and then responds to the client with the output of the 
     * standard library call. 
     * 
     * Parameters: 
     *  - int sessfd: The file descriptor corresponding to the client who has passed the payload. 
     *  - const uint8_t* payload: The payload bytes containing the arguments for write() from the client. 
     *  - uint32_t payload_length: The size of the payload in bytes from the client. 
     * 
     * Returns 0 on success and -1 on failure. 
     * 
     * The payload from the client is understood to have the following contiguous order: 
     * 1. [server_fd, 4 bytes]
     * 2. [n_bytes, 8 bytes]
     * 3. [write_buf, n_bytes bytes]
     * 
     * The response back to the client is formatted in this contiguous order: 
     * 1. [result, 8 bytes]
     * 2. [errno, 4 bytes]
     */

    // [server_fd, 4][n_bytes, 8][write_buf, n_bytes]
    if (payload_len < sizeof(uint32_t) + sizeof(uint64_t)) {
        fprintf(stderr, "Write payload too short: %u \n", payload_len); 
        return -1; 
    }

    int32_t server_fd; 
    uint64_t n_bytes; 
    size_t copy_out_offset = 0; 
    copy_out(&server_fd, payload, sizeof(uint32_t), true, &copy_out_offset); 
    copy_out(&n_bytes, payload, sizeof(uint64_t), false, &copy_out_offset); 

    if ((uint64_t)(sizeof(uint32_t) + sizeof(uint64_t)) + n_bytes != (uint64_t)payload_len) {
        fprintf(stderr, "WRITE payload mismatch: payload_len=%u n_bytes=%lu\n", payload_len, n_bytes);
        return -1;
    } else if (n_bytes > UINT32_MAX) {
        fprintf(stderr, "Write payload too big \n");
        return -1; 
    }

    uint8_t* write_bytes = (uint8_t*)malloc(n_bytes); 
    if (write_bytes == NULL) {
        fprintf(stderr, "malloc fails in write");
        return -1; 
    }
    copy_out(write_bytes, payload, n_bytes, false, &copy_out_offset); 

    ssize_t write_result = write(server_fd, write_bytes, n_bytes); 
    free(write_bytes); 

    int32_t ret_errno = 0; 
    if (write_result < 0) {
        ret_errno = (int32_t)errno; 
    } else {
        ret_errno = 0;
    }

    // Write response: [result, 8][errno, 4]
    uint8_t* response_buf = (uint8_t*)malloc(sizeof(ssize_t) + sizeof(int));
    if (response_buf == NULL) {
        return -1; 
    }

    size_t copy_in_offset = 0; 
    copy_in(response_buf, &write_result, sizeof(int64_t), false, &copy_in_offset); 
    copy_in(response_buf, &ret_errno, sizeof(int32_t), true, &copy_in_offset); 

    if (send_all(sessfd, response_buf, sizeof(ssize_t) + sizeof(int)) < 0) {
        free(response_buf);
        return -1;
    } else {
        free(response_buf);
        return 0;
    }
}

static int handle_close_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    /**
     * This function interprets the payload of an close RPC from the client into local arguments, passes those local 
     * arguments to the standard library close() function, and then responds to the client with the outputs of the 
     * standard library call. 
     * 
     * Parameters: 
     *  - int sessfd: The file descriptor corresponding to the client who has passed the payload. 
     *  - const uint8_t* payload: The payload bytes containing the arguments for write() from the client. 
     *  - uint32_t payload_length: The size of the payload in bytes from the client. 
     * 
     * Returns 0 on success and -1 on failure. 
     * 
     * The payload from the client is understood to have the following contiguous order: 
     * 1. [fd, 4 bytes]
     * 
     * The response back to the client is formatted in this contiguous order: 
     * 1. [fd, 4 bytes]
     * 2. [errno, 4 bytes]
     */

    //[fd, 4]
    if (payload_len != sizeof(int)) {
        fprintf(stderr, "Wrong close payload size: %u\n", payload_len);
        return -1;
    }

    size_t copy_out_offset = 0; 
    int32_t server_fd; 
    copy_out(&server_fd, payload, sizeof(uint32_t), true, &copy_out_offset); 

    int close_return = close((int)server_fd); 
    int32_t close_errno;
    if (close_return < 0) {
        close_errno = (int32_t)errno; 
    } else {
        close_errno = 0; 
    }

    // Open response: [fd, 4][errno, 4]
    uint8_t* response_buf = (uint8_t*)malloc(sizeof(int) + sizeof(int));

    size_t copy_in_offset = 0; 
    copy_in(response_buf, &close_return, sizeof(uint32_t), true, &copy_in_offset); 
    copy_in(response_buf, &close_errno, sizeof(uint32_t), true, &copy_in_offset); 

    if (send_all(sessfd, response_buf, sizeof(int) + sizeof(int)) < 0) {
        free(response_buf);
        return -1;
    } else {
        free(response_buf);
        return 0;
    }
}

static int handle_lseek_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    /**
     * This function interprets the payload of an lseek RPC from the client into local arguments, passes those local 
     * arguments to the standard library lseek() function, and then responds to the client with the outputs of the 
     * standard library call. 
     * 
     * Parameters: 
     *  - int sessfd: The file descriptor corresponding to the client who has passed the payload. 
     *  - const uint8_t* payload: The payload bytes containing the arguments for write() from the client. 
     *  - uint32_t payload_length: The size of the payload in bytes from the client. 
     * 
     * Returns 0 on success and -1 on failure. 
     * 
     * The payload from the client is understood to have the following contiguous order: 
	 * 1. [server_fd, 4 bytes]
	 * 2. [offset, 8 bytes]
	 * 3. [whence, 4 bytes]
     * 
     * The response back to the client is formatted in this contiguous order: 
     * 1. [offset, 8 bytes]
     * 2. [errno, 4 bytes]
     */

    if (payload_len != sizeof(int) + sizeof(off_t) + sizeof(int)) {
        fprintf(stderr, "Wrong lseek payload size: %u\n", payload_len);
        return -1;
    }

    uint32_t fd_network; 
    memcpy(&fd_network, payload, sizeof(uint32_t)); 
    int server_fd = (int)(ntohl(fd_network)); 

    int64_t off_beamed; 
    memcpy(&off_beamed, payload + sizeof(uint32_t), sizeof(int64_t)); 
    off_t offset = (off_t)(off_beamed); 

    uint32_t whence_network; 
    memcpy(&whence_network, payload + sizeof(uint32_t) + sizeof(int64_t), sizeof(uint32_t)); 
    int32_t whence = (int32_t)(ntohl(whence_network)); 

    fprintf(stderr, "SERVER lseek recv: server_fd=%d offset=%lld (0x%llx) whence=%d\n",
        server_fd,
        (long long)offset,
        (unsigned long long)offset,
        whence);
    fflush(stderr);

    off_t lseek_result = lseek(server_fd, offset, whence); 
    int32_t lseek_errno; 
    if (lseek_result < 0) {
        lseek_errno = (int32_t)errno; 
    } else {
        lseek_errno = 0; 
    }

    uint32_t errno_network = htonl((uint32_t)lseek_errno);

    // lseek response: [offset, 8][errno, 4]
    uint8_t* response_buf = (uint8_t*)malloc(sizeof(int64_t) + sizeof(int));
    int64_t result_beamed = (int64_t)lseek_result; 
    memcpy(response_buf, &result_beamed, sizeof(int64_t));
    memcpy(response_buf + sizeof(int64_t), &errno_network, sizeof(int)); 

    if (send_all(sessfd, response_buf, sizeof(int64_t) + sizeof(int)) < 0) {
        free(response_buf);
        return -1;
    } else {
        free(response_buf);
        return 0;
    }
}

static int handle_read_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    /**
     * This function interprets the payload of a read RPC from the client into local arguments, passes those local 
     * arguments to the standard library read() function, and then responds to the client with the outputs of the 
     * standard library call. 
     * 
     * Parameters: 
     *  - int sessfd: The file descriptor corresponding to the client who has passed the payload. 
     *  - const uint8_t* payload: The payload bytes containing the arguments for write() from the client. 
     *  - uint32_t payload_length: The size of the payload in bytes from the client. 
     * 
     * Returns 0 on success and -1 on failure. 
     * 
     * The payload from the client is understood to have the following contiguous order: 
	 * 1. [server_fd, 4 bytes]
	 * 2. [count, 8 bytes]
     * 
     * The response back to the client is formatted in this contiguous order: 
     * 1. [read_result, 8 bytes]
     * 2. [errno, 4 bytes]
     * 3. [read_buf, count bytes]
     */

    // [server_fd, 4][count, 8]
    if (payload_len != sizeof(int) + sizeof(uint64_t)) {
        fprintf(stderr, "Wrong read payload size: %u\n", payload_len);
        return -1;
    }

    uint32_t fd_network; 
    memcpy(&fd_network, payload, sizeof(uint32_t)); 
    int server_fd = (int)(ntohl(fd_network)); 

    uint64_t count_received; 
    memcpy(&count_received, payload + sizeof(uint32_t), sizeof(uint64_t)); 
    size_t count = (size_t)(count_received); 

    if (count == 0) {
        int64_t read_result = 0; 
        uint32_t errno_network = htonl(0); 

        uint8_t* response = malloc(sizeof(uint64_t) + sizeof(uint32_t)); 
        memcpy(response, &read_result, sizeof(uint64_t)); 
        memcpy(response + sizeof(uint64_t), &errno_network, sizeof(uint32_t)); 
        int rc = (send_all(sessfd, response, sizeof(uint32_t) + sizeof(uint64_t))); 
        free(response); 
        if (rc < 0) {
            return -1; 
        } else {
            return 0; 
        }
    }

    void* read_buf = malloc(count); 
    if (read_buf == NULL) {
        return -1; 
    }

    ssize_t read_result = read(server_fd, read_buf, count); 

    int32_t read_errno; 
    if (read_result < 0) {
        read_errno = (int32_t)errno; 
    } else {
        read_errno = 0; 
    }
    uint32_t errno_network = htonl((uint32_t)read_errno);
    int64_t result_beamed = (int64_t)read_result; 

    size_t data_length; 
    if (read_result > 0) {
        data_length = (size_t)read_result;
    } else {
        data_length = 0; 
    }

    // read response: [read_result, 8][errno_network, 4][read_buf, count]
    uint8_t* response_buf = (uint8_t*)malloc(sizeof(ssize_t) + sizeof(int) + data_length);
    if (response_buf == NULL) {
        free(response_buf);
        free(read_buf);
        return -1; 
    }

    memcpy(response_buf, &result_beamed, sizeof(ssize_t));
    memcpy(response_buf + sizeof(ssize_t), &errno_network, sizeof(int)); 
    if (data_length > 0) {
        memcpy(response_buf + sizeof(ssize_t) + sizeof(int), read_buf, data_length); 
    }
    

    if (send_all(sessfd, response_buf, sizeof(ssize_t) + sizeof(int) + data_length) < 0) {
        free(response_buf);
        free(read_buf);
        return -1;
    } else {
        free(response_buf);
        free(read_buf); 
        return 0;
    }
}

static int handle_stat_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    /**
     * This function interprets the payload of a stat RPC from the client into local arguments, passes those local 
     * arguments to the standard library stat() function, and then responds to the client with the outputs of the 
     * standard library call. 
     * 
     * Parameters: 
     *  - int sessfd: The file descriptor corresponding to the client who has passed the payload. 
     *  - const uint8_t* payload: The payload bytes containing the arguments for write() from the client. 
     *  - uint32_t payload_length: The size of the payload in bytes from the client. 
     * 
     * Returns 0 on success and -1 on failure. 
     * 
     * The payload from the client is understood to have the following contiguous order: 
	 * 1. [path_length, 4 bytes]
	 * 2. [path, path_length bytes]
     * 
     * The response back to the client is formatted in this contiguous order: 
     * 1. [stat_result, 4 bytes]
     * 2. [errno, 4 bytes]
     * 3. [stat struct, sizeof(struct stat) bytes]
     */

    //[path_length, 4][path, path_length]

    if (payload_len < sizeof(uint32_t)) {
        fprintf(stderr, "Wrong stat payload size: %u\n", payload_len);
        return -1;
    }

    uint32_t path_length_network; 
    memcpy(&path_length_network, payload, sizeof(uint32_t)); 
    int path_length = (int)(ntohl(path_length_network)); 

    char* path = (char*)malloc(path_length); 
    if (path == NULL) {
        free(path); 
        return -1; 
    }
    memcpy(path, payload + sizeof(uint32_t), path_length); 

    struct stat st; 
    int stat_result = stat(path, &st); 
    free(path);

    int32_t stat_errno; 
    if (stat_result < 0) {
        stat_errno = (int32_t)errno; 
    } else {
        stat_errno = 0; 
    }
    uint32_t stat_result_network = htonl((uint32_t)stat_result); 
    uint32_t errno_network = htonl((uint32_t)stat_errno); 
    

    // [stat_result, 4][errno, 4][struct stat, sizeof(struct stat)] 
    uint8_t* response_buf = (uint8_t*)malloc(sizeof(int) + sizeof(int) + sizeof(struct stat)); 
    if (response_buf == NULL) {
        free(response_buf); 
        return -1; 
    }

    memcpy(response_buf, &stat_result_network, sizeof(int)); 
    memcpy(response_buf + sizeof(int), &errno_network, sizeof(int)); 
    memcpy(response_buf + sizeof(int) + sizeof(int), &st, sizeof(struct stat)); 

    if (send_all(sessfd, response_buf, sizeof(int) + sizeof(int) + sizeof(struct stat)) < 0) {
        free(response_buf);
        return -1;
    } else {
        free(response_buf);
        return 0;
    }
}

static int handle_unlink_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    /**
     * This function interprets the payload of an unlink RPC from the client into local arguments, passes those local 
     * arguments to the standard library unlink() function, and then responds to the client with the outputs of the 
     * standard library call. 
     * 
     * Parameters: 
     *  - int sessfd: The file descriptor corresponding to the client who has passed the payload. 
     *  - const uint8_t* payload: The payload bytes containing the arguments for write() from the client. 
     *  - uint32_t payload_length: The size of the payload in bytes from the client. 
     * 
     * Returns 0 on success and -1 on failure. 
     * 
     * The payload from the client is understood to have the following contiguous order: 
	 * 1. [path_length, 4 bytes]
	 * 2. [path, path_length bytes]
     * 
     * The response back to the client is formatted in this contiguous order: 
     * 1. [unlink_result, 4 bytes]
     * 2. [unlink_errno, 4 bytes]
     */

    //[path_length, 4][path, path_length]

    if (payload_len < sizeof(uint32_t)) {
        fprintf(stderr, "Wrong stat payload size: %u\n", payload_len);
        return -1;
    }

    uint32_t path_length_network; 
    memcpy(&path_length_network, payload, sizeof(uint32_t)); 
    int path_length = (int)(ntohl(path_length_network)); 

    char* path = (char*)malloc(path_length); 
    if (path == NULL) {
        return -1; 
    }
    memcpy(path, payload + sizeof(uint32_t), path_length); 

    int unlink_result = unlink(path); 

    free(path); 

    int32_t unlink_errno; 
    if (unlink_result < 0) {
        unlink_errno = errno; 
    } else {
        unlink_errno = 0; 
    }

    uint32_t unlink_result_network = htonl((uint32_t)unlink_result); 
    uint32_t errno_network = htonl((uint32_t)unlink_errno); 
    
    // read response: [unlink_result, 4][unlink_errno, 4]
    uint8_t* response_buf = (uint8_t*)malloc(sizeof(uint32_t) + sizeof(uint32_t));
    if (response_buf == NULL) {
        free(response_buf); 
        return -1; 
    }

    memcpy(response_buf, &unlink_result_network, sizeof(uint32_t)); 
    memcpy(response_buf + sizeof(uint32_t), &errno_network, sizeof(int)); 

    if (send_all(sessfd, response_buf, sizeof(uint32_t) + sizeof(int)) < 0) {
        free(response_buf);
        return -1;
    } else {
        free(response_buf);
        return 0;
    }
}

static int handle_getdirentries_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    /**
     * This function interprets the payload of an getdirentries RPC from the client into local arguments, passes those 
     * local arguments to the standard library getdirentries() function, and then responds to the client with the 
     * outputs of the standard library call. 
     * 
     * Parameters: 
     *  - int sessfd: The file descriptor corresponding to the client who has passed the payload. 
     *  - const uint8_t* payload: The payload bytes containing the arguments for write() from the client. 
     *  - uint32_t payload_length: The size of the payload in bytes from the client. 
     * 
     * Returns 0 on success and -1 on failure. 
     * 
     * The payload from the client is understood to have the following contiguous order: 
	 * 1. [server_fd, 4 bytes]
     * 2. [nbytes, 8 bytes]
	 * 3. [base, 8 bytes]
     * 
     * The response back to the client is formatted in this contiguous order: 
     * 1. [getdirentries_result, 8 bytes]
     * 2. [getdirentries_errno, 4 bytes]
     * 3. [new_base, 8 bytes]
     * 4. [getdirentries_buf, getdirentries_result bytes]
     */

    //[server_fd, 4][nbytes, 8][base, 8]

    if (payload_len != sizeof(int) + sizeof(size_t) + sizeof(off_t)) {
        fprintf(stderr, "Wrong getdirentries payload size: %u\n", payload_len);
        return -1;
    }

    uint32_t server_fd_network; 
    memcpy(&server_fd_network, payload, sizeof(int)); 
    int server_fd = (int)(ntohl(server_fd_network)); 

    uint64_t nbytes; 
    memcpy(&nbytes, payload + sizeof(int), sizeof(uint64_t)); 

    uint64_t base; 
    memcpy(&base, payload + sizeof(int) + sizeof(uint64_t), sizeof(off_t)); 

    char* getdirentries_buf; 
    if (nbytes > 0) {
        getdirentries_buf = (char*)malloc((size_t)nbytes); 
        if (getdirentries_buf == NULL) {
            return -1; 
        }
    } else {
        getdirentries_buf = NULL; 
    }

    off_t* basep = malloc(sizeof(off_t)); 
    if (basep == NULL) {
        free(getdirentries_buf);
        return -1; 
    }
    *basep = (off_t)base;

    ssize_t getdirentries_result = getdirentries(server_fd, getdirentries_buf, (size_t)nbytes, basep); 

    int getdirentries_errno; 
    size_t data_length; 
    if (getdirentries_result < 0) {
        getdirentries_errno = errno; 
        data_length = 0; 
    } else {
        getdirentries_errno = 0; 
        data_length = (size_t)getdirentries_result; 
    }

    uint32_t getdirentries_errno_network = htonl((uint32_t)getdirentries_errno); 

    /**
     * getdirentries response: 
     *  [getdirentries_result, 8][getdirentries_errno, 4][new_base, 8][getdirentries_buf, data_length]
     *  
    */ 
    uint8_t* response_buf = (uint8_t*)malloc(sizeof(ssize_t) + sizeof(int) + sizeof(off_t) + data_length);
    if (response_buf == NULL) {
        free(basep); 
        free(getdirentries_buf); 
        return -1; 
    }

    memcpy(response_buf, &getdirentries_result, 8);
    memcpy(response_buf + 8, &getdirentries_errno_network, 4); 
    memcpy(response_buf + 12, basep, 8); 
    if (data_length > 0) {
        memcpy(response_buf + 20, getdirentries_buf, data_length); 
    }

    int rc = send_all(sessfd, response_buf, 8 + 4 + 8 + data_length); 

    free(response_buf);
    free(basep); 
    free(getdirentries_buf); 

    if (rc < 0) {
        return -1; 
    } else {
        return 0; 
    }
}

static void measure_dirtree_size(struct dirtreenode* node, size_t* node_count, size_t* total_nodal_bytes) {
    /**
     * Counts the total number of nodes and bytes that make up a dirtree starting from a given root node. 
     * 
     * Parameters: 
     *  - struct dirtree* node: The start/root node of the directory tree that we are counting the size of. 
     *  - size_t* node_count: A pointer to the number of nodes that this function will update. 
     *  - size_t* total_nodal_bytes: A pointer to the size in bytes across all the nodes in the tree that this 
     *                               function will update. 
     * 
     * This function should update the values within node_count and total_nodal_bytes. 
     * 
     * These sizes will be included to the response to the client for its getdirentries RPC. 
     */

    if (node == NULL) {
        return; 
    }

    *node_count += 1; 
    
    size_t node_name_len = strlen(node->name) + 1; 

    // A node is [num_subdirs, 4][name_len, 4][name, name_len]
    *total_nodal_bytes += 4 + 4 + node_name_len; 


    for (int i = 0; i < node->num_subdirs; i++) {
        measure_dirtree_size(node->subdirs[i], node_count, total_nodal_bytes); 
    }
}

static int marshal_nodes(struct dirtreenode* node, uint8_t* nodal_message, size_t* offset_p) {
    /**
     * Encodes the nodes of a tree for gitdirentries into a linear data structure in a buffer. Takes the node to 
     * write, the nodal_message buffer to write into, and the current offset within that bufffer. 
     * 
     * Parameters: 
     *  - struct dirtreenode* node: The start/root node of the tree we want to encode into bytes. 
     *  - uint8_t* nodal_message: The buffer of bytes that nodes will be serialized into. 
     *  - size_t* oppset_p: Pointer to the location of nodal_message that the next node will be serialized into. 
     * 
     * For any node in the tree, writes down its number of children, the length of its name string, and then its name 
     * string. 
     * 
     * The root node is the first to be encoded. After that, we write the children of a node depth-first from left to 
     * right through its indices. This defined order will be exploited by the mylib.c functions that have to take 
     * that message and turn it back into a tree. 
     */

    // Returns 0 for done, -1 for errors. 
    if (node == NULL) {
        return 0; 
    }

    uint32_t node_name_length = (uint32_t)strlen(node->name) + 1; //Include '\0'. 

    //Nodes in the form of [num_children, 4][name_len, 8][name, name_len] 
    int num_subdirs = node->num_subdirs; 
    memcpy(nodal_message + *offset_p, &num_subdirs, 4); 
    *offset_p += 4; 

    memcpy(nodal_message + *offset_p, &node_name_length, 4); 
    *offset_p += 4; 

    memcpy(nodal_message + *offset_p, node->name, node_name_length); 
    *offset_p += node_name_length; 

    for (int i = 0; i < node->num_subdirs; i++) {
        marshal_nodes(node->subdirs[i], nodal_message, offset_p); 
    }

    return 0; 

}

static uint8_t* convert_dirtree_to_message(struct dirtreenode* dirtreeroot, 
                                           uint32_t* bytes_to_send, 
                                           int getdirtree_errno) {
    /**
     * Converts a dirtree into a linear message that can be sent to the client. 
     * 
     * Parameters: 
     *  - struct getdirtrenode* dirtreeroot: The root of the directory tree we want to serialize. 
     *  - uint32_t* bytes_to_send: A pointer that will be updated with the number of bytes that need to be sent 
     *                             in a message to the client. 
     *  - int getdirtree_errno: The errno that should be encoded into a message to the client. 
     */

    // Serialize a tree structure. 

    // [node_count, 8][node_bytes, 8][getdirtree_errno, 4], then repeat [num_subdirs, 4][name_len, 4][name, name_len]
    if (bytes_to_send == NULL) {
        return NULL; 
    }
    *bytes_to_send = 0; 

    size_t total_nodes = 0; 
    size_t nodal_bytes = 0; 

    if (dirtreeroot != NULL) {
        measure_dirtree_size(dirtreeroot, &total_nodes, &nodal_bytes); 
    }


    size_t total_message_bytes = 8 + 8 + 4 + nodal_bytes; 
    if (total_message_bytes > UINT32_MAX) {
        return NULL; 
    }

    uint8_t* message = (uint8_t*)malloc((size_t)total_message_bytes); 
    if (message == NULL) {
        return NULL; 
    }

    size_t message_offset = 0; 

    memcpy(message + message_offset, &total_nodes, 8);
    message_offset += 8; 

    memcpy(message + message_offset, &nodal_bytes, 8); 
    message_offset += 8; 

    memcpy(message + message_offset, &getdirtree_errno, 4); 
    message_offset += 4; 

    if (dirtreeroot != NULL) {
        size_t node_offset = 0; 
        marshal_nodes(dirtreeroot, message + message_offset, &node_offset); 
        message_offset += node_offset; 
    }

    assert(message_offset == total_message_bytes); 

    *bytes_to_send = (uint32_t)total_message_bytes; 

    return message; 
}

static int handle_getdirtree_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    /**
     * This function interprets the payload of an getdirtree RPC from the client into local arguments, passes those 
     * local arguments to the standard library getdirtree() function, and then responds to the client with the 
     * outputs of the standard library call. 
     * 
     * Parameters: 
     *  - int sessfd: The file descriptor corresponding to the client who has passed the payload. 
     *  - const uint8_t* payload: The payload bytes containing the arguments for write() from the client. 
     *  - uint32_t payload_length: The size of the payload in bytes from the client. 
     * 
     * Returns 0 on success and -1 on failure. 
     * 
     * The payload from the client is understood to have the following contiguous order: 
	 * 1. [path_length, 4 bytes]
     * 2. [path, path_length bytes]
     * 
     * The response back to the client is formatted in this contiguous order: 
	 * 1. [getdirentries_result, 8 bytes]
	 * 2. [getdirentries_errno, 4 bytes]
	 * 3. [new_base, 8 bytes]
	 * 4. [getdirentries_buf, getdirentries_result bytes]
     */

    //[path_length, 4][path, path_length]
    if (payload_len < 4) {
        fprintf(stderr, "Wrong getdirtree payload size: %u\n", payload_len);
        return -1;
    }

    uint32_t path_length_network; 
    memcpy(&path_length_network, payload, 4); 
    int path_length = (int)(ntohl(path_length_network)); 

    char* path = (char*)malloc(path_length); 
    if (path == NULL) {
        return -1; 
    }
    memcpy(path, payload + 4, path_length); 

    struct dirtreenode* getdirtree_result = getdirtree(path);  
    int getdirtree_errno; 
    if (getdirtree_result == NULL) {
        getdirtree_errno = errno; 
    } else {
        getdirtree_errno = 0; 
    }

    free(path); 


    // [node_count, 8][node_bytes, 8][getdirtree_errno, 4], then repeat [num_subdirs, 4][name_len, 4][name, name_len]
    uint32_t message_size = 0; 
    uint8_t* response_buf = convert_dirtree_to_message(getdirtree_result, &message_size, getdirtree_errno); 

    // No reason to keep it around on the server; it's the client's problem now. 
    if (getdirtree_result != NULL) {
        freedirtree(getdirtree_result);
    }

    if (send_all(sessfd, response_buf, message_size) < 0) {
        free(response_buf);  
        return -1; 
    } else {
        free(response_buf); 
        return 0; 
    }

}

static int handle_one_message(int sessfd) {
    /**
     * This function takes in an entire RPC message from the client by listening out on a connected socket. This 
     * RPC message will include both a fixed header and the payload. 
     * 
     * Parameters: 
     *  - int sessfd: The file descriptor desciribng the socket that a client is listening for a response on. 
     * 
     * Return 1 on success, 0 on the client closing the connection, and -1 on error. 
     * 
     * The fixed header is always formatted contiguously as such: 
     * 1. [opcode, 4 bytes]
     * 2. [payload_length, 4 bytes]
     * 
     * The fixed header is always 8 bytes and contains the opcode corresponding with the function the client is 
     * requesting to call as well as the length in bytes of the following payload. So, this function continually 
     * tries to read 8 byte headers off the socket connection and when it does, then interprets that header to get the 
     * payload size. It then uses the now known payload size to capture the payload from the socket connection, and 
     * cases on the opcode in order to call the correct helper function. 
     * 
     */


    uint32_t op_network, length_network; 

    int rc = recv_all(sessfd, &op_network, 4);
    if (rc <= 0) {
        return rc;
    }
    rc = recv_all(sessfd, &length_network, 4);
    if (rc <= 0) {
        return rc; 
    }

    uint32_t op_number = ntohl(op_network);
    uint32_t payload_len = ntohl(length_network); 

    uint8_t* payload = malloc(payload_len); 
    if (payload == NULL) {
        return -1;
    }

    rc = recv_all(sessfd, payload, payload_len); 
    if (rc <= 0) {
        free(payload); 
        return rc;
    }

    int ret = 0; 
    switch (op_number) {
        case OP_OPEN: 
            ret = handle_open_payload(sessfd, payload, payload_len); 
            break; 
        case OP_WRITE: 
            ret = handle_write_payload(sessfd, payload, payload_len); 
            break; 
        case OP_CLOSE:
            ret = handle_close_payload(sessfd, payload, payload_len); 
            break;
        case OP_LSEEK: 
            ret = handle_lseek_payload(sessfd, payload, payload_len); 
            break; 
        case OP_READ: 
            ret = handle_read_payload(sessfd, payload, payload_len); 
            break; 
        case OP_STAT: 
            ret = handle_stat_payload(sessfd, payload, payload_len); 
            break; 
        case OP_UNLINK: 
            ret = handle_unlink_payload(sessfd, payload, payload_len); 
            break;
        case OP_GETDIRTREE: 
            ret = handle_getdirtree_payload(sessfd, payload, payload_len); 
            break; 
        case OP_GETDIRENTRIES: 
            ret = handle_getdirentries_payload(sessfd, payload, payload_len); 
            break;
        default: 
            fprintf(stderr, "Unknown opcode %u in server.c \n", op_number); 
            ret = -1; 
            break; 
    }

    free(payload);
    if (ret == 0) {
        return 1; 
    } else {
        return -1; 
    }
}


int main(int argc, char** argv) {
    /**
     * This main function implements the main loop of the server. We listen on a port to accept connections from 
     * clients into a socket, and when that occurs we fork off a child process so that we can handle that client in 
     * parallel with other clients. The child process simply runs handle_one_message. 
     * 
     * Parameters: 
     *  - int argc: The number of command line arguments to this file's compiled executable. 
     *  - char** argv: Array of string command line inputs into this file's compiled executable. 
     * 
     * Returns 0 on success. 
     * 
     * Exits with a nonzero status code on failure. 
     * 
     * We also install the handler for the children for when they finish executing. 
     */

    signal(SIGCHLD, sigchld_handler);

    (void)argc;
    (void)argv;

    char *serverport; 
    unsigned short port; 
    int sockfd, sessfd, rv;
    struct sockaddr_in srv, cli; 
    socklen_t sa_size; 

    // Get the server port that we will listen on from the environment 
    // variable. In the case of failure set it to a default. 
    serverport = getenv("serverport15440");
    if (serverport != NULL) {
        port = (unsigned short)(atoi(serverport));
    } else {
        port = 15440; 
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0); // TCP/IP
    if (sockfd < 0) {
        err(1, 0); // Prints an error based on errorno and exits the program. 
    }

    // setup address structure to indicate server port
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = htonl(INADDR_ANY);	// don't care IP address
	srv.sin_port = htons(port);			// server port

	// bind to our port
	rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);
	
	// start listening for connections
	rv = listen(sockfd, 5);
    if (rv < 0) {
        err(1, 0);
    }

    while (true) {

        // Wait for next client, get session socket. 
        sa_size = sizeof(struct sockaddr_in); 
        sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
        if (sessfd < 0) {
            err(1, 0); 
        }

        pid_t pid = fork(); 

        if (pid == 0) {
            close(sockfd); 
            while (true) {
                int rc = handle_one_message(sessfd); 
                if (rc == 1) {
                    // rc == 1 means got a message. 
                    continue; 
                } else if (rc == 0) {
                    // rc == 0 intends to mean client breaks connection. 
                    break; 
                } else {
                    // rc < 0 means an error. 
                    err(1, 0); 
                }
            }
            close(sessfd); 
            exit(0); 
        } else {
            close(sessfd); 
        }

    }

    close(sockfd);
    return 0;



}