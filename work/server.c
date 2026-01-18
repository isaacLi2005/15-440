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


#define MAXMSGLEN 100 

enum {
	OP_OPEN = 1, 
	OP_WRITE = 2, 
	OP_CLOSE = 3, 
	OP_LSEEK = 4, 
	OP_READ = 5
};

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

static int handle_open_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    // Takes the payload of an open call, calls open, and sends a respose back. 
    //[flags, 4][mode, 4][path_len, 4][pathname, path_len]
    if (payload_len < 12) {
        fprintf(stderr, "Open payload too short in server.c: %u\n", payload_len);
        return -1;
    }

    uint32_t flags_network, mode_network, pathlen_network; 
    memcpy(&flags_network, payload + 0, 4); 
    memcpy(&mode_network, payload + 4, 4);
    memcpy(&pathlen_network, payload + 8, 4); 
    
    uint32_t flags = ntohl(flags_network);
    uint32_t mode = ntohl(mode_network);
    uint32_t pathlen = ntohl(pathlen_network);

    if ((uint32_t)12 + pathlen != payload_len) {
        fprintf(stderr, "OPEN payload mismatch: payload_len is %u, pathlen is %u \n", payload_len, pathlen);
        return -1;
    }

    const char* pathname = (const char*)(payload+12);
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

    uint32_t fd_network = htonl((uint32_t)ret_fd);
    uint32_t errno_network = htonl((uint32_t)ret_errno);

    // Open response: [fd, 4][errno, 4]
    uint8_t* response_buf = (uint8_t*)malloc(8);
    memcpy(response_buf, &fd_network, 4);
    memcpy(response_buf + 4, &errno_network, 4); 

    if (send_all(sessfd, response_buf, 8) < 0) {
        free(response_buf);
        return -1;
    } else {
        free(response_buf);
        return 0;
    }
}

static int handle_write_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    // [server_fd, 4][n_bytes, 8][write_buf, n_bytes]
    if (payload_len < 12) {
        fprintf(stderr, "Write payload too short: %u \n", payload_len); 
        return -1; 
    }

    uint32_t server_fd_network; 
    uint64_t n_bytes; 
    memcpy(&server_fd_network, payload, 4); 
    memcpy(&n_bytes, payload + 4, 8);

    int32_t server_fd = (int32_t)ntohl(server_fd_network); 

    if ((uint64_t)12 + n_bytes != (uint64_t)payload_len) {
        fprintf(stderr, "WRITE payload mismatch: payload_len=%u n_bytes=%llu\n", payload_len, n_bytes);
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
    memcpy(write_bytes, payload + 12, n_bytes); 
    ssize_t write_result = write(server_fd, write_bytes, n_bytes); 
    free(write_bytes); 

    int32_t ret_errno = 0; 
    if (write_result < 0) {
        ret_errno = (int32_t)errno; 
    } else {
        ret_errno = 0;
    }

    uint32_t errno_network = htonl((uint32_t)ret_errno);

    // Write response: [result, 8][errno, 4]
    uint8_t* response_buf = (uint8_t*)malloc(12);
    if (response_buf == NULL) {
        return -1; 
    }
    int64_t write_result_for_sending = (int64_t)write_result;
    memcpy(response_buf, &write_result_for_sending, 8);
    memcpy(response_buf + 8, &errno_network, 4); 

    if (send_all(sessfd, response_buf, 12) < 0) {
        free(response_buf);
        return -1;
    } else {
        free(response_buf);
        return 0;
    }
}

static int handle_close_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    // Takes the payload of an close call, calls close, and sends a respose back. 
    //[fd, 4]
    if (payload_len != 4) {
        fprintf(stderr, "Wrong close payload size: %u\n", payload_len);
        return -1;
    }

    uint32_t fd_network; 
    memcpy(&fd_network, payload, 4); 

    int32_t server_fd = (int32_t)(ntohl(fd_network)); 

    int close_return = close((int)server_fd); 
    int32_t close_errno;
    if (close_return < 0) {
        close_errno = (int32_t)errno; 
    } else {
        close_errno = 0; 
    }

    uint32_t close_return_network = htonl((uint32_t)close_return);
    uint32_t errno_network = htonl((uint32_t)close_errno);

    // Open response: [fd, 4][errno, 4]
    uint8_t* response_buf = (uint8_t*)malloc(8);
    memcpy(response_buf, &close_return_network, 4);
    memcpy(response_buf + 4, &errno_network, 4); 

    if (send_all(sessfd, response_buf, 8) < 0) {
        free(response_buf);
        return -1;
    } else {
        free(response_buf);
        return 0;
    }
}

static int handle_lseek_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    if (payload_len != 16) {
        fprintf(stderr, "Wrong lseek payload size: %u\n", payload_len);
        return -1;
    }

    uint32_t fd_network; 
    memcpy(&fd_network, payload, 4); 
    int server_fd = (int)(ntohl(fd_network)); 

    //TODO: 64 bits couldn't be handled by htonl. 
    int64_t off_beamed; 
    memcpy(&off_beamed, payload + 4, 8); 
    off_t offset = (off_t)(off_beamed); 

    uint32_t whence_network; 
    memcpy(&whence_network, payload + 12, 4); 
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
    uint8_t* response_buf = (uint8_t*)malloc(12);
    int64_t result_beamed = (int64_t)lseek_result; 
    memcpy(response_buf, &result_beamed, 8);
    memcpy(response_buf + 8, &errno_network, 4); 

    if (send_all(sessfd, response_buf, 12) < 0) {
        free(response_buf);
        return -1;
    } else {
        free(response_buf);
        return 0;
    }
}

// TODO: What if a client asks for a 0 read? 
static int handle_read_payload(int sessfd, const uint8_t* payload, uint32_t payload_len) {
    // [server_fd, 4][count, 8]
    if (payload_len != 12) {
        fprintf(stderr, "Wrong lseek payload size: %u\n", payload_len);
        return -1;
    }

    uint32_t fd_network; 
    memcpy(&fd_network, payload, 4); 
    int server_fd = (int)(ntohl(fd_network)); 

    uint64_t count_received; 
    memcpy(&count_received, payload + 4, 8); 
    size_t count = (size_t)(count_received); 

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
    uint8_t* response_buf = (uint8_t*)malloc(8 + 4 + data_length);
    if (response_buf == NULL) {
        free(response_buf);
        return -1; 
    }

    memcpy(response_buf, &result_beamed, 8);
    memcpy(response_buf + 8, &errno_network, 4); 
    if (data_length > 0) {
        memcpy(response_buf + 12, read_buf, data_length); 
    }
    

    if (send_all(sessfd, response_buf, 8 + 4 + data_length) < 0) {
        free(response_buf);
        free(read_buf);
        return -1;
    } else {
        free(response_buf);
        free(read_buf); 
        return 0;
    }
}

static int handle_one_message(int sessfd) {
    // [opcode, 4][payload_len, 4]
    // Return 1 on success, 0 on client closing connection, -1 on error. 

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


// Recall: argc is number or arguments, argv is the array of char* strings. 
int main(int argc, char** argv) {
    fflush(stderr);

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

    // Main server loop, set up to go indefinitely one at a time. 
    while (true) {

        // Wait for next client, get session socket. 
        sa_size = sizeof(struct sockaddr_in); 
        sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
        if (sessfd < 0) {
            err(1, 0); 
        }

        // Get messages and echo them until done. 

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

    }

    close(sockfd);
    return 0;



}