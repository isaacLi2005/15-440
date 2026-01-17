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

#define MAXMSGLEN 100 

enum {OP_OPEN = 1};

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

static int handle_open_payload(const uint8_t* payload, uint32_t payload_len) {
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


    printf("OPEN received:\n");
    printf("flags = 0x%x\n", flags);
    printf("mode = 0%o\n", mode);
    printf("path = \"%s\"\n", pathname);
    fflush(stdout);

    return 0;
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
            ret = handle_open_payload(payload, payload_len); 
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
    fprintf(stderr, "SERVER VERSION 9:30\n");
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