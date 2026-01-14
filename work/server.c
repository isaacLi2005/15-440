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

#define MAXMSGLEN 100 

// Recall: argc is number or arguments, argv is the array of char* strings. 
int main(int argc, char** argv) {
    (void)argc;
    (void)argv;


    char buf[MAXMSGLEN+1];
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

        // Loops while we still are able to read bytes into buf. 
        while ( (rv = recv(sessfd, buf, MAXMSGLEN, 0)) > 0) {
            write(STDOUT_FILENO, buf, rv);
        }
        if (rv < 0) {
            err(1, 0);
        } 
        close(sessfd);

    }

    close(sockfd);



    return 0;



}