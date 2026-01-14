#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#define MAXMSGLEN 100 

// Recall: argc is number or arguments, argv is the array of char* strings. 
int main(int argc, char** argv) {
    char buf[MAXMSGLEN+1];
    char *serverport; 
    unsigned short port; 
    int sockfd, sessfd, rv;
    struct sockaddr_in srv, cli; 
    socklen_t sa_size; 

    // Get the server port that we will listen on from the environment 
    // variable. In the case of failure set it to a default. 
    serverport = getenv("serverport15440")
    if (serverport != NULL) {
        port = (unsigned short)(atoi(serverport));
    } else {
        port = 15440; 
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0); // TCP/IP

}