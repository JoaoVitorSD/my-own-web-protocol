#include "common.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

void usage(int argc, char **argv)
{
    printf("usage: %s <peer-2-peer port> <connection port>\n", argv[0]);
    printf("example: %s 40000 50000\n", argv[0]);
    exit(EXIT_FAILURE);
}

int listen_and_return_socket(char *port, struct sockaddr_storage *storage)
{
    if (0 != server_sockaddr_init(port, storage))
    {
        usage(3, &port);
    }
    int s = socket(storage->ss_family, SOCK_STREAM, 0);
    if (s == -1)
    {
        logexit("socket");
    }

    int enable = 1;
    if (0 != setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) + setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)))
    {
        logexit("setsockopt");
    }

    struct sockaddr *addr = (struct sockaddr *)(storage);
    if (0 != bind(s, addr, sizeof(*storage)))
    {
        logexit("bind");
    }
    if (0 != listen(s, 10))
    {
        logexit("listen");
    }

    char addrstr[BUFSZ];
    addrtostr(addr, addrstr, BUFSZ);
    printf("bound to %s, waiting client connections\n", addrstr);
    return s;
}

int accept_conncetion(int socket, char *caddrstr, char * buffer)
{
    struct sockaddr_storage cstorage;
    struct sockaddr *caddr = (struct sockaddr *)(&cstorage);
    socklen_t caddrlen = sizeof(cstorage);

    int csock = accept(socket, caddr, &caddrlen);
    if (csock == -1)
    {
        logexit("accept");
        return -1;
    }
    addrtostr(caddr, caddrstr, BUFSZ);
    printf("[log] connection from %s\n", caddrstr);
    char buf[BUFSZ];

    memset(buf, 0, BUFSZ);
    size_t count = recv(csock, buf, BUFSZ - 1, 0);
    printf("[msg] %s, %d bytes: %s\n", caddrstr, (int)count, buf);
    strcpy(buffer, buf);
    return csock;
  
}

void handle_peer_req(int socket, char *buffer)
{
    if (socket == -1)
    {
        printf("Error accepting connection\n");
        return;
    }
    send_req(socket, buffer);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argc, argv);
    }
    struct sockaddr_storage peer_storage;
    struct sockaddr_storage client_storage;
    int peer_socket = listen_and_return_socket(argv[1], &peer_storage);
    int client_socket = listen_and_return_socket(argv[2], &client_storage);

    // send_req(peer_socket, REQ_CONNPEER);
    while (1) {
        char peer_addrstr[BUFSZ];
        char peer_buffer[BUFSZ];
        int peerSock = accept_conncetion(peer_socket, peer_addrstr,peer_buffer);
        handle_peer_req(peerSock, peer_buffer);
        char client_addrstr[BUFSZ];
        char client_request[BUFSZ];
        accept_conncetion(client_socket, client_addrstr,client_request);
    }

    exit(EXIT_SUCCESS);
}

