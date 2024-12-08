#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
#include <sys/socket.h>
#include <sys/types.h>

void usage(int argc, char **argv)
{
    printf("usage: %s <peer-2-peer port> <connection port>\n", argv[0]);
    printf("example: %s 40000 50000\n", argv[0]);
    exit(EXIT_FAILURE);
}

void listen_to_socket(int socket, struct sockaddr_storage *storage)
{
    int enable = 1;
    if (0 != setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)))
    {
        logexit("setsockopt");
    }
    int enable_ipv4 = 0;
    if (0 != setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, &enable_ipv4, sizeof(int)))
    {
        logexit("setsockopt");
    }
    struct sockaddr *addr = (struct sockaddr *)(storage);
    if (0 != bind(socket, addr, sizeof(*storage)))
    {
        logexit("bind");
    }
    if (0 != listen(socket, 10))
    {
        logexit("listen");
    }

    char addrstr[BUFSZ];
    addrtostr(addr, addrstr, BUFSZ);
    printf("bound to %s, waiting client connections\n", addrstr);
}

int init_server(char *port, struct sockaddr_storage *storage)
{
    printf("Initializing server on port %s\n", port);
    int port_n = atoi(port);
    if (0 != server_sockaddr_init(port_n, storage))
    {
        usage(3, &port);
    }
    int s = socket(storage->ss_family, SOCK_STREAM, 0);
    if (s == -1)
    {
        logexit("socket");
    }

    listen_to_socket(s, storage);
    return s;
}

int accept_conncetion(int socket, char *caddrstr, char *buffer)
{
    struct sockaddr_storage cstorage;
    struct sockaddr *caddr = (struct sockaddr *)(&cstorage);
    socklen_t caddrlen = sizeof(cstorage);
    memset(buffer, 0, BUFSZ);
    int csock = accept(socket, caddr, &caddrlen);
    if (csock == -1)
    {
        logexit("accept");
        return -1;
    }
    addrtostr(caddr, caddrstr, BUFSZ);
    printf("[log] connection from %s\n", caddrstr);
    size_t count = recv(csock, buffer, BUFSZ - 1, 0);
    printf("[msg] %s, %d bytes: %s\n", caddrstr, (int)count, buffer);
    return csock;
}

void init_peer_connection(char *peerPort, server_t *server)
{
    struct sockaddr_storage storage;
    if (0 != addrparse("127.0.0.1", peerPort, &storage))
    {
        usage(3, &peerPort);
    }
    server->peer_storage = storage;
    int s = socket(storage.ss_family, SOCK_STREAM, 0);
    if (s == -1)
    {
        logexit("socket");
    }
    struct sockaddr *addr = (struct sockaddr *)(&storage);
    if (0 != connect(s, addr, sizeof(storage)))
    {
        printf("No peer found, starting to listen...\n");
        server->initial_peer = 1;
        server->peer_id = init_server(peerPort, &storage);
        return;
    }

    struct response_t response = request(s, REQ_CONNPEER, "");
    if (response.action == ERROR)
    {
        printf("Error connecting to peer\n");
        handle_error(response.payload);
        return;
    }
    server->peer_id = init_server(response.payload, &storage);
    server->peer_pair_id = s;
    server->initial_peer = 0;
    printf("Peer %s connected\n", response.payload);

}

void handle_peer_req(server_t *server, int client_sock, char *clientInfo)
{
    if (client_sock == -1)
    {
        printf("Error accepting connection\n");
        return;
    }
    int action;
    char payload[BUFSZ];
    sscanf(clientInfo, "%d %s", &action, payload);

    if (action == REQ_CONNPEER)
    {
        // Request new socket to peer
        if (server->peer_pair_id != -1)
        {
            return_response(client_sock, ERROR, "01");
            return;
        }
        // TODO asign socket instead of port
        int peer_port = gen_peer_port();
        server->peer_pair_id = peer_port;
        printf("Peer connected\n");
        return_response(client_sock, RES_CONNPEER, itoa(peer_port));
        return;
    }
    if (action == REQ_DISCPEER)
    {
        // Disconnect peer
        printf("Disconnecting peer\n");
        int peer_to_disconnect = atoi(payload);
        if (server->peer_pair_id != peer_to_disconnect)
        {
            return_response(client_sock, ERROR, ERROR_PEER_NOT_FOUND);
            return;
        }
        int peer_sock = server->peer_pair_id;
        server->peer_pair_id = -1;
        return_response(client_sock, OK, SUCCESSFUL_DISCONNECTED);
        printf("Peer %d disconnected\n", peer_sock);
        return;
    }
    return_response(client_sock, ERROR, clientInfo);
}

user * NewUserFromPayload(char * payload){
    user *newUser;
    newUser = malloc(sizeof(user));
    sscanf(payload, "%s %d", newUser->id, &newUser->root);
    return newUser;
}

void handle_client_req(server_t *server, int client_sock, char *clientInfo)
{
    if (client_sock == -1)
    {
        printf("Error accepting connection\n");
        return;
    }
    int action;
    char *payload;
    sscanf(clientInfo, "%d %s", &action, payload);
    if (action == REQ_USRADD)
    {
        user *newUser = NewUserFromPayload(payload);
        server->users[server->user_count] = newUser;
        server->user_count++;
        printf("Adding new user %s\n", newUser->id);
        return_response(client_sock, OK, SUCCESSFUL_CREATE);
        return;
    }
    if (action == PRINTUSERS)
    {
        for (int i = 0; i < server->user_count; i++)
        {
            printf("User %s root: %d\n", server->users[i]->id, server->users[i]->root);
        }
    }
    return_response(client_sock, ERROR, clientInfo);
}

server_t * NewServer(){
    server_t *server;
    server = malloc(sizeof(server_t));
    server->peer_id = -1;
    server->peer_pair_id = -1;
    server->initial_peer = 1;
    server->users = malloc(sizeof(user) * 10);
    server->user_locations = malloc(sizeof(user_location) * 10);
    server->user_count = 0;
    return server;
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        usage(argc, argv);
    }

  
    server_t *server = NewServer();
    init_peer_connection(argv[1], server);

    struct sockaddr_storage client_storage;
    int client_socket = init_server(argv[2], &client_storage);

    fd_set master_set, read_fds;
    int fdmax = (server->peer_id > client_socket) ? server->peer_id : client_socket;

    FD_ZERO(&master_set);
    FD_SET(server->peer_id, &master_set);
    FD_SET(client_socket, &master_set);

    while (1)
    {
        read_fds = master_set;

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1)
        {
            logexit("select");
        }

        if (FD_ISSET(server->peer_id, &read_fds))
        {
            // Handle peer connection
            char peer_addrstr[BUFSZ];
            char peer_buffer[BUFSZ];
            int peerSock = accept_conncetion(server->peer_id, peer_addrstr, peer_buffer);
            handle_peer_req(server, peerSock, peer_buffer);
        }

        if (FD_ISSET(client_socket, &read_fds))
        {
            // Handle client connection
            char client_addrstr[BUFSZ];
            char client_request[BUFSZ];
            int clientSock = accept_conncetion(client_socket, client_addrstr, client_request);
            handle_client_req(server, clientSock, client_request);
        }
    }

    free(server);
    exit(EXIT_SUCCESS);
}
