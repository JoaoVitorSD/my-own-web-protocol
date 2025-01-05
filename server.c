#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
#include <sys/socket.h>
#include <sys/types.h>
#include "time.h"
#include <pthread.h>

typedef struct
{
    server_t *server;
    int client_sock;
    char request[BUFSZ];
} thread_data_t;
void *handle_client_connection(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    handle_client_req(data->server, data->client_sock, data->request);
    close(data->client_sock);
    free(data);
    pthread_exit(NULL);
}
thread_data_t *accept_connection_data(int socket, char *caddrstr)
{
    thread_data_t *data = malloc(sizeof(thread_data_t));
    struct sockaddr_storage cstorage;
    struct sockaddr *caddr = (struct sockaddr *)(&cstorage);
    socklen_t caddrlen = sizeof(cstorage);

    memset(data->request, 0, BUFSZ);
    data->client_sock = accept(socket, caddr, &caddrlen);
    if (data->client_sock == -1)
    {
        logexit("accept");
        free(data);
        return NULL;
    }

    addrtostr(caddr, caddrstr, BUFSZ);
    recv(data->client_sock, data->request, BUFSZ - 1, 0);
    return data;
}

void usage(int argc, char **argv)
{
    printf("usage: %s <peer-2-peer port> <connection port>\n", argv[0]);
    printf("example: %s 40000 50000\n", argv[0]);
    exit(EXIT_FAILURE);
}

struct response_t peer_request(int peer_sock, int action, char *payload)
{
    char buffer[BUFSZ];
    sprintf(buffer, "%d %s", action, payload);
    size_t count = send(peer_sock, buffer, strlen(buffer) + 1, 0);
    if (count != strlen(buffer) + 1)
    {
        logexit("send");
    }

    memset(buffer, 0, BUFSZ);
    unsigned total = 0;
    recv(peer_sock, buffer + total, BUFSZ - total, 0);
    return parse_response(buffer);
}

void peer_response(int peer_sock, int action, char *payload)
{
    char buffer[BUFSZ];
    memset(buffer, 0, BUFSZ);
    sprintf(buffer, "%d %s", action, payload);
    size_t count = send(peer_sock, buffer, strlen(buffer) + 1, 0);
    if (count != strlen(buffer) + 1)
    {
        logexit("send");
    }
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
}

int init_server(char *port, struct sockaddr_storage *storage)
{
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
    printf("Accepting connection\n");
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
    size_t count = recv(csock, buffer, BUFSZ - 1, 0);
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
        server->peer_mode = PEER_MODE_USER_STORAGE;
        server->server_sock = init_server(peerPort, &storage);
        return;
    }
    struct response_t response = peer_request(s, REQ_CONNPEER, "");
    if (response.action == ERROR)
    {
        printf("Error connecting to peer\n");
        handle_error(response.payload);
        return;
    }
    // Peer connected, using socket to communicate
    server->peer_sock = s;
    sscanf(response.payload, "%d", &server->peer_id);
    printf("New Peer ID: %d\n", server->peer_id);
    server->peer_id = gen_peer_id();
    printf("Peer %d connected\n", server->peer_id);
    peer_response(s, RES_CONNPEER, itoa(server->peer_id));
    server->peer_mode = PEER_MODE_USER_LOCATIONS;
}

void handle_peer_req(server_t *server, int peer_sock, char *clientInfo)
{
    int action;
    char payload[BUFSZ];
    sscanf(clientInfo, "%d %s", &action, payload);

    if (action == REQ_CONNPEER)
    {
        // Request new socket to peer
        if (server->peer_id != -1)
        {
            return_response(peer_sock, ERROR, "01");
            return;
        }
        // TODO asign socket instead of port
        int peer_id = gen_peer_id();
        server->peer_id = peer_id;
        printf("Peer %d connected\n", peer_id);
        struct response_t response =  peer_request(peer_sock, RES_CONNPEER, itoa(peer_id));
        return;
    }
    if (action == REQ_DISCPEER)
    {
        // Disconnect peer
        printf("Disconnecting peer\n");
        int peer_to_disconnect = atoi(payload);
        if (server->peer_id != peer_to_disconnect)
        {
            return_response(peer_sock, ERROR, ERROR_PEER_NOT_FOUND);
            return;
        }
        int peer_sock = server->peer_id;
        server->peer_id = -1;
        return_response(peer_sock, OK, SUCCESSFUL_DISCONNECTED);
        printf("Peer %d disconnected\n", peer_sock);
        return;
    }

    return_response(peer_sock, ERROR, clientInfo);
}

user *NewUserFromPayload(char *payload)
{
    user *newUser;
    newUser = malloc(sizeof(user));
    sscanf(payload, "%s %d", newUser->id, &newUser->root);
    return newUser;
}
typedef struct
{
    server_t *server;
    int client_sock;
    int client_id;
} client_thread_data_t;

void *handle_client_thread(void *arg)
{
    client_thread_data_t *data = (client_thread_data_t *)arg;
    char buffer[BUFSZ];

    printf("Started listening thread for client %d\n", data->client_id);

    while (1)
    {
        memset(buffer, 0, BUFSZ);
        ssize_t received = recv(data->client_sock, buffer, BUFSZ - 1, 0);

        if (received <= 0)
        {
            printf("Client %d disconnected\n", data->client_id);
            close(data->client_sock);
            free(data);
            pthread_exit(NULL);
        }

        printf("Received from client %d: %s\n", data->client_id, buffer);
        handle_client_req(data->server, data->client_sock, buffer);
    }

    return NULL;
}

void handle_client_storage_req(server_t *server, int client_sock, int action, char *payload)
{
    printf("Handling client request %d\n", action);
  
        if (action == REQ_USRADD)
        {
            printf("REQ_USRADD %s\n", payload);
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

    return_response(client_sock, ERROR, "Invalid action");
}

void handle_client_location_req(server_t *server, int client_sock, int action, char *payload)
{
   
    // if (action == REQ_USRLOC)
    // {
    //     user *newUser = NewUserFromPayload(payload);
    //     server->users[server->user_count] = newUser;
    //     server->user_count++;
    //     printf("Adding new user %s\n", newUser->id);
    //     return_response(client_sock, OK, SUCCESSFUL_CREATE);
    //     return;
    // }
    // if (action == PRINTUSERS)
    // {
    //     for (int i = 0; i < server->user_count; i++)
    //     {
    //         printf("User %s root: %d\n", server->users[i]->id, server->users[i]->root);
    //     }
    // }

    return_response(client_sock, ERROR, ERROR_USER_NOT_FOUND);
}

void handle_client_req(server_t *server, int client_sock, char *request)
{
    printf("Handling client request %s\n", request);
    int action;
    char payload[BUFSZ];
    sscanf(request, "%d %s", &action, payload);

    if (action == REQ_CONN)
    {
        if (server->client_connections_count >= MAX_CLIENT_CONNECTIONS)
        {
            return_response(client_sock, ERROR, ERROR_CLIENT_LIMIT_EXCEEDED);
            return;
        }

        int loc_id;
        sscanf(payload, "%d", &loc_id);
        int client_id = ++server->client_connections_count;
        server->client_connections[loc_id - 1] = client_id;
        printf("Client %d added(Loc %d)\n", client_id, loc_id);
        server->client_sockets[client_id] = client_sock;

        // Create thread data
        client_thread_data_t *thread_data = malloc(sizeof(client_thread_data_t));
        thread_data->server = server;
        thread_data->client_sock = client_sock;
        thread_data->client_id = client_id;

        // Create listening thread
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client_thread, thread_data) != 0)
        {
            fprintf(stderr, "Failed to create thread for client %d\n", client_id);
            free(thread_data);
            return_response(client_sock, ERROR, "Failed to create handler thread");
            return;
        }
        pthread_detach(thread);

        return_response(client_sock, RES_CONN, itoa(client_id));
        return;
    }
    switch (server->peer_mode)
    {
    case PEER_MODE_USER_STORAGE:
        handle_client_storage_req(server, client_sock, action, payload);
        break;
    case PEER_MODE_USER_LOCATIONS:
        handle_client_location_req(server, client_sock, action, payload);
        break;
    default:
        fprintf(stderr, "Invalid peer mode\n");
        break;
    }
}
server_t *NewServer()
{
    server_t *server;
    server = malloc(sizeof(server_t));
    server->peer_id = -1;
    server->peer_sock = -1;
    server->server_sock = -1;
    server->peer_mode = -1;
    server->user_count = 0;
    server->client_connections_count = 0;
    return server;
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        usage(argc, argv);
    }
    srand(time(0));
    server_t *server = NewServer();
    init_peer_connection(argv[1], server);

    struct sockaddr_storage client_storage;
    int client_socket = init_server(argv[2], &client_storage);

    fd_set master_set, read_fds;
    int fdmax = (server->server_sock > client_socket) ? server->server_sock : client_socket;

    FD_ZERO(&master_set);
    FD_SET(server->server_sock, &master_set);
    FD_SET(client_socket, &master_set);

    while (1)
    {
        read_fds = master_set;

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1)
        {
            logexit("select");
        }

        if (FD_ISSET(server->server_sock, &read_fds))
        {
            // Handle peer connection
            char peer_addrstr[BUFSZ];
            char peer_buffer[BUFSZ];
            int peerSock = accept_conncetion(server->server_sock, peer_addrstr, peer_buffer);
            handle_peer_req(server, peerSock, peer_buffer);
        }

        if (FD_ISSET(client_socket, &read_fds))
        {
            // Handle client connection
            char client_addrstr[BUFSZ];
            char client_request[BUFSZ];
            int clientSock = accept_conncetion(client_socket, client_addrstr, client_request);
            printf("Received request from %s\n", client_addrstr);
            handle_client_req(server, clientSock, client_request);
        }
    }

    free(server);
    exit(EXIT_SUCCESS);
}
