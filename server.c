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

int accept_conncetion(int socket, char *buffer)
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
    recv(csock, buffer, BUFSZ - 1, 0);
    return csock;
}

void init_peer_connection_and_setup_server_conf(char *peerPort, server_t *server)
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
        server->active_mode = 1;
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
    peer_response(s, RES_CONNPEER, integer_to_string(server->peer_id));
    server->peer_mode = PEER_MODE_USER_LOCATIONS;
    server->active_mode = 0;
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
        server->peer_sock = peer_sock;
        printf("Peer %d connected\n", peer_id);
        struct response_t response = peer_request(peer_sock, RES_CONNPEER, integer_to_string(peer_id));
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

user *find_user_by_id(server_t *server, char *id)
{
    for (int i = 0; i < server->user_count; i++)
    {
        if (strcmp(server->users[i]->id, id) == 0)
        {
            return server->users[i];
        }
    }
    return NULL;
}

typedef struct
{
    server_t *server;
    int client_sock;
    int client_id;
} client_thread_data_t;

void *new_client_requests_handler_thread(void *arg)
{
    client_thread_data_t *data = (client_thread_data_t *)arg;
    char buffer[BUFSZ];
    while (1)
    {
        memset(buffer, 0, BUFSZ);
        ssize_t received = recv(data->client_sock, buffer, BUFSZ - 1, 0);

        // Client disconnected unexpectedly
        if (received <= 0)
        {
            close(data->client_sock);
            free(data);
            pthread_exit(NULL);
        }

        handle_client_req(data->server, data->client_sock, buffer, data->client_id);
    }

    return NULL;
}

void persist_user_location_in_location_peer(server_t *server, user *user, int loc_id)
{
    char payload[BUFSZ];
    sprintf(payload, "%s %d", user->id, loc_id);
    peer_request(server->peer_sock, REQ_LOCREG, payload);
}

void handle_peer_server_storage_req(server_t *server, char *rawPayload)
{

    int action;
    char payload[BUFSZ];
    parse_payload(rawPayload, &action, payload);
    switch (action)
    {
    case REQ_LOCREG:
    {
        printf("REQ_LOCREG %s\n", payload);
        int loc_id;
        char *id = malloc(10);
        sscanf(payload, "%s %d", id, &loc_id);
        // for(int i = 0; i < 30; i++)
        // {
        //     char user_id[10] = server->user_locations->users[loc_id-1][i];
        //     if (strcmp(user_id, id) == 0)
        //     {

        //         peer_response(server->peer_sock, RES_LOCREG, integer_to_string(loc_id));
        //         return;
        //     }
        // }
        printf("Saving user %s in loc %d\n", id, loc_id);
        user_location *location = server->user_locations[loc_id - 1];
        int user_count = location->user_count;
        printf("User count %d\n", user_count);
        location->users[user_count] = id;
        location->user_count = user_count + 1;
      
        peer_response(server->peer_sock, RES_LOCREG, integer_to_string(loc_id));
        return;
    }
    }
}
void handle_client_storage_req(server_t *server, int client_sock, int action, char *payload, int client_id)
{

    if (action == REQ_USRADD)
    {
        printf("REQ_USRADD %s\n", payload);
        user *newUser = NewUserFromPayload(payload);
        user *existingUser = find_user_by_id(server, newUser->id);
        if (existingUser != NULL)
        {
            printf("Updating user %s\n", newUser->id);
            existingUser->root = newUser->root;
            peer_request(server->peer_sock, REQ_USRADD, payload);
            return_response(client_sock, OK, SUCCESSFUL_UPDATE);
            return;
        }
        if (server->user_count >= 30)
        {
            return_response(client_sock, ERROR, ERROR_USER_LIMIT_EXCEEDED);
            return;
        }
        persist_user_location_in_location_peer(server, newUser, server->client_locations[client_id - 1]);
        server->users[server->user_count] = newUser;
        server->user_count++;
        return_response(client_sock, OK, SUCCESSFUL_CREATE);
        return;
    }
    if (action == PRINTUSERS)
    {
        for (int i = 0; i < server->user_count; i++)
        {
            printf("User %s root: %d\n", server->users[i]->id, server->users[i]->root);
        }
        return;
    }

    return_response(client_sock, ERROR, "Invalid action");
}

user *find_user_location_by_id(server_t *server, char *id)
{
    for (int i = 0; i < 10; i++)
    {
        for (int j = 0; j < 30; j++)
        {
            if (server->user_locations[i]->users[j] == NULL)
            {
                continue;
            }
            if (strcmp(server->user_locations[i]->users[j], id) == 0)
            {
                return server->user_locations[i]->users[j];
            }
        }
    }
    return NULL;
}
void handle_client_location_req(server_t *server, int client_sock, int action, char *payload, int client_id)
{

    switch (action)
    {
    case REQ_USRLOC:
        printf("Filtering user %s\n", payload);
        for (int i = 0; i < CLIENTS_LOCATIONS; i++)
        {
            int users_amount = server->user_locations[i]->user_count;
            for (int j = 0; j < users_amount; j++)
            {
                printf("Checking user index:%d value:%s, filter: %s\n", j, server->user_locations[i]->users[j],payload);
                if (server->user_locations[i]->users[j] == NULL)
                {
                    continue;
                }
                if (strcmp(server->user_locations[i]->users[j], payload) == 0)
                {
                    printf("User %s found in location %d\n", payload, i + 1);
                    return_response(client_sock, OK, integer_to_string(i + 1));
                    return;
                }
            }
        }
        return_response(client_sock, ERROR, ERROR_USER_NOT_FOUND);
        return;
        /* code */
        break;
    default:
        break;
    }

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
void handle_client_req(server_t *server, int client_sock, char *request, int client_id)
{
    int action;
    char payload[BUFSZ];
    parse_payload(request, &action, payload);
    switch (server->peer_mode)
    {
    case PEER_MODE_USER_STORAGE:
        handle_client_storage_req(server, client_sock, action, payload, client_id);
        break;
    case PEER_MODE_USER_LOCATIONS:
        handle_client_location_req(server, client_sock, action, payload, client_id);
        break;
    default:
        fprintf(stderr, "Invalid peer mode\n");
        break;
    }
}

void handle_inital_client_req(server_t *server, int client_sock, char *request)
{
    int action;
    char payload[BUFSZ];
    /**
     * Example input: "33 1 1"
     * - 33: Represents the action code.
     * - 1: Represents the user ID.
     * - 1: Indicates if the user is a root user.
     *
     * The input "33 1 1" would be parsed as:
     * - Action: 33
     * - Payload: "1 1"
     */
    parse_payload(request, &action, payload);

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
        server->client_locations[client_id - 1] = loc_id;
        printf("Client %d added(Loc %d)\n", client_id, loc_id);
        server->client_sockets[client_id] = client_sock;

        // Initialize thread data for client request
        client_thread_data_t *thread_data = malloc(sizeof(client_thread_data_t));
        thread_data->server = server;
        thread_data->client_sock = client_sock;
        thread_data->client_id = client_id;

        pthread_t thread;
        if (pthread_create(&thread, NULL, new_client_requests_handler_thread, thread_data) != 0)
        {
            fprintf(stderr, "Failed to create thread for client %d\n", client_id);
            free(thread_data);
            return_response(client_sock, ERROR, "Failed to create client handler thread");
            return;
        }
        pthread_detach(thread);

        return_response(client_sock, RES_CONN, integer_to_string(client_id));
        return;
    }
    return_response(client_sock, ERROR, ERROR_PERMISSION_DENIED);
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
    server->active_mode = 0;
    server->user_locations = malloc(sizeof(user_location) * CLIENTS_LOCATIONS);
    for (int i = 0; i < 30; i++)
    {
        server->users[i] = NULL;
    }
    for (int i = 0; i < 10; i++)
    {
        server->user_locations[i] = malloc(sizeof(user_location));
        server->user_locations[i]->user_count = 0;
        
    }


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
    init_peer_connection_and_setup_server_conf(argv[1], server);

    struct sockaddr_storage client_storage;
    int client_socket = init_server(argv[2], &client_storage);

    // Accept connections from peer and initial requests from clients
    fd_set master_set, read_fds;
    int peer_connection_socket = server->active_mode == 1 ? server->server_sock : server->peer_sock;
    int fdmax = (peer_connection_socket > client_socket) ? peer_connection_socket : client_socket;

    FD_ZERO(&master_set);
    FD_SET(peer_connection_socket, &master_set);
    FD_SET(client_socket, &master_set);
    while (1)
    {
        read_fds = master_set;

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1)
        {
            logexit("select");
        }
        if (FD_ISSET(peer_connection_socket, &read_fds))
        {
            // Handle peer connection
            char peer_buffer[BUFSZ];
            if (server->active_mode == 1)
            {
                int peerSock = accept_conncetion(server->server_sock, peer_buffer);
                handle_peer_req(server, peerSock, peer_buffer);
            }
            else
            {
                recv(server->peer_sock, peer_buffer, BUFSZ - 1, 0);
                handle_peer_server_storage_req(server, peer_buffer);
            }
        }

        if (FD_ISSET(client_socket, &read_fds))
        {
            // Handle client connection
            char client_request[BUFSZ];
            int clientSock = accept_conncetion(client_socket, client_request);
            handle_inital_client_req(server, clientSock, client_request);
        }
    }

    free(server);
    exit(EXIT_SUCCESS);
}
