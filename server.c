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
    return NULL;
}

// Server utils - Funções de manipulação de dados do servidor
void put_user_in_location(char **users_locations, char *id)
{
    for (int i = 0; i < MAX_USERS; i++)
    {
        if (users_locations[i] == NULL)
        {
            users_locations[i] = id;
            return;
        }
    }
    return;
}

void put_user_outside_location(char **users_locations, char *id)
{
    for (int i = 0; i < MAX_USERS; i++)
    {
        if (users_locations[i] == NULL)
        {
            continue;
        }
        if (strcmp(users_locations[i], id) == 0)
        {
            users_locations[i] = NULL;
            return;
        }
    }
    return;
}

void disconnect_client(server_t *server, int client_sock, int client_id)
{
    printf("REQ_DISC\n");
    if (server->client_locations[client_id - 1] == -1)
    {
        return_response(client_sock, ERROR, ERROR_CLIENT_NOT_FOUND);
        return;
    }
    printf("Client %d removed (Loc %d)\n", client_id, server->client_locations[client_id - 1]);
    server->client_locations[client_id - 1] = -1;
    server->client_sockets[client_id - 1] = -1;
    server->client_connections_count--;
    return_response(client_sock, OK, SUCCESSFUL_DISCONNECTED);
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

struct response_t peer_request(server_t *server, int action, char *payload)
{
    char buffer[BUFSZ];
    sprintf(buffer, "%d %s", action, payload);
    size_t count = send(server->peer_sock, buffer, strlen(buffer) + 1, 0);
    if (count != strlen(buffer) + 1)
    {
        logexit("send");
    }

    memset(buffer, 0, BUFSZ);
    unsigned total = 0;
    recv(server->peer_sock, buffer + total, BUFSZ - total, 0);
    return extract_response(buffer);
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

// END Server utils

// THREADS SECTIONS
typedef struct
{
    server_t *server;
    int sock;
    int id;
    void *handler;
} connection_thread_t;

void *thread_handler(void *arg)
{
    connection_thread_t *data = (connection_thread_t *)arg;
    char buffer[BUFSZ];
    while (1)
    {
        memset(buffer, 0, BUFSZ);
        ssize_t received = recv(data->sock, buffer, BUFSZ - 1, 0);

        if (received <= 0)
        {
            close(data->sock);
            free(data);
        }
        printf("%d\n", data->id);
        ((void (*)(server_t *, int, char *, int))data->handler)(data->server, data->sock, buffer, data->id);
    }

    return NULL;
}


void * thread_accept_handler(void *arg){
    connection_thread_t *data = (connection_thread_t *)arg;
    char buffer[BUFSZ];
    while (1)
    {
        memset(buffer, 0, BUFSZ);
        int client_sock = accept_conncetion(data->sock, buffer);
        if (client_sock == -1)
        {
            continue;
        }
        ((void (*)(server_t *, int, char *, int))data->handler)(data->server, client_sock, buffer, data->id);
    }
    return NULL;
}
void start_thread(server_t *server, int sock_to_listen, int id, void *thread_function, int accept)
{
    connection_thread_t *thread_data = malloc(sizeof(connection_thread_t));
    thread_data->server = server;
    thread_data->sock = sock_to_listen;
    thread_data->id = id;
    thread_data->handler = thread_function;
    void* (*handler)(void*) = accept ? thread_accept_handler : thread_handler;
    pthread_t thread;
    if (pthread_create(&thread, NULL, handler, thread_data) != 0)
    {
        fprintf(stderr, "Failed to create thread\n");
        free(thread_data);
        return;
    }
    pthread_detach(thread);
}

// Tratamento de requisições do SU
void *handle_peer_server_storage_req(server_t *server, int peerSock, char *rawPayload, int id)
{

    int action;
    char payload[BUFSZ];
    parse_response(rawPayload, &action, payload);
    if (action == REQ_USRAUTH)
    {
        printf("REQ_USRAUTH %s\n", payload);
        user *existingUser = find_user_by_id(server, payload);
        if (existingUser != NULL)
        {
            peer_response(server->peer_sock, RES_USRAUTH, integer_to_string(existingUser->root));
            return;
        }
        peer_response(server->peer_sock, ERROR, ERROR_USER_NOT_FOUND);
        return;
    }
    if (action == REQ_DISCPEER)
    {
        // Disconnect peer
        printf("Disconnecting peer\n");
        int peer_to_disconnect = atoi(payload);
        if (server->peer_id != peer_to_disconnect)
        {
            return_response(peerSock, ERROR, ERROR_PEER_NOT_FOUND);
            return;
        }
        int peer_sock = server->peer_id;
        server->peer_id = -1;
        return_response(peer_sock, OK, SUCCESSFUL_DISCONNECTED);
        printf("Peer %d disconnected\n", peer_sock);
        return;
    }
    peer_response(server->peer_sock, ERROR, "Invalid action");
}

// Tratamento de requisições do SL
void *handle_peer_server_location_req(server_t *server, int peerSock, char *rawPayload, int id)
{

    int action;
    char payload[BUFSZ];
    parse_response(rawPayload, &action, payload);

    if (action == REQ_LOCREG)
    {
        printf("REQ_LOCREG %s\n", payload);
        int loc_id;
        char *id = malloc(10);
        sscanf(payload, "%s %d", id, &loc_id);
        int oldLocation = find_user_location_in_sl(server, id);
        char **newUserLocationArray = loc_id == -1 ? server->users_outside : server->user_locations[loc_id - 1]->users;
        if (oldLocation == 0)
        {
            put_user_in_location(newUserLocationArray, id);
            peer_response(server->peer_sock, RES_LOCREG, "-1");
            return;
        }
        char **oldUserLocationArray = oldLocation == -1 ? server->users_outside : server->user_locations[oldLocation - 1]->users;
        put_user_outside_location(oldUserLocationArray, id);
        put_user_in_location(newUserLocationArray, id);
        peer_response(server->peer_sock, RES_LOCREG, integer_to_string(oldLocation));
        free(oldLocation);
        return;
    }
    if (action == REQ_DISCPEER)
    {
        // Disconnect peer
        printf("Disconnecting peer\n");
        int peer_to_disconnect = atoi(payload);
        if (server->peer_id != peer_to_disconnect)
        {
            return_response(peerSock, ERROR, ERROR_PEER_NOT_FOUND);
            return;
        }
        server->peer_id = -1;
        return_response(peerSock, OK, SUCCESSFUL_DISCONNECTED);
        printf("Peer %d disconnected\n", peerSock);
        return;
    }
    peer_response(server->peer_sock, ERROR, "Invalid action");
}
// Lidando com as requisições de conexão
void *handle_peer_req(server_t *server, int peer_sock, char *clientInfo, int id)
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
        }
        else
        {
            // TODO asign socket instead of port
            int peer_id = gen_peer_id();
            server->peer_id = peer_id;
            server->peer_sock = peer_sock;
            printf("Peer %d connected\n", peer_id);
            struct response_t response = peer_request(server, RES_CONNPEER, integer_to_string(peer_id));
            server->server_id = atoi(response.payload);
            printf("New Peer ID: %d\n", server->server_id);
            start_thread(server, peer_sock, peer_id, handle_peer_server_storage_req,0);
        }
    }
    else
    {
        return_response(peer_sock, ERROR, clientInfo);
    }
}

void *handle_client_storage_req(server_t *server, int client_sock, int action, char *payload, int client_id)
{

    if (action == REQ_USRADD)
    {
        printf("REQ_USRADD %s\n", payload);
        user *newUser = NewUserFromPayload(payload);
        user *existingUser = find_user_by_id(server, newUser->id);
        if (existingUser != NULL)
        {
            existingUser->root = newUser->root;
            return_response(client_sock, OK, SUCCESSFUL_UPDATE);
            return;
        }
        if (server->user_count >= 30)
        {
            return_response(client_sock, ERROR, ERROR_USER_LIMIT_EXCEEDED);
            return;
        }

        server->users[server->user_count] = newUser;
        server->user_count++;
        return_response(client_sock, OK, SUCCESSFUL_CREATE);
        return;
    }

    if (action == REQ_USRACCESS)
    {
        char *direction = malloc(4), *id = malloc(10);
        sscanf(payload, "%s %s", id, direction);
        printf("REQ_USRACCESS %s %s\n", id, direction);
        user *existingUser = find_user_by_id(server, id);
        if (existingUser != NULL)
        {
            int locId = strcmp(direction, "out") == 0 ? -1 : server->client_locations[client_id - 1];
            char payload[BUFSZ];
            sprintf(payload, "%s %d", id, locId);
            struct response_t response = peer_request(server, REQ_LOCREG, payload);
            return_response(client_sock, RES_USRACCESS, response.payload);
            return;
        }
        return_response(client_sock, ERROR, ERROR_USER_NOT_FOUND);
        return;
    }

    if (action == REQ_DISC)
    {
        disconnect_client(server, client_sock, client_id);
        return;
    }
    return_response(client_sock, ERROR, "Invalid action");
}

// END THREADS SECTIONS

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
        start_thread(server, server->server_sock, 0, handle_peer_req,1);
        return;
    }
    server->peer_sock = s;
    struct response_t response = peer_request(server, REQ_CONNPEER, "");
    if (response.action == ERROR)
    {
        printf("Error connecting to peer\n");
        handle_error(response.payload);
        return;
    }
    // Peer connected, using socket to communicate
    sscanf(response.payload, "%d", &server->peer_id);
    printf("New Peer ID: %d\n", server->peer_id);
    server->peer_id = gen_peer_id();
    printf("Peer %d connected\n", server->peer_id);
    peer_response(s, RES_CONNPEER, integer_to_string(server->peer_id));
    server->peer_mode = PEER_MODE_USER_LOCATIONS;
    server->active_mode = 0;

    // Inicia thread para tratar requisições de SL
    start_thread(server, server->peer_sock, server->peer_id, handle_peer_server_location_req,0);
}

// Returns an array with user location and respective index in array
//  Returns 0 if user is not found or -1 if user is outside or location_id if user is inside
int find_user_location_in_sl(server_t *server, char *id)
{
    for (int i = 0; i < CLIENTS_LOCATIONS; i++)
    {
        for (int j = 0; j < MAX_USERS; j++)
        {
            if (server->user_locations[i]->users[j] == NULL)
            {
                continue;
            }
            if (strcmp(server->user_locations[i]->users[j], id) == 0)
            {
                return i + 1;
            }
        }
    }
    // Checking users outside
    for (int i = 0; i < MAX_USERS; i++)
    {
        if (server->users_outside[i] == NULL)
        {
            continue;
        }
        if (strcmp(server->users_outside[i], id) == 0)
        {
            return -1;
        }
    }
    return 0;
}

void handle_client_location_req(server_t *server, int client_sock, int action, char *payload, int client_id)
{

    switch (action)
    {
    case REQ_USRLOC:
        printf("REQ_USRLOC %s\n", payload);
        int loc_id = find_user_location_in_sl(server, payload);
        if (loc_id != 0)
        {
            return_response(client_sock, RES_USRLOC, integer_to_string(loc_id));
            return;
        }
        return_response(client_sock, ERROR, ERROR_USER_NOT_FOUND);
        return;
    case REQ_LOCLIST:
        char locList[BUFSZ];
        printf("REQ_LOCLIST %s\n", payload);
        memset(locList, 0, BUFSZ);
        char *user_id = malloc(10);
        sscanf(payload, "%s %d", user_id, &loc_id);
        struct response_t auth_response = peer_request(server, REQ_USRAUTH, user_id);
        int is_special = atoi(auth_response.payload);
        if (is_special != 1)
        {
            return_response(client_sock, ERROR, ERROR_PERMISSION_DENIED);
            return;
        }

        char **users = loc_id == -1 ? server->users_outside : server->user_locations[loc_id - 1]->users;
        int lastIndex = 0;
        for (int i = 0; i < MAX_USERS; i++)
        {
            if (users[i] == NULL)
            {
                continue;
            }
            lastIndex = i;
        }
        for (int i = 0; i <= lastIndex; i++)
        {
            if (users[i] == NULL)
            {
                continue;
            }
            strcat(locList, users[i]);
            if (i != lastIndex)
            {
                strcat(locList, ", ");
            }
        }
        return_response(client_sock, RES_LOCLIST, locList);
        return;
    case REQ_DISC:
        disconnect_client(server, client_sock, client_id);
        return;
    default:
        break;
    }

    return_response(client_sock, ERROR, ERROR_USER_NOT_FOUND);
}
void handle_client_req(server_t *server, int client_sock, char *request, int client_id)
{
    int action;
    char payload[BUFSZ];
    parse_response(request, &action, payload);
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

void handle_inital_client_req(server_t *server, int client_sock, char *request, int _)
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
    parse_response(request, &action, payload);

    if (action == REQ_CONN)
    {
        int client_id = gen_client_id(server->client_locations);
        if (client_id == -1)
        {
            return_response(client_sock, ERROR, ERROR_CLIENT_LIMIT_EXCEEDED);
            return;
        }
        int loc_id;
        sscanf(payload, "%d", &loc_id);
        server->client_locations[client_id - 1] = loc_id;
        server->client_sockets[client_id - 1] = client_sock;
        printf("Client %d added(Loc %d)\n", client_id, loc_id);

        start_thread(server, client_sock, client_id, handle_client_req,0);

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
    server->users_outside = malloc(sizeof(char) * 30 * 10);
    for (int i = 0; i < 30; i++)
    {
        server->users[i] = NULL;
    }
    for (int i = 0; i < 10; i++)
    {
        server->client_locations[i] = -1;
        server->client_sockets[i] = -1;
        server->user_locations[i] = malloc(sizeof(user_location));
    }

    return server;
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        usage(argc, argv);
    }
    server_t *server = NewServer();
    // Tentar conectar com o peer, se não, iniciar servidor na porta passada
    init_peer_connection_and_setup_server_conf(argv[1], server);

    struct sockaddr_storage client_storage;
    int client_socket = init_server(argv[2], &client_storage);
    // Inicia thread para tratar requisições de abertura de conexão
    start_thread(server, client_socket, 0, handle_inital_client_req,1);
    while (1)
    {

        char buffer[BUFSZ];
        memset(buffer, 0, BUFSZ);
        scanf("%s", buffer);
        if (strcmp(buffer, "kill") == 0)
        {
            // TODO disconnect from peer
            break;
        }
    }

    free(server);
    exit(EXIT_SUCCESS);
}
