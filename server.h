#include <sys/types.h>


#ifndef SERVER
#define SERVER

typedef struct
{
    char id[10];
    unsigned root;
} user;

typedef struct
{
    char id[10];
    int location;
} user_location;

typedef struct
{
    int peer_mode;
    int server_sock;
    int server_id;
    int peer_sock;
    int peer_id;
    struct sockaddr_storage peer_storage;
    int user_count;
    user* users[30];
    user_location* user_locations[10];
    int client_connections[10];
    int client_connections_count;
    int client_sockets[10];
} server_t;

#endif
