#include <sys/types.h>

#ifndef SERVER
#define SERVER

typedef struct {
    char id[10];
    unsigned root;
} user;


typedef struct{
    char id[10];
    int location;
} user_location;

typedef struct {
    int initial_peer;
    int peer_id;
    int peer_sock;
    int peer_pair_id;
    struct sockaddr_storage peer_storage;
    user **users;
    int user_count;
    user_location **user_locations;
} server_t;



#endif
