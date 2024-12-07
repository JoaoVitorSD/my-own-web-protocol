#include <sys/types.h>

#ifndef SERVER
#define SERVER

typedef struct {
    int initial_peer;
    int peer_id;
    int peer_sock;
    int peer_pair_id;
    struct sockaddr_storage peer_storage;
} server_t;

#endif
