#include <sys/types.h>

#ifndef SERVER
#define SERVER

typedef struct {
    int current_peer_id;
    int initial_peer;
    int peer_socket;
    struct sockaddr_storage peer_storage;
} server_t;

#endif
