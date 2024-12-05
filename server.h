#include <sys/types.h>

#ifndef SERVER
#define SERVER

typedef struct {
    int current_peer;
    struct sockaddr_storage peer_storage;
} server_t;

#endif
