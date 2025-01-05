#include <sys/types.h>
#define PEER_MODE_USER_STORAGE 1
#define PEER_MODE_USER_LOCATIONS 2

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
    int peer_mode;
    int server_sock;
    int peer_sock;
    int peer_id;
    struct sockaddr_storage peer_storage;
    user **users;
    int user_count;
    user_location **user_locations;
} server_t;



#endif
