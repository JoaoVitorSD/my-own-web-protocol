// Controll messages
#define REQ_CONNPEER 17
#define RES_CONNPEER 18
#define REQ_DISCPEER 19
#define REQ_CONN 20
#define RES_CONN 21
#define REQ_DISC 22

// Control Values
#define MAX_CLIENT_CONNECTIONS 10
#define PEER_MODE_USER_STORAGE 1
#define PEER_MODE_USER_LOCATIONS 2
#define CLIENTS_LOCATIONS 10
#define MAX_USERS 30

// Debug
#define PRINTUSERS 1000
// Data Messages
#define REQ_USRADD 33
#define REQ_USRACCESS 34
#define RES_USRACCESS 35
#define REQ_LOCREG 36
#define RES_LOCREG 37
#define REQ_USRLOC 38
#define RES_USRLOC 39
#define REQ_LOCLIST 40
#define RES_LOCLIST 41
#define REQ_USRAUTH 42
#define RES_USRAUTH 43


// Success codes & Messages
#define OK 0
#define SUCCESSFUL_DISCONNECTED "01"
#define SUCCESSFUL_CREATE "02"
#define SUCCESSFUL_UPDATE "03"
// Confirmation & Error Messages
#define ERROR 255


#define ERROR_PEER_LIMIT_EXCEEDED "01"
#define ERROR_PEER_NOT_FOUND "02"
#define ERROR_CLIENT_LIMIT_EXCEEDED "09"
#define ERROR_CLIENT_NOT_FOUND "10"
#define ERROR_USER_LIMIT_EXCEEDED "17"
#define ERROR_USER_NOT_FOUND "18"
#define ERROR_PERMISSION_DENIED "19"



// Params

#define BUFSZ 1024

struct sockets_conf
{
    uint16_t peer_port;
    uint16_t conn_port;
};

struct response_t
{
    int action;
    char *payload;
};