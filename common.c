#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

void logexit(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int addrparse(const char *addrstr, const char *portstr,
              struct sockaddr_storage *storage)
{
    if (addrstr == NULL || portstr == NULL)
    {
        return -1;
    }

    uint16_t port = (uint16_t)atoi(portstr); // unsigned short
    if (port == 0)
    {
        return -1;
    }
    port = htons(port); // host to network short

    struct in_addr inaddr4; // 32-bit IP address
    if (inet_pton(AF_INET, addrstr, &inaddr4))
    {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)storage;
        addr4->sin_family = AF_INET;
        addr4->sin_port = port;
        addr4->sin_addr = inaddr4;
        return 0;
    }

    struct in6_addr inaddr6; // 128-bit IPv6 address
    if (inet_pton(AF_INET6, addrstr, &inaddr6))
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)storage;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = port;
        // addr6->sin6_addr = inaddr6
        memcpy(&(addr6->sin6_addr), &inaddr6, sizeof(inaddr6));
        return 0;
    }

    return -1;
}

void addrtostr(const struct sockaddr *addr, char *str, size_t strsize)
{
    int version;
    char addrstr[INET6_ADDRSTRLEN + 1] = "";
    uint16_t port;

    if (addr->sa_family == AF_INET)
    {
        version = 4;
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        if (!inet_ntop(AF_INET, &(addr4->sin_addr), addrstr,
                       INET6_ADDRSTRLEN + 1))
        {
            logexit("ntop");
        }
        port = ntohs(addr4->sin_port); // network to host short
    }
    else if (addr->sa_family == AF_INET6)
    {
        version = 6;
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        if (!inet_ntop(AF_INET6, &(addr6->sin6_addr), addrstr,
                       INET6_ADDRSTRLEN + 1))
        {
            logexit("ntop");
        }
        port = ntohs(addr6->sin6_port); // network to host short
    }
    else
    {
        logexit("unknown protocol family.");
    }
    if (str)
    {
        snprintf(str, strsize, "IPv%d %s %hu", version, addrstr, port);
    }
}

int server_sockaddr_init(uint16_t port,
                         struct sockaddr_storage *storage)
{
    port = htons(port); // host to network short
    memset(storage, 0, sizeof(*storage));

    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)storage;
    addr6->sin6_family = AF_INET6;
    addr6->sin6_addr = in6addr_any;
    addr6->sin6_port = port;
    return 0;
}

struct response_t extract_response(char *buffer)
{
    int action_response;
    char *payload_response = malloc(BUFSZ);
    parse_response(buffer, &action_response, payload_response);
    // printf("Received response: %d %s\n", action_response, payload_response);
    return (struct response_t){action_response, payload_response};
}

struct response_t client_request_to_server(int socket, int action, char *payload)
{
    char buffer[BUFSZ];
    memset(buffer, 0, BUFSZ);
    sprintf(buffer, "%d %s", action, payload);
    size_t count = send(socket, buffer, strlen(buffer) + 1, 0);
    if (count != strlen(buffer) + 1)
    {
        logexit("send");
    }
    memset(buffer, 0, BUFSZ);
    unsigned total = 0;
    recv(socket, buffer + total, BUFSZ - total - 1, 0);
    return extract_response(buffer);
}

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
int parse_response(char *raw, int *action, char *payload)
{
 return sscanf(raw, "%d %[^\n]", action, payload);
}

char *integer_to_string(int value)
{
    char *result = malloc(12);
    sprintf(result, "%d", value);
    return result;
}

void return_response(int socket, int action, char *payload)
{
    char buffer[BUFSZ];
    sprintf(buffer, "%d %s", action, payload);

    size_t count = send(socket, buffer, strlen(buffer) + 1, 0);
    if (count != strlen(buffer) + 1)
    {
        printf("Error sending response\n");
        logexit("send");
    }
    // printf("Sent response: %s\n", buffer);
}

// 01 : ”Peer limit exceeded” 02 : ”Peer not found” 09 : ”Client limit exceeded” 10 : “Client not found” 17 : “User limit exceeded” 18 : “User not found” 19 : “Permission denied”

void handle_error(char *message)
{
    if (0 == strcmp(message, ERROR_PEER_LIMIT_EXCEEDED))
    {
        printf("Error: Peer limit exceeded\n");
        exit(EXIT_FAILURE);
    }
    else if (0 == strcmp(message, ERROR_PEER_NOT_FOUND))
        printf("Error: Peer not found\n");
    else if (0 == strcmp(message, ERROR_CLIENT_LIMIT_EXCEEDED))
        printf("Error: Client limit exceeded\n");
    else if (0 == strcmp(message, ERROR_CLIENT_NOT_FOUND))
        printf("Error: Client not found\n");
    else if (0 == strcmp(message, ERROR_USER_LIMIT_EXCEEDED))
        printf("Error: User limit exceeded\n");
    else if (0 == strcmp(message, ERROR_USER_NOT_FOUND))
        printf("Error: User not found\n");
    else if (0 == strcmp(message, ERROR_PERMISSION_DENIED))
        printf("Error: Permission denied\n");
    else
        printf("Error: Unknown error %s\n", message);
}

int gen_peer_id()
{
    srand(time(0));
    return 1 + rand() % 100000;
}

int gen_client_id()
{
    return rand() % 100000;
}