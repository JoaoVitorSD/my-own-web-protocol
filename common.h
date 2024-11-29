#pragma once

#include <stdlib.h>

#include <arpa/inet.h>


struct sockets_conf
{
    uint16_t peer_port;
    uint16_t conn_port;
};


void logexit(const char *msg);

int addrparse(const char *addrstr, const char *portstr,
              struct sockaddr_storage *storage);

void addrtostr(const struct sockaddr *addr, char *str, size_t strsize);

int server_sockaddr_init(const char *proto, const char *portstr,
                         struct sockaddr_storage *storage);

