#pragma once

#include <stdlib.h>

#include <arpa/inet.h>
#include "constants.h"




void logexit(const char *msg);

int addrparse(const char *addrstr, const char *portstr,
              struct sockaddr_storage *storage);

void addrtostr(const struct sockaddr *addr, char *str, size_t strsize);

int server_sockaddr_init(uint16_t port,
                         struct sockaddr_storage *storage);

struct response_t request(int socket, int req_action, const char *buffer);

struct response_t request_in_port(int port, int req_action, const char *buffer);

void return_response(int socket, int req_action, const char *payload);

char * itoa(int value);


void handle_error(char *msg);


int gen_peer_port();