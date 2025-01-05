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

struct response_t client_request_to_server(int socket, int req_action, const char *buffer);


struct response_t parse_response(char *buffer);

void return_response(int socket, int req_action, const char *payload);

// Extract response to action and payload
int parse_payload(char * rawPayload, int * action, char * payload);
char *integer_to_string(int value);

void handle_error(char *msg);


int gen_peer_id();
