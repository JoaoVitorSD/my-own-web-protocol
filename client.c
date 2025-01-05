#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

void validate_loc_id_and_exit(int loc_id)
{
	if (loc_id < 1 || loc_id > 10)
	{
		printf("Invalid argument\n");
		exit(EXIT_FAILURE);
	}
}

int connect_to_server_and_return_client_id(const char *server_ip, const char *server_port, int loc_id, int *server_sock, int *client_id)
{
	struct sockaddr_storage server_storage;
	if (addrparse(server_ip, server_port, &server_storage) != 0)
	{
		handle_error("addrparse");
	}

	*server_sock = socket(server_storage.ss_family, SOCK_STREAM, 0);
	if (*server_sock == -1)
	{
		handle_error("socket");
	}

	struct sockaddr *addr = (struct sockaddr *)(&server_storage);
	if (connect(*server_sock, addr, sizeof(server_storage)) != 0)
	{
		handle_error("connect");
	}

	char payload[BUFSZ];
	snprintf(payload, BUFSZ, "%d", loc_id);
	struct response_t response = client_request_to_server(*server_sock, REQ_CONN, payload);

	if (response.action == ERROR)
	{
		handle_error(response.payload);
	}

	sscanf(response.payload, "%d", client_id);
	printf("Socket server %d ", *server_sock);
	close(*server_sock);
	return *client_id;
}

void disconnect_from_server(int server_sock, int client_id)
{
	char payload[BUFSZ];
	snprintf(payload, BUFSZ, "%d", client_id);
	struct response_t response = client_request_to_server(server_sock, REQ_DISC, payload);

	if (response.action == ERROR)
	{
		handle_error(response.payload);
	}

	printf("Successful disconnect\n");
	close(server_sock);
}

int main(int argc, char **argv)
{
	if (argc != 5)
	{
		printf("Usage: %s <server_ip> <server_storage_port> <server_location_port> <loc_id>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	const char *server_ip = argv[1];
	const char *server_storage_port = argv[2];
	const char *server_location_port = argv[3];
	int loc_id = atoi(argv[4]);

	validate_loc_id_and_exit(loc_id);

	int storage_sock, location_sock;
	int client_id_storage, client_id_location;

	// Connect to SU
	connect_to_server_and_return_client_id(server_ip, server_storage_port, loc_id, &storage_sock, &client_id_storage);
	printf("SU New Id: %d\n", client_id_storage);
	// Connect to SL
	// connect_to_server_and_return_client_id(server_ip, server_location_port, loc_id, &location_sock, &client_id_location);
	// printf("SL New Id: %d\n", client_id_location);

	char command[BUFSZ];
	while (1)
	{
		printf("Enter command: ");
		fgets(command, BUFSZ, stdin);
		command[strcspn(command, "\n")] = '\0'; // Remove newline character
		printf("Command: %s\n", command);
		if (strcmp(command, "kill") == 0)
		{
			disconnect_from_server(storage_sock, client_id_storage);
			disconnect_from_server(location_sock, client_id_location);
			break;
		}
		else if (strncmp(command, "add ", 4) == 0)
		{
			char uid[11];
			int is_special;
			sscanf(command + 4, "%10s %d", uid, &is_special);
			char payload[BUFSZ];
			memset(payload, 0, BUFSZ);	
			snprintf(payload, BUFSZ, "%s %d", uid, is_special);
			struct response_t response = client_request_to_server(storage_sock, REQ_USRADD, payload);

			if (response.action == ERROR)
			{
				handle_error(response.payload);
			}
			else if (response.action == OK)
			{
				printf("User updated: %s\n", uid);
			}
			else
			{
				printf("New user added: %s\n", uid);
			}
		}
		else if (strncmp(command, "find ", 5) == 0)
		{
			char uid[11];
			sscanf(command + 5, "%10s", uid);
			struct response_t response = client_request_to_server(location_sock, REQ_USRLOC, uid);

			if (response.action == ERROR)
			{
				handle_error(response.payload);
			}
			else
			{
				printf("Current location: %s\n", response.payload);
			}
		}
		else if (strcmp(command, "print") == 0)
		{
			struct response_t response = client_request_to_server(storage_sock, PRINTUSERS, "");
	
			if (response.action == ERROR)
			{
				handle_error(response.payload);
			}
		}
		else
		{
			printf("Unknown command\n");
		}
	}

	return 0;
}