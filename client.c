#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

struct infraestructure_t
{

	char *server_ip;
	char *server_storage_port;
	char *server_location_port;
	int loc_id;
	int storage_sock;
	int location_sock;
	int client_id_storage;
	int client_id_location;
};

void validate_loc_id_and_if_invalid_exit(int loc_id)
{
	if (loc_id < 1 || loc_id > 10)
	{
		printf("Invalid argument\n");
		exit(EXIT_FAILURE);
	}
}

struct infraestructure_t *extract_infraestructure(int argc, char **argv)
{
	struct infraestructure_t *infraestructure = malloc(sizeof(struct infraestructure_t));
	if (argc != 5)
	{
		printf("Usage: %s <server_ip> <server_storage_port> <server_location_port> <loc_id>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	infraestructure->server_ip = argv[1];
	infraestructure->server_storage_port = argv[2];
	infraestructure->server_location_port = argv[3];
	infraestructure->loc_id = atoi(argv[4]);
	validate_loc_id_and_if_invalid_exit(infraestructure->loc_id);

	return infraestructure;
}
int connect_to_server_and_return_client_id(struct infraestructure_t *infraestructure, int peer_mode)
{
	int *server_sock = peer_mode == PEER_MODE_USER_STORAGE ? &infraestructure->storage_sock : &infraestructure->location_sock;
	char *peer_port = peer_mode == PEER_MODE_USER_STORAGE ? infraestructure->server_storage_port : infraestructure->server_location_port;
	int *client_id = peer_mode == PEER_MODE_USER_STORAGE ? &infraestructure->client_id_storage : &infraestructure->client_id_location;
	struct sockaddr_storage server_storage;
	if (addrparse(infraestructure->server_ip, peer_port, &server_storage) != 0)
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
	snprintf(payload, BUFSZ, "%d", infraestructure->loc_id);
	struct response_t response = client_request_to_server(*server_sock, REQ_CONN, payload);

	if (response.action == ERROR)
	{
		handle_error(response.payload);
	}
	sscanf(response.payload, "%d", client_id);
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
	struct infraestructure_t *infraestructure = extract_infraestructure(argc, argv);
	// Connect to SU
	connect_to_server_and_return_client_id(infraestructure, PEER_MODE_USER_STORAGE);
	printf("SU New Id: %d\n", infraestructure->client_id_storage);

	// Connect to SL
	connect_to_server_and_return_client_id(infraestructure, PEER_MODE_USER_LOCATIONS);
	printf("SL New Id: %d\n", infraestructure->client_id_location);

	char command[BUFSZ];
	while (1)
	{
		printf("Enter command: ");
		fgets(command, BUFSZ, stdin);
		command[strcspn(command, "\n")] = '\0'; // Remove newline character
		if (strcmp(command, "kill") == 0)
		{
			// disconnect_from_server(storage_sock, client_id_storage);
			// disconnect_from_server(location_sock, client_id_location);
			break;
		}
		else if (strncmp(command, "add ", 4) == 0)
		{
			char uid[11];
			int is_special;
			sscanf(command + 4, "%10s %d", uid, &is_special);
			char payload[BUFSZ];
			memset(payload, 0, BUFSZ);
			sprintf(payload, "%s %d", uid, is_special);
			struct response_t response = client_request_to_server(infraestructure->storage_sock, REQ_USRADD, payload);

			if (response.action == ERROR)
			{
				handle_error(response.payload);
			}
			else if (response.action == OK)
			{
				if (strcmp(response.payload, SUCCESSFUL_CREATE) == 0)
				{
					printf("New user added: %s\n", uid);
				}
				else if (strcmp(response.payload, SUCCESSFUL_UPDATE) == 0)
				{
					printf("User updated: %s\n", uid);
				}
				else
				{
					printf("Invalid response\n");
				}
			}
		}
		else if (strncmp(command, "find ", 5) == 0)
		{
			char uid[11];
			sscanf(command + 5, "%10s", uid);
			struct response_t response = client_request_to_server(infraestructure->location_sock, REQ_USRLOC, uid);
			if (response.action == ERROR)
			{
				handle_error(response.payload);
			}
			else
			{
				printf("Current location: %s\n", response.payload);
			}
		}
		else if (strncmp(command, "in ", 3) == 0 || strncmp(command, "out ", 4) == 0)
		{
			char uid[11];
			char action[4];
			sscanf(command, "%s %s", action, uid);
			char payload[BUFSZ];
			memset(payload, 0, BUFSZ);
			sprintf(payload, "%s %s", action, uid);
			printf("Payload: %s\n", payload);
			struct response_t response = client_request_to_server(infraestructure->storage_sock, REQ_USRACCESS, payload);
			if (response.action == ERROR)
			{
				handle_error(response.payload);
			}
			else
			{
				printf("Ok. Last location: %s\n", response.payload);
			}
		}
		else if (strncmp(command, "inspect ", 8) == 0)
		{
			// UID LocId
			printf("Inspecting %s \n", command);
			char *id = malloc(11);
			int loc_id;
			char filter[BUFSZ];
			sscanf(command + 8, "%s %d", id, &loc_id);
			sprintf(filter, "%s %d", id, loc_id);
			printf("Filter: %s\n", filter);
			struct response_t response = client_request_to_server(infraestructure->location_sock, REQ_LOCLIST, filter);
			if (response.action == ERROR)
			{
				handle_error(response.payload);
			}
			else
			{
				printf("List of people at the specified location: %s\n", response.payload);
			}
		}

		else
		{
			printf("Unknown command\n");
		}
	}

	return 0;
}