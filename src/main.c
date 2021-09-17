#include <stdio.h>

#include "log.h"
#include "tcp_client.h"

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define MAX_ACTIONSIZE 12
#define BUFFER_ROOM 12

#define GEN_BUFF_SIZE (BUFFER_ROOM + MAX_ACTIONSIZE + TCP_CLIENT_MAX_RECEIVE_SIZE)

int main(int argc, char *argv[]) {
    int exit_code;
    Config client_conn_config;

    if (tcp_client_parse_arguments(argc, argv, &client_conn_config)) {
        exit_code = EXIT_FAILURE;
        goto CLEAN_UP;
    }
    if ((client_conn_config.host == NULL) || (client_conn_config.port == NULL) ||
        (client_conn_config.action == NULL) || (client_conn_config.message == NULL)) {
        exit_code = EXIT_SUCCESS;
        goto CLEAN_UP;
    }

    int sock_fd = tcp_client_connect(client_conn_config);
    if (sock_fd == -1) {
        exit_code = EXIT_FAILURE;
        goto CLEAN_UP;
    }

    if (tcp_client_send_request(sock_fd, client_conn_config)) {
        exit_code = EXIT_FAILURE;
        goto CLOSE_AND_CLEAN_UP;
    }

    char buff[GEN_BUFF_SIZE];
    memset(buff, 0, sizeof(buff));
    if (tcp_client_receive_response(sock_fd, buff, GEN_BUFF_SIZE)) {
        exit_code = EXIT_FAILURE;
        goto CLOSE_AND_CLEAN_UP;
    }

    // print response
    printf("%s\n", buff);
    exit_code = EXIT_SUCCESS;

CLOSE_AND_CLEAN_UP:
    tcp_client_close(sock_fd);
CLEAN_UP:
    return exit_code;
}
