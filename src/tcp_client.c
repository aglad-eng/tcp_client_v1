#include "tcp_client.h"
#include "log.h"
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>

#define END_OPTIONS -1
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define CONNECTION_FAILURE -1

#define NUM_CHARS_MAX_MSG_LEN 32

#define UPPERCASE_STRING "uppercase"
#define LOWERCASE_STRING "lowercase"
#define TITLECASE_STRING "title-case"
#define REVERSE_STRING "reverse"
#define SHUFFLE_STRING "shuffle"

#define UPPERCASE_CHAR 'u'
#define LOWERCASE_CHAR 'l'
#define TITLECASE_CHAR 't'
#define REVERSE_CHAR 'r'
#define SHUFFLE_CHAR 's'

#define HELP_STRING "help"
#define VERBOSE_STRING "verbose"
#define HOST_STRING "host"
#define PORT_STRING "port"

#define VERBOSE_CHAR 'v'
#define HOST_CHAR 'h'
#define PORT_CHAR 'p'

#define HELP_BITMASK 0x1
#define VERBOSE_BITMASK 0x2
#define HOST_BITMASK 0x4
#define PORT_BITMASK 0x8
#define ERR_BITMASK 0x10

#define V_LOG_ERROR(...)                                                                           \
    if (options_detected & VERBOSE_BITMASK) {                                                      \
        log_error(__VA_ARGS__);                                                                    \
    }

#define V_LOG_INFO(...)                                                                            \
    if (options_detected & VERBOSE_BITMASK) {                                                      \
        log_info(__VA_ARGS__);                                                                     \
    }

#define V_LOG_WARNING(...)                                                                         \
    if (options_detected & VERBOSE_BITMASK) {                                                      \
        log_warn(__VA_ARGS__);                                                                     \
    }

static char *usage_message =
    "\tUsage: tcp_client [--help] [-v] [-h HOST] [-p PORT] ACTION MESSAGE\n\n"
    "\tArguments:\n"
    "\t\tACTION   Must be uppercase, lowercase, title-case,\n"
    "\t\t         reverse, or shuffle.\n"
    "\t\tMESSAGE  Message to send to the server\n\n"
    "\tOptions:\n"
    "\t\t--help\n"
    "\t\t-v, --verbose\n"
    "\t\t--host HOSTNAME, -h HOSTNAME\n"
    "\t\t--port PORT, -p PORT\n";

static unsigned int options_detected = 0;

static struct option long_options[] = {
    /* These options set a flag */
    /* Options that dont set a flag */
    {HELP_STRING, no_argument, NULL, 0},
    {VERBOSE_STRING, no_argument, NULL, VERBOSE_CHAR},
    {HOST_STRING, required_argument, NULL, HOST_CHAR},
    {PORT_STRING, required_argument, NULL, PORT_CHAR}};

static bool is_valid_action(const char *action_str) {
    if (strcmp(action_str, UPPERCASE_STRING) == 0 || strcmp(action_str, LOWERCASE_STRING) == 0 ||
        strcmp(action_str, TITLECASE_STRING) == 0 || strcmp(action_str, REVERSE_STRING) == 0 ||
        strcmp(action_str, SHUFFLE_STRING) == 0) {
        return true;
    }
    return false;
}

static int handle_help_msg(Config *config) {
    if (options_detected & HELP_BITMASK) {
        memset(config, 0, sizeof(Config));
        if (options_detected != HELP_BITMASK) {
            V_LOG_ERROR("Invalid option combination");
            V_LOG_INFO("\n%s", usage_message);
            return EXIT_FAILURE;
        }
        V_LOG_INFO("\n%s", usage_message);
    }
    return EXIT_SUCCESS;
}

static bool port_valid(char *port) {
    for (size_t i = 0; i < strlen(port); i++) {
        if (!isdigit(port[i])) {
            return false;
        }
    }
    return true;
}

/*
Description:
    Parses the commandline arguments and options given to the program.
Arguments:
    int argc: the amount of arguments provided to the program (provided by the main function)
    char *argv[]: the array of arguments provided to the program (provided by the main function)
    Config *config: An empty Config struct that will be filled in by this function.
Return value:
    Returns a 1 on failure, 0 on success
*/
int tcp_client_parse_arguments(int argc, char *argv[], Config *config) {

    int opt_char;
    int option_index;
    options_detected = 0;

    // default values
    config->host = TCP_CLIENT_DEFAULT_HOST;
    config->port = TCP_CLIENT_DEFAULT_PORT;

    while ((opt_char = getopt_long(argc, argv, "vh:p:", long_options, &option_index)) !=
           END_OPTIONS) {

        switch (opt_char) {

            // FIXME need to make this help message
        case 0:
            options_detected |= HELP_BITMASK;
            break;

        case VERBOSE_CHAR:
            options_detected |= VERBOSE_BITMASK;
            break;

        case HOST_CHAR:
            options_detected |= HOST_BITMASK;
            config->host = optarg;
            break;

        case PORT_CHAR:
            options_detected |= PORT_BITMASK;
            config->port = optarg;
            break;

        default:
            V_LOG_ERROR("unrecognised option");
            V_LOG_INFO("\n%s", usage_message);
            options_detected |= HELP_BITMASK;
            options_detected |= ERR_BITMASK;
            return EXIT_FAILURE;
        }
    }

    if (options_detected & HELP_BITMASK) {
        if (handle_help_msg(config)) {
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // check if all the options are valid
    if (!port_valid(config->port)) {
        V_LOG_ERROR("Userinput for port was not valid.");
        V_LOG_INFO("\n%s", usage_message);
        return EXIT_FAILURE;
    }

    if (argc < (optind + 2)) {
        // to few arguments
        // (not given action or message)
        V_LOG_ERROR("Too few parameters, Action or message not given");
        V_LOG_INFO("\n%s", usage_message);
        return EXIT_FAILURE;
    }
    if ((argc - optind) > 2) {
        // to many arguments
        V_LOG_ERROR("Too many parameters: %d more parameters than expected", (argc - optind - 2));
        V_LOG_ERROR("Make sure that all options have arguments if required");
        V_LOG_INFO("\n%s", usage_message);
        return EXIT_FAILURE;
    }

    config->action = argv[optind];
    optind++;
    config->message = argv[optind];
    if (!is_valid_action(config->action)) {
        V_LOG_ERROR("Invalid action given.  Action recieved: %s", config->action);
        V_LOG_INFO("\n%s", usage_message);
        return EXIT_FAILURE;
    }

    V_LOG_INFO("Input parameters succesfully parsed..");

    return EXIT_SUCCESS;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

/*
Description:
    Creates a TCP socket and connects it to the specified host and port.
Arguments:
    Config config: A config struct with the necessary information.
Return value:
    Returns the socket file descriptor or -1 if an error occurs.
*/
int tcp_client_connect(Config config) {

    int sock_fd;
    char s[60];
    memset(s, '\0', 60);

    // find host
    int adrrinfo_status;
    struct addrinfo hints;
    struct addrinfo *servinfo, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0x6;

    if ((adrrinfo_status = getaddrinfo(config.host, config.port, &hints, &servinfo)) != 0) {
        V_LOG_ERROR("getaddrinfo error: %s", gai_strerror(adrrinfo_status));
        V_LOG_ERROR("possibility host argument provided wrong. Host argument saved was: %s",
                    config.host);
        return CONNECTION_FAILURE;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
        V_LOG_INFO("client: Attempting to connect to %s", s);

        if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            V_LOG_ERROR("Socket was not created, trying again");
            continue;
        }

        if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock_fd);
            V_LOG_ERROR("Connection failed, trying again");
            continue;
        }

        break;
    }

    if (p == NULL) {
        V_LOG_ERROR("Failed to connect");
        freeaddrinfo(servinfo);
        return CONNECTION_FAILURE;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    V_LOG_INFO("Succesfully connected to %s", s);

    freeaddrinfo(servinfo);

    return sock_fd;
}

/*
Description:
    Creates and sends request to server using the socket and configuration.
Arguments:
    int sockfd: Socket file descriptor
    Config config: A config struct with the necessary information.
Return value:
    Returns a 1 on failure, 0 on success
*/
int tcp_client_send_request(int sockfd, Config config) {
    unsigned long buff_size =
        strlen(config.action) + strlen(config.message) + 10; // big enough for ACTION LENGTH MESSAGE
    char buffer[buff_size];
    long r_code;

    memset(buffer, 0, sizeof(buffer));

    sprintf(buffer, "%s %ld %s", config.action, strlen(config.message), config.message);

    r_code = send(sockfd, buffer, strlen(buffer), 0);
    if (r_code < 0) {
        V_LOG_ERROR("Error while sending msg to server.  Error code: %d", errno);
        return EXIT_FAILURE;
    }
    if (r_code < (long)strlen(buffer)) {
        V_LOG_WARNING("Not all bits sent to server.  Expected to send: %d, only sent: %ld",
                      strlen(buffer), r_code);
        return EXIT_FAILURE;
    }

    V_LOG_INFO("Request succesfully sent to server..");
    return EXIT_SUCCESS;
}

/*
Description:
    Receives the response from the server. The caller must provide an already allocated buffer.
Arguments:
    int sockfd: Socket file descriptor
    char *buf: An already allocated buffer to receive the response in
    int buf_size: The size of the allocated buffer
Return value:
    Returns a 1 on failure, 0 on success
*/
int tcp_client_receive_response(int sockfd, char *buf, int buf_size) {
    // Receive a reply from the server
    if (recv(sockfd, buf, buf_size, 0) < 0) {
        V_LOG_ERROR("Error receiving message from server.");
        return EXIT_FAILURE;
    }

    V_LOG_INFO("Recieved response from server..");
    return EXIT_SUCCESS;
}

/*
Description:
    Closes the given socket.
Arguments:
    int sockfd: Socket file descriptor
Return value:
    Returns a 1 on failure, 0 on success
*/
int tcp_client_close(int sockfd) {

    if (close(sockfd)) {
        V_LOG_ERROR("Unable to close socket.");
        return EXIT_FAILURE;
    }

    V_LOG_INFO("Closed socket..");
    return EXIT_FAILURE;
}