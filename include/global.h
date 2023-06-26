#ifndef GLOBAL_H_
#define GLOBAL_H_

#define HOSTNAME_LEN 128
#define PATH_LEN 256

#define STDIN 0

#define TRUE 1
#define BUFFER_SIZE 10000
#define MSG_SIZE 256
#define BACKLOG 10

#define MAX_HOSTNAME_LEN 1024
#define IP_LEN 64

#define AUTHOR_MESSAGE "I, namanagr, have read and understood the course academic integrity policy.\n"

/* Request headers */
#define LOGIN "LOGIN"
#define LOGOUT "LOGOUT"
#define GET_MESSAGES "GET_MESSAGES"
#define LIST "LIST"
#define EXIT "EXIT"
#define SUCCESS "SUCCESS"
#define FAILURE "FAILURE"
#define SEND "SEND"
#define BROADCAST "BROADCAST"
#define BLOCK "BLOCK"
#define UNBLOCK "UNBLOCK"

/* Message delimiters */
#define COMMAND_DELIMITER '~'
#define CLIENT_ATTRIBUTE_DELIMITER ':'
#define CLIENT_DELIMITER '|'
#define MSG_DELIMITER "@@@&^**&^@"
#define CRLF '\r'

#endif
