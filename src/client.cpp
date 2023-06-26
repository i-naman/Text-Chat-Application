#include <iostream>
#include <bits/stdc++.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <strings.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>

#include "../include/global.h"
#include "../include/logger.h"
#include "../include/client.h"
#include "../include/utils.h"

using namespace std;


/**
 * Send request to server
 * 
 * @param req Request to send
 * @param socket Server FD
*/
string send_request(string req, int socket) {
    int length = req.length();

    // Send request
    send(socket, (req+CRLF).c_str(), length+1, 0);
    //cout<< "Request Sent: "<<req<<endl;

    // Receive response
    char res_buf[BUFFER_SIZE+1];
    string response = "";
    while(true) {
        int bytes_received = recv(socket, res_buf, BUFFER_SIZE, 0);
        res_buf[bytes_received] = '\0';
        if(res_buf[bytes_received-1] == CRLF) {
            res_buf[bytes_received-1] = '\0';
            response.append(res_buf);
            break;
        }
        response.append(res_buf);
    }
    if(response == "") {
        throw "Unable to send request";
    }
    //cout << "Response Received: "<<response<<endl;
    return response;
}


/**
 * Establishes a connection to the server
 *
 * @param  server_ip IPv4 address of server
 * @param  server_port Port of server
 * @return File descriptor of socket which connects to server
 */
int login(const char* server_ip, const char* server_port, const char* client_port) {
    int fdsocket;
	struct addrinfo hints, *res;

	/* Set up hints structure */	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	/* Fill up address structures */	
	if (getaddrinfo(server_ip, server_port, &hints, &res) != 0)
		throw "getaddrinfo failed";

	/* Socket */
	fdsocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(fdsocket < 0)
		throw "Failed to create socket";
	
	/* Connect */
	if(connect(fdsocket, res->ai_addr, res->ai_addrlen) < 0)
		throw "Connect failed";
	
	freeaddrinfo(res);

    string response;
    try {
        /* Append client info to login request to get correct client port on the server side */
        string req = LOGIN;
        req += COMMAND_DELIMITER;
        // Append self IP
        req += get_self_ip();
        req += CLIENT_ATTRIBUTE_DELIMITER;
        req += string(client_port);
        req += CLIENT_ATTRIBUTE_DELIMITER;
        req += get_self_host();
        response = send_request(req, fdsocket);
    } catch(...) {
        throw "Unable to login";
    }

    if(response != SUCCESS) {
        throw "Request failed";
    }

	return fdsocket;
}


/**
 * Fetches the list of all clients currently connected to the server
 *
 * @param  serverFd File descriptor of socket which connects to server
 * @return Vector of all clients that are currently connected to the server
 */
void fetch_clients_from_server(int serverFd, vector<Client>* clients) {
    vector<Client> newClients;
    string response;
    try {
        response = send_request(LIST, serverFd);
    } catch(...) {
        throw "Unable to send request";
    }
    string clientData;
    stringstream ss(response);

    while(getline(ss, clientData, CLIENT_DELIMITER)){
        string component;
        stringstream ss2(clientData);
        Client client;
        // IP
        getline(ss2, component, CLIENT_ATTRIBUTE_DELIMITER);
        client.ip = component;
        // Port
        getline(ss2, component, CLIENT_ATTRIBUTE_DELIMITER);
        client.port = component;
        // HostName
        getline(ss2, component, CLIENT_ATTRIBUTE_DELIMITER);
        client.host_name = component;
        // Status
        getline(ss2, component, CLIENT_ATTRIBUTE_DELIMITER);
        client.logged_in = atoi(component.c_str());
        // Full address
        client.addr = client.ip + CLIENT_ATTRIBUTE_DELIMITER + client.port;
        newClients.push_back(client);
    }
    *clients = newClients;
}


/**
 * Frames and parses a single message received from the server
 *
 * @param serverFd File descriptor of socket which connects to server
 * @return Message object
*/
Message read_message(int socket) {
    // Receive response
    char res_buf[BUFFER_SIZE+1];
    string response = "";
    while(true) {
        int bytes_received = recv(socket, res_buf, BUFFER_SIZE, 0);
        res_buf[bytes_received] = '\0';
        if(res_buf[bytes_received-1] == CRLF) {
            res_buf[bytes_received-1] = '\0';
            response.append(res_buf);
            break;
        }
        response.append(res_buf);
    }
    if(response == "") {
        throw "Unable to receive message";
    }

    Message message;
    string component;
    stringstream ss(response);
    // Sender IP
    getline(ss, component, CLIENT_ATTRIBUTE_DELIMITER);
    message.sender_ip = component;
    // Sender Port
    getline(ss, component, CLIENT_ATTRIBUTE_DELIMITER);
    message.sender_port = component;
    // Receiver IP
    getline(ss, component, CLIENT_ATTRIBUTE_DELIMITER);
    message.receiver_ip = component;
    // Receiver Port
    getline(ss, component, CLIENT_ATTRIBUTE_DELIMITER);
    message.receiver_port = component;
    // Message
    getline(ss, component, CLIENT_ATTRIBUTE_DELIMITER);
    int msg_start = message.sender_ip.length()+1+message.sender_port.length()+1+message.receiver_ip.length()+1+message.receiver_port.length()+1;
    message.text = response.substr(msg_start, response.length()-msg_start);
    return message;
}


/**
 * Fetches the messages stored in the server's buffer for this client
 *
 * @param  serverFd File descriptor of socket which connects to server
 * @return Vector of all messages that are stored in server's buffer
 */
void fetch_messages_from_server(int serverFd, vector<Message>* msg_ptr) {
    vector<Message> messages;
    string response;
    try {
        response = send_request(GET_MESSAGES, serverFd);
    } catch(...) {
        throw "Unable to send request";
    }
    if(response == "") {
        *msg_ptr = messages;
        return;
    }
    stringstream ss0(response);
    string msgStr;
    int msg_start_index = response.find(MSG_DELIMITER);
    response = response.substr(msg_start_index+strlen(MSG_DELIMITER), response.length() - (msg_start_index+strlen(MSG_DELIMITER)));
    while(response.find(MSG_DELIMITER) != string::npos) {
        Message message;
        string component;
        // Fetch message component
        msg_start_index = response.find(MSG_DELIMITER);
        msgStr = response.substr(0, msg_start_index);
        response = response.substr(msg_start_index+strlen(MSG_DELIMITER), response.length() - (msg_start_index+strlen(MSG_DELIMITER)));
        
        stringstream ss(msgStr);
        // Sender IP
        getline(ss, component, CLIENT_ATTRIBUTE_DELIMITER);
        message.sender_ip = component;
        // Sender Port
        getline(ss, component, CLIENT_ATTRIBUTE_DELIMITER);
        message.sender_port = component;
        // Receiver IP
        getline(ss, component, CLIENT_ATTRIBUTE_DELIMITER);
        message.receiver_ip = component;
        // Receiver Port
        getline(ss, component, CLIENT_ATTRIBUTE_DELIMITER);
        message.receiver_port = component;
        // Message
        getline(ss, component, CLIENT_ATTRIBUTE_DELIMITER);
        int msg_start = message.sender_ip.length()+1+message.sender_port.length()+1+message.receiver_ip.length()+1+message.receiver_port.length()+1;
        message.text = msgStr.substr(msg_start, msgStr.length()-msg_start);

        messages.push_back(message);
    }
    *msg_ptr = messages;
}


void logout(int serverFd) {
    string response;
    try {
        response = send_request(LOGOUT, serverFd);
    } catch(...) {
        throw "Unable to logout";
    }
    if(response != SUCCESS) {
        throw "Request failed";
    }
}


/**
 * Exit gracefully
 *
 * @param  serverFd File descriptor of socket which connects to server
 */
void final_exit(int serverFd) {
    string response;
    try {
        response = send_request(EXIT, serverFd);
    } catch(...) {
        return;
    }
}


/**
 * Main client process
 *
 * @param port Port on which client runs
*/
void run_client(char* port) {
    fd_set master;    // master file descriptor list
    fd_set read_fds;  // temp file descriptor list for select()
    int fdmax;        // maximum file descriptor number

    FD_ZERO(&master);    // clear the master and temp sets
    FD_ZERO(&read_fds);

    FD_SET(STDIN, &master); // Add stdin to file descriptor list
    fdmax = STDIN;

    int serverFd = -1;        // Socket which connects to server
    struct sockaddr_storage serveraddr; // server address
    socklen_t addrlen;

    char buf[2000];    // buffer for data from server
    int nbytes;

    char remoteIP[INET6_ADDRSTRLEN];

    vector<Client> clients;

    while(true) {
        fflush(stdout);
        read_fds = master; // copy the master socket descriptor set
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            throw "Error in selecting";
            exit(4);
        }

        // Read from stdin
        if(FD_ISSET(STDIN, &read_fds)) {
            // Get the command
            fgets(buf, sizeof(buf), stdin);
            string command = string(buf, strlen(buf) - 1);
            //cout<<"COMMAND: "<<command<<endl;

            if(command == "AUTHOR") { // AUTHOR command
                cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                cse4589_print_and_log(AUTHOR_MESSAGE);
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else if(command == "IP") { // IP command
                try {
                    string ip = get_self_ip();
                    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                    cse4589_print_and_log("IP:%s\n", ip.c_str());
                } catch(...) {
                    cse4589_print_and_log("[%s:ERROR]\n", command.c_str());
                }
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else if(command == "PORT") { // PORT command
                cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                cse4589_print_and_log("PORT:%s\n", port);
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else if(command == "LIST") { // LIST command
                cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                print_client_list(clients);
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else if(command.find("LOGIN") != string::npos) { // LOGIN command
                istringstream ss(command);
                ss >> command;
                // Get the input IP address
                string server_ip;
                ss >> server_ip;
                // Get the input port
                string server_port;
                ss >> server_port;

                try {
                    if(!(validate_ip(server_ip) && validate_port(server_port))) throw server_ip; // Throw an error if server IP address or port are invalid

                    // Connect to server
                    serverFd = login(server_ip.c_str(), server_port.c_str(), port);
                    FD_SET(serverFd, &master);
                    fdmax = serverFd;

                    // Fetch client list from server
                    fetch_clients_from_server(serverFd, &clients);

                    // Fetch messages from server from its buffer
                    vector<Message> messages;
                    fetch_messages_from_server(serverFd, &messages);

                    // Trigger RECEIVED event for all messages
                    for(int i=0; i<messages.size(); i++) {
                        Message message = messages[i];
                        cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
                        cse4589_print_and_log("msg from:%s\n[msg]:%s\n", message.sender_ip.c_str(), message.text.c_str());
                        cse4589_print_and_log("[%s:END]\n", "RECEIVED");
                    }

                    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str()); // If flow reaches here, then our login is successful
                } catch(...) {
                    cse4589_print_and_log("[%s:ERROR]\n", command.c_str());
                }
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else if(command == "REFRESH") { // REFRESH command
                try {
                    fetch_clients_from_server(serverFd, &clients);
                    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                } catch(...) {
                    cse4589_print_and_log("[%s:ERROR]\n", command.c_str());
                }
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else if(command.find("SEND") != string::npos) { // SEND command
                try {
                    command = command.substr(5, command.length()-5); // Remove SEND keyword and space
                    string sender_ip = get_self_ip();
                    string sender_port = string(port, strlen(port));
                    // Get the receiver IP address
                    int space_idx = command.find(" ");
                    string receiver_ip = command.substr(0, space_idx);
                    if(!validate_ip(receiver_ip)) throw receiver_ip;
                    bool found = false;
                    for(int i=0;i<clients.size();i++) {
                        if(clients[i].ip == receiver_ip && clients[i].logged_in == 1) {
                            found = true;
                            break;
                        }
                    }
                    if(!found) {
                        throw "Client not logged in/does not exist";
                    }
                    string receiver_port = "-1";
                    string message = command.substr(space_idx+1, command.length()-space_idx-1);
                    // if(message.length() > MSG_SIZE) {
                    //     message = message.substr(0, MSG_SIZE);
                    // }
                    //cout<<"Message at sender side: "<<message<<endl;
                    try {
                        /* Append client info to login request to get correct client port on the server side */
                        string req = SEND;
                        req += COMMAND_DELIMITER;
                        // Append self IP
                        req += sender_ip;
                        req += CLIENT_ATTRIBUTE_DELIMITER;
                        req += sender_port;
                        req += CLIENT_ATTRIBUTE_DELIMITER;
                        req += receiver_ip;
                        req += CLIENT_ATTRIBUTE_DELIMITER;
                        req += receiver_port;
                        req += CLIENT_ATTRIBUTE_DELIMITER;
                        req += message;
                        string response = send_request(req, serverFd);
                        if(response == FAILURE) throw "500: Server error";
                    } catch(...) {
                        throw "Unable to send message";
                    }
                    cse4589_print_and_log("[%s:SUCCESS]\n", SEND);
                } catch(...) {
                    cse4589_print_and_log("[%s:ERROR]\n", SEND);
                }
                cse4589_print_and_log("[%s:END]\n", SEND);
            } else if(command.find("BROADCAST") != string::npos) { // BROADCAST command
                try {
                    string message = command.substr(10, command.length()-10); // Remove SEND keyword and space
                    string sender_ip = get_self_ip();
                    string sender_port = string(port, strlen(port));
                    // if(message.length() > MSG_SIZE) {
                    //     message = message.substr(0, MSG_SIZE);
                    // }
                    try {
                        /* Append client info to login request to get correct client port on the server side */
                        string req = BROADCAST;
                        req += COMMAND_DELIMITER;
                        req += message;
                        string response = send_request(req, serverFd);
                        if(response == FAILURE) throw "500: Server error";
                    } catch(...) {
                        throw "Unable to send message";
                    }
                    cse4589_print_and_log("[%s:SUCCESS]\n", BROADCAST);
                } catch(...) {
                    cse4589_print_and_log("[%s:ERROR]\n", BROADCAST);
                }
                cse4589_print_and_log("[%s:END]\n", BROADCAST);
            } else if(command.find("UNBLOCK") != string::npos) { // UNBLOCK command
                try {
                    istringstream ss(command);
                    ss >> command;
                    // Get the receiver IP address
                    string blocked_ip;
                    ss >> blocked_ip;
                    if(!validate_ip(blocked_ip)) throw blocked_ip;
                    bool found = false;
                    for(int i=0;i<clients.size();i++) {
                        if(clients[i].ip == blocked_ip && clients[i].logged_in == 1) {
                            found = true;
                            break;
                        }
                    }
                    if(!found) {
                        throw "Client not logged in/does not exist";
                    }
                    try {
                        string req = UNBLOCK;
                        req += COMMAND_DELIMITER;
                        req += blocked_ip;
                        string response = send_request(req, serverFd);
                        if(response == FAILURE) throw "500: Server error";
                    } catch(...) {
                        throw "Unable to unblock";
                    }
                    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                } catch(...) {
                    cse4589_print_and_log("[%s:ERROR]\n", command.c_str());
                }
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else if(command.find("BLOCK") != string::npos) { // BLOCK command
                try {
                    istringstream ss(command);
                    ss >> command;
                    // Get the receiver IP address
                    string blocked_ip;
                    ss >> blocked_ip;
                    if(!validate_ip(blocked_ip)) throw blocked_ip;
                    bool found = false;
                    for(int i=0;i<clients.size();i++) {
                        if(clients[i].ip == blocked_ip && clients[i].logged_in == 1) {
                            found = true;
                            break;
                        }
                    }
                    if(!found) {
                        throw "Client not logged in/does not exist";
                    }
                    try {
                        string req = BLOCK;
                        req += COMMAND_DELIMITER;
                        req += blocked_ip;
                        string response = send_request(req, serverFd);
                        if(response == FAILURE) throw "500: Server error";
                    } catch(...) {
                        throw "Unable to block";
                    }
                    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                } catch(...) {
                    cse4589_print_and_log("[%s:ERROR]\n", command.c_str());
                }
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else if(command == "LOGOUT") { // LOGOUT command
                try {
                    logout(serverFd);
                    close(serverFd); // close socket
                    FD_CLR(serverFd, &read_fds);
                    FD_CLR(serverFd, &master);
                    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                } catch(...) {
                    cse4589_print_and_log("[%s:ERROR]\n", command.c_str());
                }
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else if(command == "EXIT") { // EXIT command
                try {
                    final_exit(serverFd); // delete client data on server
                    try {
                        close(serverFd); // close socket
                        FD_CLR(serverFd, &read_fds);
                        FD_CLR(serverFd, &master);
                    } catch(...) {
                        // Do nothing
                    }
                    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                    cse4589_print_and_log("[%s:END]\n", command.c_str());
                    exit(0); // Exit program
                } catch(...) {
                    cse4589_print_and_log("[%s:ERROR]\n", command.c_str());
                    cse4589_print_and_log("[%s:END]\n", command.c_str());
                }
            } else {
                throw "Wrong command";
                exit(4);
            }
        }

        // Read message from server (when RECEIVED event occurs)
        if(FD_ISSET(serverFd, &read_fds)) {
            Message message = read_message(serverFd);
            cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
            cse4589_print_and_log("msg from:%s\n[msg]:%s\n", message.sender_ip.c_str(), message.text.c_str());
            cse4589_print_and_log("[%s:END]\n", "RECEIVED");
        }
    }
}

