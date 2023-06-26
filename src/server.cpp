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
#include "../include/server.h"
#include "../include/utils.h"

using namespace std;


/**
 * Reads a request from client
 *
 * @param socket File descriptor of client
 * 
 * @return request string
*/
string read_request(int socket) {
    char req_buf[BUFFER_SIZE+1];
    string req = "";
    while(true) {
        int bytes_received = recv(socket, req_buf, BUFFER_SIZE, 0);
        req_buf[bytes_received] = '\0';
        if(req_buf[bytes_received-1] == CRLF) {
            req_buf[bytes_received-1] = '\0';
            req.append(req_buf);
            break;
        }
        req.append(req_buf);
    }
    //cout<<"Request received: "<<req<<endl;
    return req;
}


/**
 * Prepares appropriate response string
 *
 * @param req Request string
 * @param source Pointer to store the source client FD
 * @param target Pointer to store the target client FD
 * 
 * @return response string
*/
string prepare_response(string req, int* source, int* target, vector<Client> clients) {
    if(req.find(LOGIN) != string::npos || req == LOGOUT || req == EXIT) {
        *target = *source;
        return SUCCESS;
    } else if(req == LIST) {
        *target = *source;
        string response = "";
        for(int i=0;i<clients.size();i++) {
            response += clients[i].ip;
            response += CLIENT_ATTRIBUTE_DELIMITER;
            response += clients[i].port;
            response += CLIENT_ATTRIBUTE_DELIMITER;
            response += clients[i].host_name;
            response += CLIENT_ATTRIBUTE_DELIMITER;
            stringstream status;
            status << clients[i].logged_in;
            response += status.str();
            response += CLIENT_DELIMITER;
        }
        return response;
    } else if(req.find(SEND) != string::npos) {
        return "";
    } else if(req.find(BROADCAST) != string::npos) {
        return "";
    } else if(req.find(BLOCK) != string::npos) { // Covers UNBLOCK too
        *target = *source;
        return SUCCESS;
    }
    return FAILURE;
}


/**
 * Main server process
 * Some of the snippet (especially select() function use) is based on the BEEJ's guide:
 *      https://beej.us/guide/bgnet/html/split/slightly-advanced-techniques.html#select
 *
 * @param port Port on which server runs
*/
void run_server(char* port) {
    fd_set master;    // master file descriptor list
    fd_set read_fds;  // temp file descriptor list for select()
    int fdmax;        // maximum file descriptor number

    FD_ZERO(&master);    // clear the master and temp sets
    FD_ZERO(&read_fds);

    int listener;     // listening socket descriptor
    int newfd;        // newly accepted socket descriptor
    struct sockaddr_storage clientaddr; // client address
    socklen_t addrlen;

    char buf[256];    // buffer for client data
    int nbytes;

    int rv;

    struct addrinfo hints, *ai, *p;

    /* Set up hints structure */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    /* Fill up address structures */
    if (getaddrinfo(NULL, port, &hints, &ai) != 0) {
        throw "getaddrinfo failed";
        exit(4);
    }
    /* Socket */
	listener = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if(listener < 0) {
        throw "Cannot create socket";
        exit(4);
    }
    /* Bind */
	if(bind(listener, ai->ai_addr, ai->ai_addrlen) < 0) {
        throw "Bind failed";
        exit(4);
    }

    freeaddrinfo(ai); // Free address info

    /* Listen */
	if(listen(listener, BACKLOG) < 0) {
        throw "Unable to listen on port";
        exit(4);
    }

    /* Register the listening socket */
    FD_SET(listener, &master);
    FD_SET(STDIN, &master); // Add stdin to file descriptor list
    fdmax = listener;

    vector<Client> clients; // List of currently logged in clients

    vector<Client> blocker; // List of clients who blocked someone else
    vector<Client> blocked; // List of clients blocked by clients in blocker

    vector<vector<Message> > bufferedMsg; // List of buffered messages for each client

    while(true) {
        fflush(stdout);
        read_fds = master; // Copy master list
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            throw "Error in selecting";
            exit(4);
        }

        // Read from STDIN
        if(FD_ISSET(STDIN, &read_fds)) {
            // Get the command
            fgets(buf, sizeof(buf), stdin);
            string command = string(buf, strlen(buf) - 1);

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
            } else if(command == "STATISTICS") {
                cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                print_statistics(clients);
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else if(command.find("BLOCKED") != string::npos) {
                try {
                    istringstream ss(command);
                    ss >> command;
                    // Get the input IP address
                    string blocker_ip;
                    ss >> blocker_ip;
                    if(!validate_ip(blocker_ip)) throw blocker_ip;
                    // Check if the client asked even exists or not
                    bool found = false;
                    for(int i=0;i<clients.size();i++) {
                        if(clients[i].ip == blocker_ip) {
                            found = true;
                            break;
                        }
                    }
                    if(!found) throw "Invalid IP";

                    // Get all blocked clients for this client
                    vector<Client> res;
                    for(int i=0;i<blocker.size();i++) {
                        if(blocker[i].ip == blocker_ip) {
                            res.push_back(blocked[i]);
                        }
                    }
                    cse4589_print_and_log("[%s:SUCCESS]\n", command.c_str());
                    std::sort(res.begin(), res.end(), &client_sorter);
                    print_client_list(res);
                } catch(...) {
                    cse4589_print_and_log("[%s:ERROR]\n", command.c_str());
                }
                cse4589_print_and_log("[%s:END]\n", command.c_str());
            } else {
                throw "Wrong command";
                exit(4);
            }
        }

        // Read from connected clients
        for(int client_fd=1; client_fd<=fdmax; client_fd++) {
            if(client_fd == listener || FD_ISSET(client_fd, &read_fds) == 0) continue;

            string request = read_request(client_fd);

            int target_fd = 0; // The target where response should be sent

            if(request.find(LOGIN) != string::npos) {
                // Add/Update client info/status in list of clients
                string client_info;
                stringstream ss(request);
                // LOGIN keyword
                getline(ss, client_info, COMMAND_DELIMITER);
                getline(ss, client_info, COMMAND_DELIMITER);

                string client_ip;
                string client_port;
                string client_host;
                stringstream ss2(client_info);
                getline(ss2, client_ip, CLIENT_ATTRIBUTE_DELIMITER);
                getline(ss2, client_port, CLIENT_ATTRIBUTE_DELIMITER);
                getline(ss2, client_host, CLIENT_ATTRIBUTE_DELIMITER);

                // Check if client is a new user
                bool is_new = true;
                for(int i=0; i<clients.size();i++) {
                    if(clients[i].ip == client_ip && clients[i].port == client_port) {
                        is_new = false;
                        clients[i].logged_in = 1;
                        clients[i].fd = client_fd;
                        break;
                    }
                }
                if(is_new) { // If new client, add to data structures
                    Client client;
                    client.logged_in = 1;
                    client.ip = client_ip;
                    client.port = client_port;
                    client.host_name = client_host;
                    client.addr = client.ip + CLIENT_ATTRIBUTE_DELIMITER + client.port;
                    client.msg_sent = 0;
                    client.msg_received = 0;
                    client.fd = client_fd;

                    clients.push_back(client);
                    vector<Message> clientBuffer;
                    bufferedMsg.push_back(clientBuffer);
                }
                // Sort clients by port
                std::sort(clients.begin(), clients.end(), &client_sorter);
            } else if(request == EXIT || request == "") {
                FD_CLR(client_fd, &read_fds);
                FD_CLR(client_fd, &master);
                string client_ip;
                for(int i=0;i<clients.size();i++) {
                    if(clients[i].fd == client_fd) {
                        client_ip = clients[i].ip;
                        clients.erase(clients.begin(), clients.begin()+i);
                        // Remove buffered messages waiting for this receiver
                        bufferedMsg.erase(bufferedMsg.begin(), bufferedMsg.begin()+i);
                        // Remove buffered messages from this sender
                        for(int j=0;j<bufferedMsg.size();j++) {
                            int buffer_length = bufferedMsg[j].size();
                            for(int k=0;k<buffer_length;k++) {
                                if(bufferedMsg[j][k].sender_port == clients[i].port && bufferedMsg[j][k].sender_ip == clients[i].ip) {
                                    bufferedMsg[j].erase(bufferedMsg[j].begin(), bufferedMsg[j].begin()+k);
                                    k--;
                                    buffer_length--;
                                }
                            }
                        }
                        break;
                    }
                }
                // Erase client from blocker and blocked lists
                int bs = blocker.size();
                for(int i=0;i<bs;i++) {
                    if(blocker[i].ip == client_ip || blocked[i].ip == client_ip) {
                        blocker.erase(blocker.begin(), blocker.begin()+i);
                        blocked.erase(blocked.begin(), blocked.begin()+i);
                        i--;
                    }
                }
            } else if(request == LOGOUT) {
                FD_CLR(client_fd, &read_fds);
                FD_CLR(client_fd, &master);
                // Remove from logged in clients
                for(int i=0;i<clients.size();i++) {
                    if(clients[i].fd == client_fd) {
                        clients[i].logged_in = 0;
                        clients[i].fd = -1;
                        break;
                    }
                }
            } else if(request.find(UNBLOCK) != string::npos) {
                string blocked_ip;
                stringstream ss(request);
                // UNBLOCK keyword
                getline(ss, blocked_ip, COMMAND_DELIMITER);
                getline(ss, blocked_ip, COMMAND_DELIMITER);

                Client blocker_client;
                Client blocked_client;
                bool found = false;
                for(int i=0;i<clients.size();i++) {
                    if(clients[i].fd == client_fd) {
                        blocker_client = clients[i];
                    }
                    if(clients[i].ip == blocked_ip) {
                        blocked_client = clients[i];
                        found = true;
                    }
                }
                if(!found) {
                    // Throw error if blocker or blocked not found
                    string response = FAILURE;
                    send(client_fd, (response+CRLF).c_str(), response.length()+1, 0);
                    continue;
                }
                found = false;
                // Find the blocker blocked pair
                vector<Client> newBlocker;
                vector<Client> newBlocked;
                for(int i=0;i<blocker.size();i++) {
                    if(blocker[i].ip==blocker_client.ip && blocked[i].ip==blocked_client.ip) {
                        found = true;
                        continue;
                    }
                    newBlocker.push_back(blocker[i]);
                    newBlocked.push_back(blocked[i]);
                    found = false;
                }
                if(!found) {
                    // No-one to unblock
                    string response = FAILURE;
                    send(client_fd, (response+CRLF).c_str(), response.length()+1, 0);
                    continue;
                }
                blocker = newBlocker;
                blocked = newBlocked;
            } else if(request.find(BLOCK) != string::npos) {
                string blocked_ip;
                stringstream ss(request);
                // BLOCKED keyword
                getline(ss, blocked_ip, COMMAND_DELIMITER);
                getline(ss, blocked_ip, COMMAND_DELIMITER);

                Client blocker_client;
                Client blocked_client;
                bool found = false;
                // Check if the client to block even exists or not
                for(int i=0;i<clients.size();i++) {
                    if(clients[i].fd == client_fd) {
                        blocker_client = clients[i];
                    }
                    if(clients[i].ip == blocked_ip) {
                        blocked_client = clients[i];
                        found = true;
                    }
                }
                if(!found) {
                    string response = FAILURE;
                    send(client_fd, (response+CRLF).c_str(), response.length()+1, 0);
                    continue;
                }
                // Throw error if client was already blocked
                for(int i=0;i<blocker.size();i++) {
                    if(blocker[i].ip == blocker_client.ip && blocked[i].ip == blocked_client.ip) {
                        found = false;
                        break;
                    }
                }
                if(!found) {
                    string response = FAILURE;
                    send(client_fd, (response+CRLF).c_str(), response.length()+1, 0);
                    continue;
                }
                blocker.push_back(blocker_client);
                blocked.push_back(blocked_client);
            } else if(request.find(BROADCAST) != string::npos) {
                string message = request.substr(10, request.length()-10);
                Client sender;
                // Find sender index
                int sender_idx;
                for(int i=0;i<clients.size();i++) {
                    if(clients[i].fd == client_fd) {
                        sender = clients[i];
                        sender_idx = i;
                        break;
                    }
                }
                string sender_response = SUCCESS;
                try {
                    // Iterate over all clients
                    for(int i=0;i<clients.size();i++) {
                        if(clients[i].fd == client_fd) continue;

                        Client receiver = clients[i];

                        // Checked if blocked
                        bool is_blocked = false;
                        for(int j=0;j<blocker.size();j++) {
                            if(blocker[j].ip == sender.ip && blocked[j].ip == receiver.ip) {
                                is_blocked = true;
                                break;
                            }
                            if(blocked[j].ip == sender.ip && blocker[j].ip == receiver.ip) {
                                is_blocked = true;
                                break;
                            }
                        }
                        if(is_blocked) continue; // Don't send further if blocked

                        // Prepare message string to send to receiver
                        string response = "";
                        response += sender.ip;
                        response += CLIENT_ATTRIBUTE_DELIMITER;
                        response += sender.port;
                        response += CLIENT_ATTRIBUTE_DELIMITER;
                        response += receiver.ip;
                        response += CLIENT_ATTRIBUTE_DELIMITER;
                        response += receiver.port;
                        response += CLIENT_ATTRIBUTE_DELIMITER;
                        response += message;

                        if(receiver.logged_in == 1) { // Send to receiver if logged in
                            send(receiver.fd, (response+CRLF).c_str(), response.length()+1, 0);
                            clients[i].msg_received += 1;
                        } else { // Buffer if client logged_out
                            Message temp;
                            temp.sender_ip = sender.ip;
                            temp.sender_port = sender.port;
                            temp.receiver_ip = "255.255.255.255";
                            temp.receiver_port = "0";
                            temp.text = message;
                            bufferedMsg[i].push_back(temp);
                        }
                    }
                    clients[sender_idx].msg_sent += 1;
                    cse4589_print_and_log("[RELAYED:SUCCESS]\n");
                    cse4589_print_and_log("msg from:%s, to:255.255.255.255\n[msg]:%s\n", sender.ip.c_str(), message.c_str());
                    sender_response = SUCCESS;
                } catch(...) {
                    sender_response = FAILURE;
                    cse4589_print_and_log("[RELAYED:ERROR]\n");
                }
                send(client_fd, (sender_response+CRLF).c_str(), sender_response.length()+1, 0);
                cse4589_print_and_log("[RELAYED:END]\n");
            } else if(request.find(SEND) != string::npos) {
                string component;
                stringstream ss(request);

                // Command
                getline(ss, component, COMMAND_DELIMITER);
                // Target IP
                getline(ss, component, COMMAND_DELIMITER);

                stringstream ss2(component);
                // Add metadata
                string sender_ip;
                getline(ss2, sender_ip, CLIENT_ATTRIBUTE_DELIMITER);
                string sender_port;
                getline(ss2, sender_port, CLIENT_ATTRIBUTE_DELIMITER);
                string receiver_ip;
                getline(ss2, receiver_ip, CLIENT_ATTRIBUTE_DELIMITER);
                string receiver_port;
                getline(ss2, receiver_port, CLIENT_ATTRIBUTE_DELIMITER);
                // Add message
                int msg_start = 4+1+sender_ip.length()+1+sender_port.length()+1+receiver_ip.length()+1+receiver_port.length()+1;
                string message = request.substr(msg_start, request.length()-msg_start);
                Client sender;
                int sender_idx;
                for(int i=0;i<clients.size();i++) {
                    if(clients[i].fd == client_fd) {
                        sender = clients[i];
                        sender_idx = i;
                        break;
                    }
                }
                string sender_response = SUCCESS;
                for(int i=0;i<clients.size();i++) {
                    if(clients[i].fd == client_fd || clients[i].ip != receiver_ip) continue;

                    Client receiver = clients[i];

                    // Checked if blocked
                    bool is_blocked = false;
                    for(int j=0;j<blocker.size();j++) {
                        if(blocker[j].ip == sender.ip && blocked[j].ip == receiver.ip) {
                            is_blocked = true;
                            break;
                        }
                        if(blocked[j].ip == sender.ip && blocker[j].ip == receiver.ip) {
                            is_blocked = true;
                            break;
                        }
                    }
                    if(is_blocked) continue; // Don't send further if blocked

                    // Prepare message string to send to receiver
                    string response = "";
                    response += sender.ip;
                    response += CLIENT_ATTRIBUTE_DELIMITER;
                    response += sender.port;
                    response += CLIENT_ATTRIBUTE_DELIMITER;
                    response += receiver.ip;
                    response += CLIENT_ATTRIBUTE_DELIMITER;
                    response += receiver.port;
                    response += CLIENT_ATTRIBUTE_DELIMITER;
                    response += message;

                    if(receiver.logged_in == 1) {
                        try { // Send to receiver if logged in
                            send(receiver.fd, (response+CRLF).c_str(), response.length()+1, 0);
                            clients[i].msg_received += 1;
                            cse4589_print_and_log("[RELAYED:SUCCESS]\n");
                            cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", sender.ip.c_str(), receiver_ip.c_str(), message.c_str());
                            cse4589_print_and_log("[RELAYED:END]\n");
                        } catch(...) {
                            sender_response = FAILURE;
                            cse4589_print_and_log("[RELAYED:ERROR]\n");
                            cse4589_print_and_log("[RELAYED:END]\n");
                            break;
                        }
                    } else { // Add to buffer if logged out
                        Message temp;
                        temp.sender_ip = sender.ip;
                        temp.sender_port = sender.port;
                        temp.receiver_ip = receiver.ip;
                        temp.receiver_port = receiver.port;
                        temp.text = message;
                        bufferedMsg[i].push_back(temp);
                    }
                }
                // Send SUCCESS response to client
                if(sender_response == SUCCESS) {
                    clients[sender_idx].msg_sent += 1;
                }
                send(client_fd, (sender_response+CRLF).c_str(), sender_response.length()+1, 0);
            } else if(request == GET_MESSAGES) {
                string response = SUCCESS;
                response += MSG_DELIMITER;
                Client sender;
                int receiver_idx;
                for(int i=0;i<clients.size();i++) {
                    if(clients[i].fd == client_fd) {
                        sender = clients[i];
                        receiver_idx = i;
                        break;
                    }
                }
                // Iterate over the message buffer for this client
                vector<Message> client_buffer = bufferedMsg[receiver_idx];
                for(int i=0;i<client_buffer.size();i++) {
                    // Skip if receiver has or is blocked
                    bool _is_blocked = false;
                    for(int j=0;j<blocked.size();j++) {
                        // Check if blocked or blocker
                        if(blocked[j].ip == sender.ip && blocker[j].ip == clients[receiver_idx].ip)
                        {
                            _is_blocked = true;
                            break;
                        }
                        if(blocker[j].ip == sender.ip && blocked[j].ip == clients[receiver_idx].ip)
                        {
                            _is_blocked = true;
                            break;
                        }
                    }
                    if(_is_blocked) continue; // Don't do anything if blocked
                    // Prepare to send message string (metadata and message)
                    Message msg = client_buffer[i];
                    response += msg.sender_ip;
                    response += CLIENT_ATTRIBUTE_DELIMITER;
                    response += msg.sender_port;
                    response += CLIENT_ATTRIBUTE_DELIMITER;
                    response += msg.receiver_ip;
                    response += CLIENT_ATTRIBUTE_DELIMITER;
                    response += msg.receiver_port;
                    response += CLIENT_ATTRIBUTE_DELIMITER;
                    response += msg.text;
                    response += MSG_DELIMITER;
                    clients[receiver_idx].msg_received += 1;
                    if(msg.receiver_port == "255.255.255.255") continue; // Dont print RELAYED log if it was a broadcast
                    // Print RELAYED log
                    cse4589_print_and_log("[RELAYED:SUCCESS]\n");
                    cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", msg.sender_ip.c_str(), clients[receiver_idx].ip.c_str(), msg.text.c_str());
                    cse4589_print_and_log("[RELAYED:END]\n");
                }
                send(client_fd, (response+CRLF).c_str(), response.length()+1, 0);
                bufferedMsg[receiver_idx].clear();
            }

            // Process request and prepare response
            string response = prepare_response(request, &client_fd, &target_fd, clients);
            if(response == "") continue;
            //cout<<"Response sent: "<<response<<endl;
            send(target_fd, (response+CRLF).c_str(), response.length()+1, 0);
        }

        // Read listener
        if(FD_ISSET(listener, &read_fds)) {
            // Accept a client connection
            addrlen = sizeof clientaddr;
            newfd = accept(listener, (struct sockaddr *)&clientaddr, &addrlen);
            if(newfd < 0) {
                throw "Accept failed";
                exit(4);
            }
            FD_SET(newfd, &master);
            if(newfd > fdmax) fdmax = newfd;
        }
    }
}
