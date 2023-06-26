#include <iostream>
#include <bits/stdc++.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>

#include "../include/global.h"
#include "../include/logger.h"
#include "../include/utils.h"

using namespace std;

bool validate_ip(string ip) {
    string block;
    stringstream ss(ip);
    vector<string> blocks;

    while(getline(ss, block, '.')){
        blocks.push_back(block);
    }

    if(blocks.size() != 4) return false;

    for(int i=0; i<blocks.size(); i++) {
        block = blocks[i];
        try {
            int block_num = atoi(block.c_str());
            if(block_num < 0 || block_num > 255) {
                return false;
            }
        } catch(...) { // Return false if error occurs in string to integer conversion
            return false;
        }
    }
    return true;
}

bool validate_port(string port) {
    try {
        int port_num = atoi(port.c_str());
        if(port_num < 1024 || port_num > 49151) {
            // Reserved and private ports not allowed
            return false;
        }
    } catch(...) { // Return false if error occurs in string to integer conversion
        return false;
    }
    return true;
}

/**
 * Gets the hostname of self
 * @return Hostname of self
*/
string get_self_host() {
    char hostname[MAX_HOSTNAME_LEN];
    gethostname(hostname, MAX_HOSTNAME_LEN);
    return string(hostname, strlen(hostname));
}

/**
 * Gets the IP address of self
 * @return IPv4 address of self
*/
string get_self_ip() {
    char ip[IP_LEN];
    char hostname[MAX_HOSTNAME_LEN];
    struct hostent *ht;

    if (gethostname(hostname, MAX_HOSTNAME_LEN) == 0)
    {
        if ((ht = gethostbyname(hostname)) != NULL)
        {
            strcpy(ip, inet_ntoa(*((struct in_addr *)ht->h_addr)));
        }
    }
    return string(ip, strlen(ip));
}

/**
 * Format and prints a list of clients neatly
 * @param clients List of clients to print
*/
void print_client_list(vector<Client> clients) {
    for(int list_id=1;list_id<=clients.size();list_id++) { // Iterate over all clients
        Client c = clients[list_id-1];
        if(c.logged_in == 0) continue; // Don't print if client not logged in
        cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", list_id, c.host_name.c_str(), c.ip.c_str(), atoi(c.port.c_str()));
    }
}


/**
 * Format and prints server statistics
 * @param clients List of clients
*/
void print_statistics(vector<Client> clients) {
    for(int list_id=1;list_id<=clients.size();list_id++) { // Iterate over all clients
        Client c = clients[list_id-1];
        string status;
        if(c.logged_in == 1) status = "logged-in";
        else status = "logged-out";

        cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", list_id, c.host_name.c_str(), c.msg_sent, c.msg_received, status.c_str());
    }
}


/**
 * Gets the IP address from sockaddr object
 * @param sa Pointer to the sockaddr object
*/
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/**
 * Gets the port from sockaddr object
 * @param sa Pointer to the sockaddr object
*/
in_port_t get_in_port(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return (((struct sockaddr_in*)sa)->sin_port);

    return (((struct sockaddr_in6*)sa)->sin6_port);
}

/**
 * Gets the hostname from sockaddr object
 * @param sa Pointer to the sockaddr object
*/
string get_hostname(struct sockaddr *sa) {
    char hostname[NI_MAXHOST];
    char servInfo[NI_MAXSERV];
    getnameinfo(sa, sizeof (struct sockaddr),
                hostname, NI_MAXHOST,
                servInfo, NI_MAXSERV, NI_NUMERICSERV);
    
    return string(hostname, strlen(hostname));
}


/**
 * Gets the IP, port and hostname of a client
 * 
 * @param clientaddr A sockaddr pointer containing info of client address
 * @param client Pointer to the Client object where we want to store the extracted data
*/
void get_client_info(struct sockaddr* clientaddr, Client* client) {
    char clientIP[INET6_ADDRSTRLEN];
    client->ip = inet_ntop(clientaddr->sa_family, get_in_addr(clientaddr), clientIP, INET6_ADDRSTRLEN);
    client->host_name = get_hostname(clientaddr);
    client->port = "0000"; /* HACK: We'll inject port later from login request */
}

/**
 * Comparator to sort clients by ports
*/
bool client_sorter(Client const& A, Client const& B) {
    int port_A = atoi(A.port.c_str());
    int port_B = atoi(B.port.c_str());
    if(port_A < port_B) return true;
    return false;
}

