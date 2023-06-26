#include <string>
#include "../include/datatypes.h"

bool validate_ip(std::string ip);
bool validate_port(std::string port);
std::string get_self_host();
std::string get_self_ip();
void print_client_list(std::vector<Client> clients);
void print_statistics(std::vector<Client> clients);
void get_client_info(struct sockaddr* clientaddr, Client* client);
bool client_sorter(Client const& A, Client const& B);
