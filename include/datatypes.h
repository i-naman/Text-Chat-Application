struct Client {
    std::string host_name;
    std::string ip;
    std::string port;
    std::string addr;
    int msg_sent;
    int msg_received;
    int logged_in;
    int fd;
};

struct Message {
    std::string sender_ip;
    std::string sender_port;

    std::string text;

    std::string receiver_ip;
    std::string receiver_port;
};
