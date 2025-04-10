#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/types.h>
//#include <sys/socket.h>
#include <winsock2.h>
//#include <netinet/in.h>
#include <Ws2tcpip.h>
//#include <arpa/inet.h>
#include <WinInet.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // 创建socket文件描述符
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 绑定端口
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 监听
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    std::cout << "Server is listening on port " << PORT << std::endl;

    // 接受客户端连接
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    std::cout << "Connected to client with IP: " << inet_ntoa(address.sin_addr)
              << " and port: " << ntohs(address.sin_port) << std::endl;

    // 接收客户端发送的文件名
    read(new_socket, buffer, BUFFER_SIZE);
    std::string filename(buffer);
    std::ifstream file(filename, std::ios::binary);

    if (!file.is_open()) {
        std::string error = "File not found";
        send(new_socket, error.c_str(), error.size(), 0);
        std::cerr << "Error: File not found" << std::endl;
    } else {
        // 发送文件数据
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        size_t bytes_sent = 0;

        while (!file.eof()) {
            file.read(buffer, BUFFER_SIZE);
            size_t bytes_read = file.gcount();
            send(new_socket, buffer, bytes_read, 0);
            bytes_sent += bytes_read;
        }

        std::cout << "Total bytes sent: " << bytes_sent << std::endl;
        file.close();
    }

    close(new_socket);
    close(server_fd);
    return 0;
}
