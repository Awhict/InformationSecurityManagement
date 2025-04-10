#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main(int argc, char const *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <filename>" << std::endl;
        return -1;
    }

    const char *server_ip = argv[1];
    const char *filename = argv[2];
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    // 创建socket文件描述符
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // 转换IPv4和IPv6地址从文本到二进制
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return -1;
    }

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return -1;
    }

    // 发送文件名到服务器
    send(sock, filename, strlen(filename), 0);

    std::ofstream output_file("received_" + std::string(filename), std::ios::binary);
    size_t bytes_received = 0;

    while (true) {
        ssize_t n = read(sock, buffer, BUFFER_SIZE);
        if (n <= 0) break;
        output_file.write(buffer, n);
        bytes_received += n;
    }

    if (bytes_received == 0) {
        std::cerr << "Error: No data received or file not found on server" << std::endl;
    } else {
        std::cout << "New file name: " << "received_" + std::string(filename) << std::endl;
        std::cout << "Total bytes received: " << bytes_received << std::endl;
    }

    output_file.close();
    close(sock);
    return 0;
}
