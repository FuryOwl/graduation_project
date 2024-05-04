#include <iostream>
#include <string>
#include "nlohmann/json.hpp"
#include <locale>
#include <cstring> // For memset
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32 // Compilation for Windows
#include "getopt_win32.h" // Alternative implementation getopt() for Windows
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#else // Compilation for UNIX
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

void initializeNetwork() {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed with error: " << result << std::endl;
        exit(1);
    }
#endif
}

void cleanupNetwork() {
#ifdef _WIN32
    WSACleanup();
#endif
}

void closeSocket(int sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

void initializeSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanupSSL() {  // Принимаем ctx как аргумент
    EVP_cleanup();  // Очищаем все дайджесты, шифры и другие алгоритмы
    ERR_free_strings();  // Освобождаем все строки ошибок
    CRYPTO_cleanup_all_ex_data();  // Очищаем все данные ex_data
    SSL_COMP_free_compression_methods();  // Освобождаем таблицу методов сжатия SSL/TLS
}

SSL_CTX* createSSLContext() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

SSL* connectToServerWithSSL(const char* hostname, int port, SSL_CTX* ctx) {
    struct addrinfo hints{}, *res, *p;
    int sock = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(port);
    if (getaddrinfo(hostname, portStr.c_str(), &hints, &res) != 0) {
        perror("getaddrinfo failed");
        return nullptr;
    }

    for (p = res; p != nullptr; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) {
            perror("Cannot create socket");
            continue;
        }

        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            perror("Connection error");
            closeSocket(sock);
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) != 1) {
            std::cerr << "SSL_connect failed." << std::endl;
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            closeSocket(sock);
            continue;
        }

        freeaddrinfo(res);
        return ssl;
    }

    freeaddrinfo(res);
    std::cerr << "Failed to connect or establish SSL." << std::endl;
    return nullptr;
}

void PrintHelp() {
    std::cout << "Usage: client.exe -s [Student Name] -m [Mark] -i [ServerIP] -p [ServerPort]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -s, --student   Student's full name." << std::endl;
    std::cout << "  -m, --mark      Student's mark (0-100)." << std::endl;
    std::cout << "  -i, --ip        Server IP address." << std::endl;
    std::cout << "  -p, --port      Server port number." << std::endl;
    std::cout << "  -h, --help      Display this help message." << std::endl;
}

std::string serializeDataToJson(const std::string& name, int mark) {
    nlohmann::json jsonData;
    jsonData["name"] = name;
    jsonData["mark"] = mark;
    return jsonData.dump();
}

int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "");

    std::string studentName, server_ip, server_port;
    int studentMark = -1;

    const option long_options[] = {
        { "student",    required_argument,  nullptr,    's' },
        { "mark",       required_argument,  nullptr,    'm' },
        { "ip",         required_argument,  nullptr,    'i' },
        { "port",       required_argument,  nullptr,    'p' },
        { "help",       no_argument,        nullptr,    'h' },
        { nullptr,      0,                  nullptr,     0  }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "s:m:i:p:h", long_options, nullptr)) != -1) {
        switch (opt) {
        case 's':
            studentName = optarg;
            break;
        case 'm':
            studentMark = std::stoi(optarg);
            if (studentMark < 0 || studentMark > 100) {
                std::cerr << "Error: Mark must be between 0 and 100." << std::endl;
                return 1;
            }
            break;
        case 'i':
            server_ip = optarg;
            break;
        case 'p':
            server_port = optarg;
            break;
        case 'h':
            PrintHelp();
            return 0;
        default:
            std::cerr << "Invalid option or missing argument. Use -h for help." << std::endl;
            return 1;
        }
    }

    if (studentName.empty() || studentMark == -1 || server_ip.empty() || server_port.empty()) {
        std::cerr << "Error: All parameters are required." << std::endl;
        PrintHelp();
        return 1;
    }

    initializeNetwork();
    initializeSSL();
    SSL_CTX* ctx = createSSLContext();

    SSL* ssl = connectToServerWithSSL(server_ip.c_str(), std::stoi(server_port), ctx);
    if (!ssl) {
        std::cerr << "Failed to connect to the server with SSL." << std::endl;
        SSL_CTX_free(ctx);
        cleanupSSL();
        cleanupNetwork();
        return 1;
    }

    std::string jsonData = serializeDataToJson(studentName, studentMark);
    std::cout << "Serialized JSON: " << jsonData << std::endl;

    int bytes_sent = SSL_write(ssl, jsonData.c_str(), jsonData.length());
    if (bytes_sent <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_sent);
        std::cerr << "SSL_write failed with error code: " << ssl_error << std::endl;
        ERR_print_errors_fp(stderr);  // Расширенная диагностика ошибок
    }
    else {
        std::cout << "Data sent successfully: " << bytes_sent << " bytes." << std::endl;

        // Чтение ответа от сервера
        char response[1024];
        int bytes_received = SSL_read(ssl, response, sizeof(response) - 1);
        if (bytes_received > 0) {
            response[bytes_received] = '\0';  // Добавляем завершающий нулевой символ для корректной работы со строкой
            std::cout << "Server response: " << response << std::endl;
        } else {
            int ssl_error = SSL_get_error(ssl, bytes_received);
            std::cerr << "SSL_read failed with error code: " << ssl_error << std::endl;
            ERR_print_errors_fp(stderr);
        }
        bytes_received = SSL_read(ssl, response, sizeof(response) - 1);
        if (bytes_received > 0) {
            response[bytes_received] = '\0';  // Добавляем завершающий нулевой символ для корректной работы со строкой
            std::cout << "Server response: " << response << std::endl;
        } else {
            int ssl_error = SSL_get_error(ssl, bytes_received);
            std::cerr << "SSL_read failed with error code: " << ssl_error << std::endl;
            ERR_print_errors_fp(stderr);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closeSocket(SSL_get_fd(ssl));
    SSL_CTX_free(ctx);
    cleanupSSL();
    cleanupNetwork();

    return 0;
}