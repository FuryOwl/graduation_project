#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <thread>
#include "nlohmann/json.hpp"
#include "sqlite3.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <openssl/applink.c>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define SOCKET int
#define INVALID_SOCKET (SOCKET)(~0)
#define SOCKET_ERROR -1
#endif

const unsigned short SERVER_PORT = 8080;
const int MAX_CONNECTIONS = 10;

sqlite3* db;

bool initializeDatabase() {
    if (sqlite3_open("students.db", &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    const char* createStudentsTable = 
        "CREATE TABLE IF NOT EXISTS Students ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "Name TEXT NOT NULL);";

    const char* createMarksTable = 
        "CREATE TABLE IF NOT EXISTS Marks ("
        "StudentID INTEGER, "
        "Mark INTEGER, "
        "FOREIGN KEY(StudentID) REFERENCES Students(ID));";

    char* errMsg;
    if (sqlite3_exec(db, createStudentsTable, nullptr, nullptr, &errMsg) != SQLITE_OK ||
        sqlite3_exec(db, createMarksTable, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Failed to create tables: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

bool insertStudentAndMark(const std::string& name, int mark) {
    const char* insertStudentQuery = "INSERT INTO Students (Name) VALUES (?);";
    const char* insertMarkQuery = "INSERT INTO Marks (StudentID, Mark) VALUES (last_insert_rowid(), ?);";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, insertStudentQuery, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare insert student statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to insert student: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);

    if (sqlite3_prepare_v2(db, insertMarkQuery, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare insert mark statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    sqlite3_bind_int(stmt, 1, mark);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to insert mark: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

void initializeSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* createSSLContext() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "E:/Projects/cpp_projects/Project3/x64/Release/server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "E:/Projects/cpp_projects/Project3/x64/Release/private.key", SSL_FILETYPE_PEM) <= 0) {
        std::cout << "POINT" << std::endl;
        ERR_print_errors_fp(stderr);
        std::cout << "POINT" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match the public certificate" << std::endl;
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void cleanupSSL() {
    EVP_cleanup();
}

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize winsock" << std::endl;
        return EXIT_FAILURE;
    }
#endif

    initializeSSL();
    SSL_CTX* ctx = createSSLContext();

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket" << std::endl;
        return EXIT_FAILURE;
    }

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(SERVER_PORT);

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        std::cerr << "Failed to bind socket" << std::endl;
        return EXIT_FAILURE;
    }

    if (listen(serverSocket, MAX_CONNECTIONS) == SOCKET_ERROR) {
        std::cerr << "Failed to listen on socket" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Server started on port " << SERVER_PORT << ". Waiting for connections..." << std::endl;

    while (true) {
        sockaddr_in clientAddress{};
        socklen_t clientAddressSize = sizeof(clientAddress);
        SOCKET clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressSize);
        if (clientSocket == INVALID_SOCKET) {
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientSocket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            continue;
        }

        std::thread([ssl]() {
            char buffer[1024];
            int bytes = SSL_read(ssl, buffer, sizeof(buffer));
            if (bytes > 0) {
                buffer[bytes] = '\0';
                std::cout << "Received: " << buffer << std::endl;
                try {
                    std::string response = "Data successfully loaded.";
                    SSL_write(ssl, response.c_str(), response.length());

                    auto json = nlohmann::json::parse(buffer);
                    std::string name = json["name"];
                    int mark = json["mark"];
                    std::cout << "Processed: Name - " << name << ", Mark - " << mark << std::endl;

                    if (initializeDatabase()) {
                        if (insertStudentAndMark(name, mark)) {
                            std::string response = "Data successfully saved to the database.";
                            SSL_write(ssl, response.c_str(), response.length());  // Отправка подтверждения клиенту
                        } else {
                            std::string response = "Failed to save data.";
                            SSL_write(ssl, response.c_str(), response.length());  // Отправка ошибки клиенту
                        }
                    }

                } catch (std::exception& e) {
                    std::cerr << "Error parsing JSON: " << e.what() << std::endl;
                    std::string response = "Error parsing JSON";
                    SSL_write(ssl, response.c_str(), response.length());  // Отправка ошибки клиенту
                }
            } else if (bytes < 0) {
                std::cerr << "SSL_read failed." << std::endl;
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
        }).detach();

    }

    SSL_CTX_free(ctx);
    cleanupSSL();

#ifdef _WIN32
    closesocket(serverSocket);
    WSACleanup();
#else
    close(serverSocket);
#endif

    return 0;
}