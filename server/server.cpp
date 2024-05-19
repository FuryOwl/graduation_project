#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <thread>
#include <regex>
#include <mutex>
#include <atomic>
#include <csignal>
#include <conio.h>

#include "nlohmann/json.hpp"
#include "sqlite3.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <Python.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/applink.c>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#else
#include <termios.h>
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
std::atomic<bool> running(true);

void handleSignal(int signal) {
    if (signal == SIGINT) {
        running = false;
    }
}

#ifdef __linux__
void enableRawMode() {
    termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

void disableRawMode() {
    termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag |= (ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}
#endif

bool initializeDatabase() {
    // Открытия файла базы данных
    if (sqlite3_open("students.db", &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    // Формирование запроса для таблицы Students
    const char* createStudentsTable = 
        "CREATE TABLE IF NOT EXISTS Students ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "Name TEXT NOT NULL);";
    // Формирование запроса для таблицы Marks
    const char* createMarksTable = 
        "CREATE TABLE IF NOT EXISTS Marks ("
        "StudentID INTEGER, "
        "Mark INTEGER, "
        "FOREIGN KEY(StudentID) REFERENCES Students(ID));";
    // Выполнение ранее сформированных запросов и обработка ошибок
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

SSL_CTX* createSSLContext() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "private.key", SSL_FILETYPE_PEM) <= 0) {
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

std::mutex pythonMutex; // Мьютекс для синхронизации доступа к Python

class PythonRunner {
public:
    PythonRunner(const std::string& scriptDir, const std::string& moduleName, const std::string& className)
        : scriptDir(scriptDir), moduleName(moduleName), className(className) {}

    bool initialize() {
        Py_Initialize();
        // Добавление директории к sys.path
        PyObject* sysPath = PySys_GetObject("path");
        PyObject* path = PyUnicode_FromString(scriptDir.c_str());
        PyList_Append(sysPath, path);
        Py_DECREF(path);

        // Импорт модуля
        PyObject* pName = PyUnicode_FromString(moduleName.c_str());
        pModule = PyImport_Import(pName);
        Py_DECREF(pName);

        if (pModule != nullptr) {
            // Получение класса из модуля
            pClass = PyObject_GetAttrString(pModule, className.c_str());
            if (pClass && PyCallable_Check(pClass)) {
                return true;
            } else {
                PyErr_Print();
                std::cerr << "Failed to get class " << className << "." << std::endl;
                return false;
            }
        } else {
            PyErr_Print();
            std::cerr << "Failed to load module " << moduleName << "." << std::endl;
            return false;
        }
    }

    bool runMethod(const std::string& methodName, const std::string& json_data, std::string& res) {
        std::lock_guard<std::mutex> guard(pythonMutex);

        // Создание экземпляра класса
        PyObject* pModelArg = PyUnicode_FromString("xgb");
        PyObject* pInstance = PyObject_CallFunction(pClass, "O", pModelArg);
        Py_DECREF(pModelArg);

        if (pInstance) {
            // Получение метода из экземпляра
            PyObject* pFunc = PyObject_GetAttrString(pInstance, methodName.c_str());

            // Проверка функции и вызов
            if (pFunc && PyCallable_Check(pFunc)) {
                PyObject* pArgs = PyTuple_New(1);
                PyObject* pValue = PyUnicode_FromString(json_data.c_str());
                PyTuple_SetItem(pArgs, 0, pValue);

                PyObject* pResult = PyObject_CallObject(pFunc, pArgs);
                Py_DECREF(pArgs);

                if (pResult != nullptr) {
                    res = PyUnicode_AsUTF8(pResult);
                    Py_DECREF(pResult);
                    Py_DECREF(pFunc);
                    Py_DECREF(pInstance);
                    return true;
                } else {
                    PyErr_Print();
                    std::cerr << "Call failed." << std::endl;
                }
            } else {
                if (PyErr_Occurred())
                    PyErr_Print();
                std::cerr << "Cannot find function " << methodName << "." << std::endl;
            }
            Py_XDECREF(pFunc);
            Py_DECREF(pInstance);
        } else {
            PyErr_Print();
            std::cerr << "Failed to create instance of " << className << "." << std::endl;
        }
        return false;
    }

    ~PythonRunner() {
        Py_Finalize();
    }

private:
    std::string scriptDir;
    std::string moduleName;
    std::string className;
    PyObject* pModule = nullptr;
    PyObject* pClass = nullptr;
};

void handleClient(SSL* ssl, PythonRunner& pythonRunner) {
    char buffer[1024];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes > 0)
    {
        buffer[bytes] = '\0';
        std::cout << "Received: " << buffer << std::endl;
        std::string response = "Data successfully loaded.";
        SSL_write(ssl, response.c_str(), response.length());

        std::string res;
        bool injection_detected = false;
        if (pythonRunner.runMethod("detect_from_json_payload", buffer, res))
        {
            std::cout << "Result from ML: " << res << std::endl;
            // Парсинг результата как JSON и проверка инъекций
            try
            {
                auto jsonResult = nlohmann::json::parse(res);
                for (const auto &item : jsonResult)
                {
                    if (item["injection_detected"].get<bool>())
                    {
                        injection_detected = true;
                        break;
                    }
                }
                // std::cout << (injection_detected ? 1 : 0) << std::endl;
            }
            catch (const std::exception &e)
            {
                std::cerr << "JSON parsing error: " << e.what() << std::endl;
            }
        }
        else
        {
            std::cerr << "Failed to run Python script." << std::endl;
        }

        try
        {
            auto json = nlohmann::json::parse(buffer);
            std::string name = json["name"];
            int mark = json["mark"];
            std::cout << "Processed: Name - " << name << ", Mark - " << mark << std::endl;

            if (initializeDatabase() && !injection_detected)
            {
                if (insertStudentAndMark(name, mark))
                {
                    std::string response = "Data successfully saved to the database.";
                    std::cout << response << std::endl;
                    SSL_write(ssl, response.c_str(), response.length()); // Отправка подтверждения клиенту
                }
                else
                {
                    std::string response = "Failed to save data.";
                    std::cout << response << std::endl;
                    SSL_write(ssl, response.c_str(), response.length()); // Отправка ошибки клиенту
                }
            }
            else if (injection_detected)
            {
                std::string response = "Failed to save data: SQLi detected.";
                std::cout << response << std::endl;
                SSL_write(ssl, response.c_str(), response.length()); // Отправка ошибки клиенту
            }
        }
        catch (std::exception &e)
        {
            std::cerr << "Error parsing JSON: " << e.what() << std::endl;
            std::string response = "Error parsing JSON";
            SSL_write(ssl, response.c_str(), response.length()); // Отправка ошибки клиенту
        }
    }
    else if (bytes < 0)
    {
        std::cerr << "SSL_read failed." << std::endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main() {
    initializeNetwork();
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

    PythonRunner pythonRunner("sql-injection-detection-main/src",
                              "sql_injection_detection.main", "SQLInjectionDetector");
    if (!pythonRunner.initialize()) {
        return EXIT_FAILURE;
    }

    std::cout << "Server started on port " << SERVER_PORT << ". Waiting for connections..." << std::endl;
    
    // Установка обработчика сигналов
    std::signal(SIGINT, handleSignal);

    #ifdef __linux__
    enableRawMode();
    #endif

    std::thread inputThread([]() {
        while (running) {
            if (_kbhit()) {
                int ch = _getch();
                if (ch == 27) {  // Проверка нажатия клавиши Esc
                    running = false;
                }
            }
        }
    });

    while (running) {
        #ifdef __linux__
        pollfd fds[2];
        fds[0].fd = serverSocket;
        fds[0].events = POLLIN;
        fds[1].fd = 0; // stdin
        fds[1].events = POLLIN;

        int ret = poll(fds, 2, 1000); // Ожидание событий 1 секунду
        if (ret > 0) {
            if (fds[1].revents & POLLIN) { // Ввод с клавиатуры
                int ch = _getch();
                if (ch == 27) {  // Проверка нажатия клавиши Esc
                    running = false;
                    break;
                }
            }

            if (fds[0].revents & POLLIN) { // Новое подключение
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

                std::thread(handleClient, ssl, std::ref(pythonRunner)).detach();
            }
        }
        #else
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);
        timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(serverSocket + 1, &readfds, NULL, NULL, &timeout);
        if (activity > 0) {
            if (FD_ISSET(serverSocket, &readfds)) {
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

                std::thread(handleClient, ssl, std::ref(pythonRunner)).detach();
            }
        }
        if (_kbhit()) {
            int ch = _getch();
            if (ch == 27) {  // Проверка нажатия клавиши Esc
                running = false;
                break;
            }
        }
        #endif
    }

    inputThread.join();

    SSL_CTX_free(ctx);
    cleanupSSL();
    closeSocket(serverSocket);
    cleanupNetwork();

    #ifdef __linux__
    disableRawMode();
    #endif

    return 0;
}