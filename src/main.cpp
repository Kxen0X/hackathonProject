#include "common.h"
#include "db_pool.h"
#include "server.h"

constexpr const char* DB_CONN_STRING = "host=127.0.0.1 port=5432 dbname=hackathon user=postgres password=zxcTresh1";
constexpr int SERVER_PORT = 8080;
constexpr size_t DB_POOL_SIZE = 10;

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Ошибка инициализации libsodium!" << std::endl;
        return 1;
    }

    try {
        ConnectionPool dbPool(DB_CONN_STRING, DB_POOL_SIZE);
        std::cout << "[Server] Connection pool initialized (" << DB_POOL_SIZE << " connections)." << std::endl;

        Server server(SERVER_PORT, dbPool);
        std::cout << "[Server] Listening on port " << SERVER_PORT << "..." << std::endl;
        server.Start();
        server.wait();
    }
    catch (const std::exception& e) {
        std::cerr << "[Fatal Error] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}