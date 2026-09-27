#pragma once
#include "common.h"

class ConnectionPool {
public:
    ConnectionPool(const std::string& conn_info, size_t pool_size)
        : conn_info_(conn_info) {
        for (size_t i = 0; i < pool_size; ++i) {
            pool_.push(std::make_unique<pqxx::connection>(conn_info_));
        }
    }

    class ConnectionGuard {
    public:
        ConnectionGuard(ConnectionPool& pool, std::unique_ptr<pqxx::connection> conn)
            : pool_(pool), conn_(std::move(conn)) {
        }

        ~ConnectionGuard() {
            if (conn_) {
                pool_.returnConnection(std::move(conn_));
            }
        }

        pqxx::connection& get() { return *conn_; }

        ConnectionGuard(const ConnectionGuard&) = delete;
        ConnectionGuard& operator=(const ConnectionGuard&) = delete;
        ConnectionGuard(ConnectionGuard&&) noexcept = default;
        ConnectionGuard& operator=(ConnectionGuard&&) noexcept = default;

    private:
        ConnectionPool& pool_;
        std::unique_ptr<pqxx::connection> conn_;
    };

    ConnectionGuard acquire() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !pool_.empty(); });

        auto conn = std::move(pool_.front());
        pool_.pop();
        return ConnectionGuard(*this, std::move(conn));
    }

private:
    void returnConnection(std::unique_ptr<pqxx::connection> conn) {
        std::unique_lock<std::mutex> lock(mutex_);

        if (conn && conn->is_open()) {
            pool_.push(std::move(conn));
        }
        else {
            try {
                pool_.push(std::make_unique<pqxx::connection>(conn_info_));
            }
            catch (const std::exception& e) {
                std::cerr << "[DB Pool Error] Failed to reconnect: " << e.what() << std::endl;
            }
        }
        cv_.notify_one();
    }

    std::string conn_info_;
    std::queue<std::unique_ptr<pqxx::connection>> pool_;
    std::mutex mutex_;
    std::condition_variable cv_;
};