#include "common.h"
#include "session.h"

class Server {
public:

	Server(int port) : port{ port }, strand{ asio::make_strand(ctx) }, acceptor { ctx, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port) } /*sslContext{ asio::ssl::context::tlsv13_server }*/{

	}

	bool Start() {
		try {
			Start_Acception();
			IO_contextThread = std::thread([this]() { ctx.run(); });
		}
		catch(std::exception& ec){
			std::cout << ec.what() << std::endl;

			Stop();
			return 1;
		}
		return 0;
	}

	void Start_Acception() {
		asio::co_spawn(strand, [this]() -> asio::awaitable<void> {
			for (;;) {
				try {
					auto connection = co_await acceptor.async_accept(strand, asio::use_awaitable);
					//auto session = std::make_shared<Session>(std::move(connection), sslContext);
					auto session = std::make_shared<Session>(std::move(connection), JWT_SECRET_KEY);
					std::cout << "CONNECTION SUCCESSFUL" << std::endl;
					session->start();
				}
				catch (std::exception& ec) {
					std::cout << ec.what() << std::endl;
					break;
				}
			}

		
		}, asio::detached);
	}
	void Stop() {
		std::error_code ec;
		acceptor.close(ec);
		ctx.stop();
		if (IO_contextThread.joinable()) {
			IO_contextThread.join();
		}
	}

	void wait() {
		if (IO_contextThread.joinable()) {
			IO_contextThread.join();
		}
	}
private:
	const std::string JWT_SECRET_KEY = "UUST_hackathon_super_mega_secret_key_2026";
	int port;

	asio::io_context ctx;
	std::thread IO_contextThread;
	asio::strand<asio::io_context::executor_type> strand;
	asio::ip::tcp::acceptor acceptor;
	//asio::ssl::context sslContext;
};