#include "common.h"
#include "database.h"

// Данные, которые присылает пользователь при регистрации/входе
struct RegisterRequest {
	std::string email;
	std::string password; // Чистый пароль (камрад должен захэшировать его перед INSERT в БД!)
	std::string username; // Никнейм/Имя
};

struct LoginRequest {
	std::string email;
	std::string password;
};

// Полная анкета студента (Модуль 1 из ТЗ)
struct StudentProfile {
	int64_t user_id;                // Внутренний ID пользователя в БД (из JWT)
	std::string email;
	std::string username;

	int course = 1;                 // Курс (1, 2, 3...)
	std::string direction;          // Направление (например, "Программная инженерия")
	std::vector<std::string> roles; // Backend, Frontend, UI/UX Design и т.д.
	std::vector<std::string> skills;// Стек/Теги: C++, Boost.Asio, PostgreSQL
	std::string status;             // "В поиске команды" / "В команде"
};

// Модуль 2 из ТЗ (Афиша хакатонов)
struct Hackathon {
	int64_t id;
	std::string name;             
	std::string description;
};




class Session : public std::enable_shared_from_this<Session> {
public:
	Session(asio::ip::tcp::socket connectionSocket, const std::string key /*asio::ssl::context& sslContext*/) : JWT_SECRET_KEY(key), socket{ std::move(connectionSocket) } /*sContext{ sslContext },*/ /*sslSocket{ std::move(connectionSocket), sContext }*/ {

	}

	void start() {
		auto self = shared_from_this();
		asio::co_spawn(socket.get_executor(), [this, self]() -> asio::awaitable<void> {
			try {
				//co_await sslSocket.async_handshake(asio::ssl::stream<asio::ip::tcp::socket>::server, asio::use_awaitable);


				co_await ReadMsg();

			}
			catch (std::exception& ec) {
			}

			stop();
		
		}, asio::detached);
	}
	void stop() {
		std::error_code ec;

		socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
		socket.close(ec);

		/*if (sslSocket.lowest_layer().is_open()) {
			sslSocket.shutdown(ec);

			sslSocket.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
			sslSocket.lowest_layer().close(ec);
		}*/


	}

	asio::awaitable<void> ReadMsg() {
		for (;;) {
			std::error_code ec;
			int length = co_await asio::async_read_until(socket, asio::dynamic_buffer(requestData), "\r\n\r\n", asio::redirect_error(asio::use_awaitable, ec));
			if (!ec) {
				auto headers = requestData.substr(0, length);

				std::string method = getMethod(headers);
				std::string route = getRoute(headers);

				if (method == "POST" && route == "/api/auth/register") {
					size_t contentLength = getContentLength(headers);
					
					size_t remainDataSize = requestData.size() - length;

					std::string currentRequest;

					if (remainDataSize >= contentLength) {
						currentRequest = requestData.substr(0, length + contentLength);
						requestData.erase(0, length + contentLength);
					}
					else {
						auto dynBuf = asio::dynamic_buffer(requestData);
						co_await asio::async_read(socket, dynBuf.prepare(contentLength - remainDataSize), asio::use_awaitable);
						
						dynBuf.commit(contentLength - remainDataSize);

						currentRequest = requestData.substr(0, length + contentLength);
						requestData.erase(0, length + contentLength);

					}
					std::string body = currentRequest.substr(length);
					nlohmann::json data = nlohmann::json::parse(body);

					RegisterRequest rreq;
					rreq.email = data["email"];
					rreq.password = data["password"];
					rreq.username = data["username"];

					//db::registerUser();


				}
				else if (method == "POST" && route == "/api/auth/login") {
					size_t contentLength = getContentLength(headers);

					size_t remainDataSize = requestData.size() - length;

					std::string currentRequest;

					if (remainDataSize >= contentLength) {
						currentRequest = requestData.substr(0, length + contentLength);
						requestData.erase(0, length + contentLength);
					}
					else {
						auto dynBuf = asio::dynamic_buffer(requestData);
						co_await asio::async_read(socket, dynBuf.prepare(contentLength - remainDataSize), asio::use_awaitable);

						dynBuf.commit(contentLength - remainDataSize);

						currentRequest = requestData.substr(0, length + contentLength);
						requestData.erase(0, length + contentLength);

					}
					std::string body = currentRequest.substr(length);
					nlohmann::json data = nlohmann::json::parse(body);

					LoginRequest lreq;
					lreq.email = data["email"];
					lreq.password = data["password"];

					//db::loginUser()
				}
				else {
					std::string JWT = getAuthorizationToken(headers);

					if (method == "GET" && route == "/api/user/profile") {

					}
					else if (method == "UPDATE" && route == "/api/user/profile") {

					}
					else if (method == "GET" && route == "/api/hackathons") {

					}
					else if (method == "POST" && route == "/api/match/candidates") {

					}
					else if (method == "POST" && route == "/api/admin/hackathons") {

					}
				}


			}
			else { 
				co_return;
			}
		}
	}

	asio::awaitable<void> SendMsg() {

	}

private:

	std::string genereteJWT(const std::string& user_id, const std::string& role) {
		auto now = std::chrono::system_clock::now();
		auto expires_at = now + std::chrono::hours(24 * 15);

		std::string token = jwt::create()
			.set_issuer("UUST_server")
			.set_type("JWS")
			.set_issued_at(now)
			.set_expires_at(expires_at)
			.set_payload_claim("user_id", jwt::claim(user_id))
			.set_payload_claim("role", jwt::claim(role))
			.sign(jwt::algorithm::hs256{ JWT_SECRET_KEY });
		return token;
	}

	bool validateJWT(const std::string& token, std::string& out_user_id, std::string& out_role) {
		try {
			auto decoded = jwt::decode(token);
			auto verifier = jwt::verify()
				.allow_algorithm(jwt::algorithm::hs256{ JWT_SECRET_KEY })
				.with_issuer("UUST_server");

			verifier.verify(decoded);

			out_user_id = decoded.get_payload_claim("user_id").as_string();
			out_role = decoded.get_payload_claim("role").as_string();

			return true;
		}
		catch (const std::exception& ec) {
			std::cerr << "JWT Validation failed: " << ec.what() << std::endl;
			return false;
		}
	}
	std::string getAuthorizationToken(std::string_view headers) {
		std::string target = "Authorization:";
		auto it = std::search(headers.begin(), headers.end(), target.begin(), target.end(), [](unsigned char f, unsigned char s) {
			return std::tolower(f) == std::tolower(s);
		});

		if (it == headers.end()) {
			return "";
		}
		size_t valueStart = std::distance(headers.begin(), it) + target.size();
		std::string_view val = headers.substr(valueStart);

		if (size_t lineEnd = val.find_first_of("\r\n"); lineEnd != std::string_view::npos) {
			val = val.substr(0, lineEnd);
		}

		if (size_t pos = val.find_first_not_of(" \t"); pos != std::string_view::npos) {
			val.remove_prefix(pos);
		}
		else {
			return "";
		}

		std::string_view bearerPrefix = "bearer ";
		if (val.size() >= bearerPrefix.size()) {
			bool isBearer = std::equal(bearerPrefix.begin(), bearerPrefix.end(), val.begin(),
				[](unsigned char a, unsigned char b) {
					return std::tolower(a) == std::tolower(b);
				}
			);
			if (isBearer) {
				val.remove_prefix(bearerPrefix.size());
			}
		}

		if (size_t pos = val.find_first_not_of(" \t"); pos != std::string_view::npos) {
			val.remove_prefix(pos);
		}
		else {
			return "";
		}

		if (size_t pos = val.find_last_not_of(" \t"); pos != std::string_view::npos) {
			val = val.substr(0, pos + 1);
		}

		return std::string(val);

	}


	std::string returnLowerCase(std::string_view data) {

		auto newData = data | std::views::transform([](unsigned char a) { return std::tolower(a); }) | std::ranges::to<std::string>();
		return newData;

	}

	std::string getMethod(std::string_view headers) {
		size_t first = headers.find(' ');
		return std::string(headers.substr(0, first));
	}

	std::string getRoute(std::string_view headers) {
		size_t first = headers.find(' ');
		if (first == headers.npos) return "";
		size_t second = headers.find(' ', first + 1);
		if (second == headers.npos) return "";
		return std::string(headers.substr(first + 1, second - first - 1));

	}


	int getContentLength(std::string_view data) {
		std::string target = "Content-Length:";
		auto it = std::search(data.begin(), data.end(), target.begin(), target.end(), [](char f, char s) {
			return std::tolower(f) == std::tolower(s);
			});

		if (it != data.end()) {
			size_t ct = std::distance(data.begin(), it);

			auto endPos = data.find_first_of("\r\n", ct);
			if (endPos == std::string::npos) endPos = data.size();

			int valueStart = ct + target.length();
			std::string value(data.substr(valueStart, endPos - valueStart));
			try {
				return std::stoul(value);
			}
			catch (...) {
				return 0;
			}
		}

		return 0;
	}


	/*asio::ssl::context& sContext;
	asio::ssl::stream<asio::ip::tcp::socket> sslSocket;*/


	const std::string JWT_SECRET_KEY;

	asio::ip::tcp::socket socket;
	std::string requestData;

};