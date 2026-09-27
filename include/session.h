#include "common.h"
#include "database.h"


class Session : public std::enable_shared_from_this<Session> {
public:
	Session(asio::ip::tcp::socket connectionSocket, const std::string key /*asio::ssl::context& sslContext*/) : JWT_SECRET_KEY(key), socket{ std::move(connectionSocket) }, conn{ "dbname=hackathon user=postgres password=secret host=127.0.0.1 port=5432" } /*sContext{ sslContext },*/ /*sslSocket{ std::move(connectionSocket), sContext }*/ {

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

					std::string body = co_await getBody(headers, length);
					std::string httpResponse;

					try {
						auto bodyJson = nlohmann::json::parse(body);
						RegisterRequest req{
							bodyJson["email"].get<std::string>(),
							bodyJson["password"].get<std::string>(),
							bodyJson["username"].get<std::string>(),
							bodyJson.value("access_level", "student") // пока что просто реализация с установкой флага в форме регистрации как заглушка, упомянуть в документации про это
						};

						AuthResult result = db::registerUser(conn, req);
						nlohmann::json responseBody;

						if (result.success == 1) {
							std::string token = genereteJWT(result.user_id, result.access_level);
							responseBody["token"] = token;
							std::string bodyStr = responseBody.dump();
							httpResponse = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
						}
						else {
							responseBody["error"] = "Email is already registered or DB error";
							std::string bodyStr = responseBody.dump();
							httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
						}
					}
					catch (...) {
						std::string err = "{\"error\":\"Invalid JSON format\"}";
						httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Length: " + std::to_string(err.size()) + "\r\n\r\n" + err;

					}

					co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);

				}
				else if (method == "POST" && route == "/api/auth/login") {

					std::string body = co_await getBody(headers, length);
					std::string httpResponse;

					try {
						auto bodyJson = nlohmann::json::parse(body);
						LoginRequest req{
							bodyJson["email"].get<std::string>(),
							bodyJson["password"].get<std::string>()
						};

						AuthResult result = db::loginUser(conn, req);
						nlohmann::json responseBody;

						if (result.success == 1) {
							std::string token = genereteJWT(result.user_id, result.access_level);
							responseBody["token"] = token;
							std::string bodyStr = responseBody.dump();
							httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
						}
						else {
							responseBody["error"] = "Invalid email or password";
							std::string bodyStr = responseBody.dump();
							httpResponse = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
						}
					}
					catch (...) {
						std::string err = "{\"error\":\"Invalid Request\"}";
						httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Length: " + std::to_string(err.size()) + "\r\n\r\n" + err;
					}

					co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
					
				}
				else {
					std::string JWT = getAuthorizationToken(headers);
					std::string user_id;
					std::string access_level;
					if (!validateJWT(JWT, user_id, access_level)) {
						nlohmann::json responseBody;
						responseBody["error"] = "Unauthorized. Invalid or missing token.";
						std::string bodyStr = responseBody.dump();
						std::string httpResponse = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;

						co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
					}
					else {
						int64_t numeric_user_id = std::stoll(user_id);
						if (method == "GET" && route == "/api/user/profile") {
							std::string httpResponse;

							try {
								Profile profile = db::getProfile(conn, numeric_user_id);	

								if (profile.user_id != -1) {
									nlohmann::json responseBody;
									responseBody["user_id"] = profile.user_id;
									responseBody["email"] = profile.email;
									responseBody["username"] = profile.username;
									responseBody["role"] = profile.access_level;
									responseBody["course"] = profile.course;
									responseBody["direction"] = profile.direction;
									responseBody["team_roles"] = profile.specialties;
									responseBody["skills"] = profile.skills;
									responseBody["status"] = profile.status;
									responseBody["experience"] = profile.experience;

									std::string bodyStr = responseBody.dump();
									httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\n\r\n" + bodyStr;
								}
								else {
									httpResponse = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
								}
							}
							catch (...) {
								httpResponse = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
							}

							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "GET" && route.starts_with("/api/user/profile/")) {
							std::string httpResponse;

							try {
								std::string id_str = route.substr(18);
								int64_t target_user_id = std::stoll(id_str);

								Profile profile = db::getProfile(conn, target_user_id);

								if (profile.user_id != -1) {
									nlohmann::json responseBody;
									responseBody["user_id"] = profile.user_id;
									responseBody["username"] = profile.username;
									responseBody["email"] = profile.email; // В будущем, возможно, почту стоит скрыть от публичного просмотра
									responseBody["role"] = profile.access_level;
									responseBody["course"] = profile.course;
									responseBody["direction"] = profile.direction;
									responseBody["team_roles"] = profile.specialties;
									responseBody["skills"] = profile.skills;
									responseBody["status"] = profile.status;
									responseBody["experience"] = profile.experience;

									std::string bodyStr = responseBody.dump();
									httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
								}
								else {
									std::string err = "{\"error\":\"User not found\"}";
									httpResponse = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								}
							}
							catch (const std::invalid_argument&) {
								std::string err = "{\"error\":\"Invalid user ID format\"}";
								httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}
							catch (...) {
								std::string err = "{\"error\":\"Internal Server Error\"}";
								httpResponse = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}

							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "PUT" && route == "/api/user/profile") {

							std::string body = co_await getBody(headers, length);
							std::string httpResponse;

							try {
								nlohmann::json data = nlohmann::json::parse(body);
								Profile prof = db::getProfile(conn, numeric_user_id);

								prof.course = data.value("course", prof.course);
								prof.direction = data.value("direction", prof.direction);
								prof.status = data.value("status", prof.status);
								prof.username = data.value("username", prof.username);
								prof.experience = data.value("experience", prof.experience);

								if (data.contains("team_roles")) {
									prof.specialties = data["team_roles"].get<std::vector<std::string>>();
								}
								if (data.contains("skills")) {
									prof.skills = data["skills"].get<std::vector<std::string>>();
								}
								bool isSuccess = db::updateProfile(conn, numeric_user_id, prof);

								if (isSuccess) {
									nlohmann::json responseBody;
									responseBody["message"] = "Profile updated successfully";
									std::string bodyStr = responseBody.dump();
									httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
								}
								else {
									std::string err = "{\"error\":\"User not found or database error\"}";
									httpResponse = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								}
							}
							catch (const nlohmann::json::parse_error& e) {
								std::string err = "{\"error\":\"Invalid JSON format\"}";
								httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}
							catch (const std::exception& e) {
								std::string err = "{\"error\":\"Internal Server Error\"}";
								httpResponse = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}

							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "GET" && route == "/api/hackathons") {
							std::vector<Hackathon> list = db::getAllHackathons(conn);
							nlohmann::json responseBody = nlohmann::json::array();

							for (const auto& h : list) {
								responseBody.push_back({
									{"id", h.id},
									{"name", h.name},
									{"description", h.description},
									{"maxTeamSize", h.maxTeamSize}
								});
							}

							std::string bodyStr = responseBody.dump();
							std::string httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);

						}
						else if (method == "POST" && route == "/api/match/candidates") {
							

							std::string body = co_await getBody(headers, length);
							std::string httpResponse;

							try {
								auto bodyJson = nlohmann::json::parse(body);
								std::vector<std::string> reqSkills = bodyJson.value("skills", std::vector<std::string>{});
								std::string reqRole = bodyJson.value("required_role", "");

								if (reqRole.empty()) {
									httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]";
								}
								else {
									std::vector<Profile> candidates = db::findCandidates(conn, reqSkills, reqRole);
									nlohmann::json responseBody = nlohmann::json::array();

									for (const auto& c : candidates) {
										responseBody.push_back({
											{"user_id", c.user_id},
											{"username", c.username},
											{"email", c.email},
											{"role", c.access_level},
											{"course", c.course},
											{"direction", c.direction},
											{"team_roles", c.specialties},
											{"skills", c.skills},
											{"status", c.status}
											});
									}

									std::string bodyStr = responseBody.dump();
									httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid request parameters\"}";
								httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "POST" && route == "/api/hackathons") {
							std::string body = co_await getBody(headers, length);
							std::string httpResponse;

							if (access_level != "admin") {
								int currentCount = db::countUserHackathons(conn, numeric_user_id);
								if (currentCount >= 5) {
									std::string err = "{\"error\":\"Студенты могут создавать максимум 5 хакатонов.\"}";
									httpResponse = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
									co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
									co_return;
								}
							}
							try {
								auto bodyJson = nlohmann::json::parse(body);
								std::string name = bodyJson["name"].get<std::string>();
								std::string description = bodyJson.value("description", "");
								int max_team_size = bodyJson.value("maxTeamSize", 5);

								int64_t hackathon_id = db::createHackathon(conn, name, description, max_team_size, numeric_user_id);

								if (hackathon_id != -1) {
									nlohmann::json responseBody;
									responseBody["message"] = "Hackathon created successfully";
									responseBody["hackathon_id"] = hackathon_id;

									std::string bodyStr = responseBody.dump();
									httpResponse = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
								}
								else {
									std::string err = "{\"error\":\"Database error while creating hackathon\"}";
									httpResponse = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid JSON format or missing required fields\"}";
								httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}
							

							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "POST" && route == "/api/teams") {
							std::string body = co_await getBody(headers, length);
							std::string httpResponse;

							try {
								auto bodyJson = nlohmann::json::parse(body);
								Team team; 
								team.hackathon_id = bodyJson.value("hackathon_id", static_cast<int64_t>(-1));
								team.external_event_info = bodyJson.value("external_event_info", "");
								team.leader_id = numeric_user_id;
								team.name = bodyJson["name"].get<std::string>();
								team.status = bodyJson.value("status", "В поиске команды");

								int maxSize = bodyJson.value("max_allowed_team_size", 5);

								if (bodyJson.contains("vacancies") && bodyJson["vacancies"].is_array()) {
									for (const auto& vJson : bodyJson["vacancies"]) {
										Vacancy v;
										v.required_role = vJson["required_role"].get<std::string>();
										v.description = vJson.value("description", "");
										v.is_active = vJson.value("is_active", true);
										team.vacancies.push_back(v);
									}
								}

								int team_id = db::createTeam(conn, team, maxSize);

								if (team_id != -1) {
									nlohmann::json responseBody;
									responseBody["message"] = "Team created successfully";
									responseBody["team_id"] = team_id;
									std::string bodyStr = responseBody.dump();
									httpResponse = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
								}
								else {
									std::string err = "{\"error\":\"Failed to create team (maybe size limit exceeded or DB error)\"}";
									httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								}
							}
							catch (const nlohmann::json::exception& e) {
								std::string err = "{\"error\":\"Invalid JSON format or missing fields\"}";
								httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}
							catch (...) {
								std::string err = "{\"error\":\"Internal Server Error\"}";
								httpResponse = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
							
						}
						else if (method == "POST" && route == "/api/teams/members") {
							std::string body = co_await getBody(headers, length);
							std::string httpResponse;

							try {
								auto bodyJson = nlohmann::json::parse(body);
								int64_t team_id = bodyJson["team_id"].get<int64_t>();
								int64_t user_to_add = bodyJson["user_id"].get<int64_t>();

								if (!db::isTeamLeader(conn, team_id, numeric_user_id)) {
									std::string err = "{\"error\":\"Forbidden: You are not the leader of this team\"}";
									httpResponse = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								}
								else if (db::addTeamMember(conn, team_id, user_to_add)) {
									std::string msg = "{\"message\":\"User added to team\"}";
									httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(msg.size()) + "\r\nConnection: close\r\n\r\n" + msg;
								}

								else {
									std::string err = "{\"error\":\"Failed to add user (maybe duplicate or invalid IDs)\"}";
									httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid JSON format\"}";
								httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "GET" && route.starts_with("/api/hackathons/") && route.ends_with("/vacancies")) {
							std::string httpResponse;
							try {
								size_t prefixLen = 16;
								size_t suffixLen = 10;;
								std::string hId_str = route.substr(prefixLen, route.length() - prefixLen - suffixLen);
								int64_t hack_id = std::stoll(hId_str);

								std::vector<Vacancy> vacancies = db::getHackathonVacancies(conn, hack_id);

								nlohmann::json responseBody = nlohmann::json::array();
								for (const auto& v : vacancies) {
									responseBody.push_back({
										{"vacancy_id", v.vacancy_id},
										{"team_id", v.team_id},
										{"team_name", v.team_name},
										{"required_role", v.required_role},
										{"description", v.description},
										{"is_active", v.is_active} 
									});
								}

								std::string bodyStr = responseBody.dump();
								httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid hackathon ID format\"}";
								httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "GET" && route.starts_with("/api/teams/") && route.ends_with("/members")) {
							std::string httpResponse;
							try {
								size_t prefixLen = 11;
								size_t suffixLen = 8;
								std::string tId_str = route.substr(prefixLen, route.size() - prefixLen - suffixLen);
								int64_t team_id = std::stoll(tId_str);

								std::vector<Profile> members = db::getTeamMembers(conn, team_id);
								nlohmann::json responseBody = nlohmann::json::array();
								for (const auto& p : members) {
									responseBody.push_back({
										{"user_id", p.user_id},
										{"username", p.username},
										{"role", p.access_level},
										{"course", p.course},
										{"direction", p.direction},
										{"team_roles", p.specialties},
										{"skills", p.skills}
									});
								}
								std::string bodyStr = responseBody.dump();
								httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid team ID format\"}";
								httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "POST" && route == "/api/applications") { // создание заявки
							std::string body = co_await getBody(headers, length);
							std::string httpResponse;

							try {
								auto bodyJson = nlohmann::json::parse(body);
								int64_t team_id = bodyJson["team_id"].get<int64_t>();

								Application app;
								app.team_id = team_id;
								app.vacancy_id = bodyJson.value("vacancy_id", static_cast<int64_t>(-1));
								app.message = bodyJson.value("message", "");
								app.status = "pending";

								if (db::isTeamLeader(conn, team_id, numeric_user_id)) {
									app.type = "invite";

									if (!bodyJson.contains("user_id")) {
										throw std::runtime_error("Field 'user_id' is required for invites");

									}

									app.user_id = bodyJson["user_id"].get<int64_t>();
									if (app.user_id == numeric_user_id) {
										throw std::runtime_error("Cannot invite yourself");
									}
								}
								else {
									app.type = "request";
									app.user_id = numeric_user_id;
								}

								CreateAppResult result = db::createApplication(conn, app);
								if (result.success()) {
									nlohmann::json resJson;
									resJson["message"] = "Application created successfully";
									resJson["application_id"] = result.application_id;
									resJson["type"] = app.type;

									std::string bodyStr = resJson.dump();
									httpResponse = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
								}
								else {
									nlohmann::json errJson;
									errJson["error"] = result.error_message;
									std::string errStr = errJson.dump();
									httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(errStr.size()) + "\r\nConnection: close\r\n\r\n" + errStr;
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid JSON format\"}";
								httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							}

							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}



						else {
							std::string err = "{\"error\":\"Not Found\"}";
							std::string httpResponse = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
					}
				}


			}
			else { 
				co_return;
			}
		}
	}


private:

	asio::awaitable<std::string> getBody(std::string_view headers, int length) {
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

		co_return currentRequest.substr(length);

	}

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
	pqxx::connection conn;
};