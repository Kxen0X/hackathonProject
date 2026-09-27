#include "common.h"
#include "database.h"
#include "db_pool.h"



class Session : public std::enable_shared_from_this<Session> {
public:
	Session(asio::ip::tcp::socket connectionSocket, const std::string key, ConnectionPool& dbPool)
		: JWT_SECRET_KEY(key), socket{ std::move(connectionSocket) }, dbPool(dbPool) {

	}

	void start() {
		auto self = shared_from_this();
		asio::co_spawn(socket.get_executor(), [this, self]() -> asio::awaitable<void> {
			try {

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
						AuthResult result;
						{
							auto conn = dbPool.acquire();
							result = db::registerUser(conn.get(), req);

						}
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

						AuthResult result; 
						{
							auto conn = dbPool.acquire();
							result = db::loginUser(conn.get(), req);
						}
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
						int64_t numeric_user_id = 0;
						std::string err;
						try {
							numeric_user_id = std::stoll(user_id);
						}
						catch (...) {
							err = makeResponse(400, "Bad Request", "{\"error\":\"Invalid user_id in token\"}");
							
						}
						if (err.size()) {
							co_await asio::async_write(socket, asio::buffer(err), asio::use_awaitable);
							co_return;
						}
						if (method == "GET" && route == "/api/user/profile") {

							std::string httpResponse;

							try {
								Profile profile;
								{
									auto conn = dbPool.acquire();
									profile = db::getProfile(conn.get(), numeric_user_id);

								}

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

								Profile profile;
								
								{
									auto conn = dbPool.acquire();
									profile = db::getProfile(conn.get(), target_user_id);

								}
								if (profile.user_id != -1) {
									nlohmann::json responseBody;
									responseBody["user_id"] = profile.user_id;
									responseBody["username"] = profile.username;
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
								Profile prof;
								bool isSuccess;
								{
									auto conn = dbPool.acquire();
									prof = db::getProfile(conn.get(), numeric_user_id);

									prof.course = data.value("course", prof.course);
									prof.direction = data.value("direction", prof.direction);
									prof.status = data.value("status", prof.status);
									prof.username = data.value("username", prof.username);
									prof.experience = data.value("experience", prof.experience);
								}
								{
									auto conn = dbPool.acquire();
									if (data.contains("team_roles")) {
										auto roles = data["team_roles"].get<std::vector<std::string>>();
										if (!db::validateRoles(roles)) {
											httpResponse = makeResponse(400, "Bad Request", "{\"error\":\"Invalid team role provided\"}");
											co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
											co_return;
										}
										prof.specialties = roles;
									}
									if (data.contains("skills")) {
										prof.skills = data["skills"].get<std::vector<std::string>>();
									}
								}
								{
									auto conn = dbPool.acquire();
									isSuccess = db::updateProfile(conn.get(), numeric_user_id, prof);
								}
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


							std::vector<Hackathon> list;
							{
								auto conn = dbPool.acquire();
								list = db::getAllHackathons(conn.get());
							}
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
									httpResponse = makeResponse(200, "OK", "[]");
								}
								else if (!db::ALLOWED_ROLES.contains(reqRole)) {
									std::string err = "{\"error\":\"Invalid required_role: " + reqRole + "\"}";
									httpResponse = makeResponse(400, "Bad Request", err);
								}
								else {
									std::vector<Profile> candidates;
									{
										auto conn = dbPool.acquire();
										candidates = db::findCandidates(conn.get(), reqSkills, reqRole);
									}
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
								int currentCount;
								{
									auto conn = dbPool.acquire();
									currentCount = db::countUserHackathons(conn.get(), numeric_user_id);
								}
								if (currentCount >= 5) {
									std::string err = "{\"error\":\"Студенты могут создавать максимум 5 хакатонов.\"}";
									//httpResponse = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
									httpResponse = makeResponse(403, "Forbidden", err);

									co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
									co_return;
								}
							}
							try {
								auto bodyJson = nlohmann::json::parse(body);
								std::string name = bodyJson["name"].get<std::string>();
								std::string description = bodyJson.value("description", "");
								int max_team_size = bodyJson.value("maxTeamSize", 5);

								int64_t hackathon_id;
								{
									auto conn = dbPool.acquire();
									hackathon_id = db::createHackathon(conn.get(), name, description, max_team_size, numeric_user_id);
								}
								if (hackathon_id != -1) {
									nlohmann::json responseBody;
									responseBody["message"] = "Hackathon created successfully";
									responseBody["hackathon_id"] = hackathon_id;

									std::string bodyStr = responseBody.dump();
									//httpResponse = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
									httpResponse = makeResponse(201, "Created", bodyStr);

								}
								else {
									std::string err = "{\"error\":\"Database error while creating hackathon\"}";
									//httpResponse = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
									httpResponse = makeResponse(500, "Internal Server Error", err);

								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid JSON format or missing required fields\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

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
										if (!db::ALLOWED_ROLES.contains(v.required_role)) {
											std::string err = "{\"error\":\"Invalid role in vacancy: " + v.required_role + "\"}";
											httpResponse = makeResponse(400, "Bad Request", err);
											co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
											co_return;
										}
										v.description = vJson.value("description", "");
										v.is_active = vJson.value("is_active", true);
										team.vacancies.push_back(v);
									}
								}

								int team_id;
								{
									auto conn = dbPool.acquire();
									team_id = db::createTeam(conn.get(), team, maxSize);
								}
								if (team_id != -1) {
									nlohmann::json responseBody;
									responseBody["message"] = "Team created successfully";
									responseBody["team_id"] = team_id;
									std::string bodyStr = responseBody.dump();
									//httpResponse = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
									httpResponse = makeResponse(201, "Created", bodyStr);

								}
								else {
									std::string err = "{\"error\":\"Failed to create team (maybe size limit exceeded or DB error)\"}";
									//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
									httpResponse = makeResponse(400, "Bad Request", err);

								}
							}
							catch (const nlohmann::json::exception& e) {
								std::string err = "{\"error\":\"Invalid JSON format or missing fields\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

							}
							catch (...) {
								std::string err = "{\"error\":\"Internal Server Error\"}";
								//httpResponse = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(500, "Internal Server Error", err);

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
								{
									auto conn = dbPool.acquire();

									if (!db::isTeamLeader(conn.get(), team_id, numeric_user_id)) {
										std::string err = "{\"error\":\"Forbidden: You are not the leader of this team\"}";
										httpResponse = makeResponse(403, "Forbidden", err);

										//httpResponse = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
									}
									else if (db::addTeamMember(conn.get(), team_id, user_to_add)) {
										std::string msg = "{\"message\":\"User added to team\"}";
										//httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(msg.size()) + "\r\nConnection: close\r\n\r\n" + msg;
										httpResponse = makeResponse(200, "OK", msg);

									}

									else {
										std::string err = "{\"error\":\"Failed to add user (maybe duplicate or invalid IDs)\"}";
										//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
										httpResponse = makeResponse(400, "Bad Request", err);
									}
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid JSON format\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

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

								std::vector<Vacancy> vacancies;
								{
									auto conn = dbPool.acquire();
									vacancies = db::getHackathonVacancies(conn.get(), hack_id);
								}
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
								//httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
								httpResponse = makeResponse(200, "OK", bodyStr);

							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid hackathon ID format\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

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

								std::vector<Profile> members;
								{
									auto conn = dbPool.acquire();
									members = db::getTeamMembers(conn.get(), team_id);
								}
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
								//httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
								httpResponse = makeResponse(200, "OK", bodyStr);

							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid team ID format\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

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
								{
									auto conn = dbPool.acquire();

								
									if (db::isTeamLeader(conn.get(), team_id, numeric_user_id)) {
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

									CreateAppResult result = db::createApplication(conn.get(), app);
									if (result.success()) {
										nlohmann::json resJson;
										resJson["message"] = "Application created successfully";
										resJson["application_id"] = result.application_id;
										resJson["type"] = app.type;

										std::string bodyStr = resJson.dump();
										//httpResponse = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
										httpResponse = makeResponse(201, "Created", bodyStr);

									}
									else {
										nlohmann::json errJson;
										errJson["error"] = result.error_message;
										std::string errStr = errJson.dump();
										//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(errStr.size()) + "\r\nConnection: close\r\n\r\n" + errStr;
										httpResponse = makeResponse(400, "Bad Request", errStr);
									}
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid JSON format\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

							}

							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}

						else if (method == "PUT" && route == "/api/applications/respond") {
							

							std::string body = co_await getBody(headers, length);
							std::string httpResponse;

							try {
								auto bodyJson = nlohmann::json::parse(body);

								if (!bodyJson.contains("application_id") || !bodyJson.contains("accept")) {
									std::string err = "{\"error\":\"Fields 'application_id' and 'accept' (boolean) are required\"}";
									//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
									httpResponse = makeResponse(400, "Bad Request", err);

									co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
									co_return;
								}

								int64_t app_id = bodyJson["application_id"].get<int64_t>();
								bool accept = bodyJson["accept"].get<bool>();

								RespondAppResult result;
								{
									auto conn = dbPool.acquire();
									result = db::respondToApplication(conn.get(), app_id, numeric_user_id, accept);
								}
								if (result.success) {
									std::string statusStr = accept ? "accepted" : "rejected";
									nlohmann::json resJson;
									resJson["message"] = "Application successfully " + statusStr;
									std::string bodyStr = resJson.dump();

									//httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
									httpResponse = makeResponse(200, "OK", bodyStr);

								}
								else {
									nlohmann::json errJson;
									errJson["error"] = result.error_message;
									std::string errStr = errJson.dump();

									//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(errStr.size()) + "\r\nConnection: close\r\n\r\n" + errStr;
									httpResponse = makeResponse(400, "Bad Request", errStr);

								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid JSON format\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

							}

							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "GET" && route == "/api/applications/my") {
							

							std::string httpResponse;
							std::vector<Application> apps;
							{
								auto conn = dbPool.acquire();
								apps = db::getUserApplications(conn.get(), numeric_user_id);
							}
							nlohmann::json resJson = nlohmann::json::array();
							for (const auto& app : apps) {
								nlohmann::json item;
								item["application_id"] = app.application_id;
								item["team_id"] = app.team_id;
								item["vacancy_id"] = app.vacancy_id;
								item["type"] = app.type;
								item["status"] = app.status;
								item["message"] = app.message;
								resJson.push_back(item);
							}

							std::string bodyStr = resJson.dump();
							//httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
							httpResponse = makeResponse(200, "OK", bodyStr);

							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "GET" && route.rfind("/api/applications/team/", 0) == 0) {
							

							std::string httpResponse;
							try {
								std::string teamIdStr = route.substr(std::string("/api/applications/team/").length());
								int64_t team_id = std::stoll(teamIdStr);
								{
									auto conn = dbPool.acquire();


									if (!db::isTeamLeader(conn.get(), team_id, numeric_user_id)) {
										std::string err = "{\"error\":\"Forbidden: Only the team leader can view team applications\"}";
										//httpResponse = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
										httpResponse = makeResponse(403, "Forbidden", err);

									}
									else {
										auto apps = db::getTeamApplications(conn.get(), team_id);
										nlohmann::json resJson = nlohmann::json::array();
										for (const auto& app : apps) {
											nlohmann::json item;
											item["application_id"] = app.application_id;
											item["team_id"] = app.team_id;
											item["user_id"] = app.user_id;
											item["vacancy_id"] = app.vacancy_id;
											item["type"] = app.type;
											item["status"] = app.status;
											item["message"] = app.message;
											resJson.push_back(item);
										}

										std::string bodyStr = resJson.dump();
										//httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
										httpResponse = makeResponse(200, "OK", bodyStr);

									}
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid team ID format\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

							}

							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "DELETE" && route.starts_with("/api/teams/") && route.find("/members/") != std::string::npos) {
							

							std::string httpResponse;
							try {
								size_t teamPos = 11;
								size_t memPos = route.find("/members/");
								int64_t team_id = std::stoll(route.substr(teamPos, memPos - teamPos));
								int64_t user_to_remove = std::stoll(route.substr(memPos + 9));
								{
									auto conn = dbPool.acquire();

								
									if (!db::isTeamLeader(conn.get(), team_id, numeric_user_id)) {
										std::string err = "{\"error\":\"Forbidden: Only team leader can remove members\"}";
										//httpResponse = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
										httpResponse = makeResponse(403, "Forbidden", err);

									}
									else if (db::removeTeamMember(conn.get(), team_id, user_to_remove)) {
										std::string msg = "{\"message\":\"Member removed from team successfully\"}";
										//httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(msg.size()) + "\r\nConnection: close\r\n\r\n" + msg;
										httpResponse = makeResponse(200, "OK", msg);

									}
									else {
										std::string err = "{\"error\":\"Cannot remove member (user is not in team or is leader)\"}";
										//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
										httpResponse = makeResponse(400, "Bad Request", err);
									}
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid route parameters\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "DELETE" && route.starts_with("/api/teams/") && route.ends_with("/leave")) {
							

							std::string httpResponse;
							try {
								size_t prefixLen = 11;
								size_t suffixLen = 6;
								int64_t team_id = std::stoll(route.substr(prefixLen, route.size() - prefixLen - suffixLen));
								{
									auto conn = dbPool.acquire();


									if (db::removeTeamMember(conn.get(), team_id, numeric_user_id)) {
										std::string msg = "{\"message\":\"You have left the team\"}";
										//httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(msg.size()) + "\r\nConnection: close\r\n\r\n" + msg;
										httpResponse = makeResponse(200, "OK", msg);

									}
									else {
										std::string err = "{\"error\":\"Failed to leave team (leader cannot leave without deleting or transferring ownership)\"}";
										//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
										httpResponse = makeResponse(400, "Bad Request", err);

									}
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid team ID format\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "POST" && route.starts_with("/api/teams/") && route.ends_with("/vacancies")) {
							
							
							std::string body = co_await getBody(headers, length);
							std::string httpResponse;
							try {
								size_t prefixLen = 11;
								size_t suffixLen = 10;
								int64_t team_id = std::stoll(route.substr(prefixLen, route.size() - prefixLen - suffixLen));
								{
									auto conn = dbPool.acquire();

								
									if (!db::isTeamLeader(conn.get(), team_id, numeric_user_id)) {
										std::string err = "{\"error\":\"Forbidden: Only team leader can add vacancies\"}";
										//httpResponse = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
										httpResponse = makeResponse(403, "Forbidden", err);

									}
									else {
										auto bodyJson = nlohmann::json::parse(body);
										std::string req_role = bodyJson["required_role"].get<std::string>();
										
										if (!db::ALLOWED_ROLES.contains(req_role)) {
											std::string err = "{\"error\":\"Invalid role: " + req_role + "\"}";
											httpResponse = makeResponse(400, "Bad Request", err);
										}
										else {


											std::string desc = bodyJson.value("description", "");

											int64_t vac_id = db::addVacancy(conn.get(), team_id, req_role, desc);
											if (vac_id != -1) {
												nlohmann::json resJson;
												resJson["message"] = "Vacancy created successfully";
												resJson["vacancy_id"] = vac_id;
												std::string bodyStr = resJson.dump();
												//httpResponse = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(bodyStr.size()) + "\r\nConnection: close\r\n\r\n" + bodyStr;
												httpResponse = makeResponse(201, "Created", bodyStr);

											}
											else {
												std::string err = "{\"error\":\"Database error while creating vacancy\"}";
												//httpResponse = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
												httpResponse = makeResponse(500, "Internal Server Error", err);
											}
										}
									}
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid JSON or route parameters\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "DELETE" && route.starts_with("/api/teams/") && route.find("/vacancies/") != std::string::npos) {
							

							std::string httpResponse;
							try {
								size_t teamPos = 11;
								size_t vacPos = route.find("/vacancies/");
								int64_t team_id = std::stoll(route.substr(teamPos, vacPos - teamPos));
								int64_t vacancy_id = std::stoll(route.substr(vacPos + 11));
								{
									auto conn = dbPool.acquire();

								
									if (!db::isTeamLeader(conn.get(), team_id, numeric_user_id)) {
										std::string err = "{\"error\":\"Forbidden: Only team leader can delete vacancies\"}";
										//httpResponse = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
										httpResponse = makeResponse(403, "Forbidden", err);

									}
									else if (db::deleteVacancy(conn.get(), team_id, vacancy_id)) {
										std::string msg = "{\"message\":\"Vacancy deleted successfully\"}";
										//httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(msg.size()) + "\r\nConnection: close\r\n\r\n" + msg;
										httpResponse = makeResponse(200, "OK", msg);

									}
									else {
										std::string err = "{\"error\":\"Vacancy not found or does not belong to team\"}";
										//httpResponse = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
										httpResponse = makeResponse(404, "Not Found", err);

									}
								}
							}
							catch (...) {
								std::string err = "{\"error\":\"Invalid route parameters\"}";
								//httpResponse = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
								httpResponse = makeResponse(400, "Bad Request", err);

							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "PUT" && route.starts_with("/api/teams/") && route.find("/", 11) == std::string::npos) {
							

							std::string httpResponse;
							try {
								int64_t team_id = std::stoll(route.substr(11));
								std::string body = co_await getBody(headers, length);
								auto bodyJson = nlohmann::json::parse(body);

								std::string name = bodyJson.value("name", "");
								std::string description = bodyJson.value("description", "");
								{
									auto conn = dbPool.acquire();

								
									if (db::updateTeam(conn.get(), team_id, numeric_user_id, name, description)) {
										httpResponse = makeResponse(200, "OK", "{\"message\":\"Team updated successfully\"}");
									}
									else {
										httpResponse = makeResponse(403, "Forbidden", "{\"error\":\"Team not found or you are not the leader\"}");
									}
								}
							}
							catch (...) {
								httpResponse = makeResponse(400, "Bad Request", "{\"error\":\"Invalid request format\"}");
							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "DELETE" && route.starts_with("/api/teams/") && route.find("/", 11) == std::string::npos) {
							

							std::string httpResponse;
							try {
								int64_t team_id = std::stoll(route.substr(11));
								{
									auto conn = dbPool.acquire();

								
									if (db::deleteTeam(conn.get(), team_id, numeric_user_id)) {
										httpResponse = makeResponse(200, "OK", "{\"message\":\"Team deleted successfully\"}");
									}
									else {
										httpResponse = makeResponse(403, "Forbidden", "{\"error\":\"Team not found or you are not the leader\"}");
									}
								}
							}
							catch (...) {
								httpResponse = makeResponse(400, "Bad Request", "{\"error\":\"Invalid ID format\"}");
							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "PUT" && route.starts_with("/api/teams/") && route.ends_with("/transfer")) {
							
							std::string httpResponse;
							try {
								size_t prefixLen = 11;
								size_t suffixLen = 9;
								int64_t team_id = std::stoll(route.substr(prefixLen, route.size() - prefixLen - suffixLen));

								std::string body = co_await getBody(headers, length);
								auto bodyJson = nlohmann::json::parse(body);

								if (!bodyJson.contains("new_leader_id")) {
									throw std::invalid_argument("Missing new_leader_id");
								}
								int64_t new_leader_id = bodyJson["new_leader_id"].get<int64_t>();
								{
									auto conn = dbPool.acquire();

								
									if (db::transferTeamLeadership(conn.get(), team_id, numeric_user_id, new_leader_id)) {
										httpResponse = makeResponse(200, "OK", "{\"message\":\"Leadership transferred\"}");
									}
									else {
										httpResponse = makeResponse(400, "Bad Request", "{\"error\":\"Transfer failed. Ensure new leader is in the team.\"}");
									}
								}
							}
							catch (...) {
								httpResponse = makeResponse(400, "Bad Request", "{\"error\":\"Invalid JSON or parameters format\"}");
							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else if (method == "PUT" && route.starts_with("/api/hackathons/")) {
							

							std::string httpResponse;
							try {
								int64_t hack_id = std::stoll(route.substr(16));
								std::string body = co_await getBody(headers, length);
								auto bodyJson = nlohmann::json::parse(body);

								std::string title = bodyJson.value("name", "");
								std::string desc = bodyJson.value("description", "");
								int max_sz = bodyJson.value("maxTeamSize", 5);
								bool active = bodyJson.value("is_active", true);

								bool isAdmin = (access_level == "admin");
								{
									auto conn = dbPool.acquire();


									if (db::updateHackathon(conn.get(), hack_id, numeric_user_id, isAdmin, title, desc, max_sz, active)) {
										httpResponse = makeResponse(200, "OK", "{\"message\":\"Hackathon updated successfully\"}");
									}
									else {
										httpResponse = makeResponse(403, "Forbidden", "{\"error\":\"Hackathon not found or access denied\"}");
									}
								}
							}
							catch (...) {
								httpResponse = makeResponse(400, "Bad Request", "{\"error\":\"Invalid JSON or ID format\"}");
							}
							co_await asio::async_write(socket, asio::buffer(httpResponse), asio::use_awaitable);
						}
						else {
							std::string err = "{\"error\":\"Not Found\"}";
							//std::string httpResponse = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(err.size()) + "\r\nConnection: close\r\n\r\n" + err;
							std::string httpResponse = makeResponse(404, "Not Found", err);
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

	static std::string makeResponse(int code, const std::string& statusText, const std::string& jsonBody) {
		return "HTTP/1.1 " + std::to_string(code) + " " + statusText + "\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: " + std::to_string(jsonBody.size()) + "\r\n" +
			"Connection: close\r\n\r\n" +
			jsonBody;
	}

	/*asio::ssl::context& sContext;
	asio::ssl::stream<asio::ip::tcp::socket> sslSocket;*/


	const std::string JWT_SECRET_KEY;

	asio::ip::tcp::socket socket;
	ConnectionPool& dbPool;

	std::string requestData;
};