#pragma once
#include <string>
#include <vector>
#include <pqxx/pqxx>
struct RegisterRequest {
	std::string email;
	std::string password;
	std::string username;
	std::string access_level;
};

struct LoginRequest {
	std::string email;
	std::string password;
};

struct AuthResult {
	std::string user_id;
	std::string access_level;
	int success = -1;
};

struct Profile {
	int64_t user_id = -1;
	
	std::string email;
	std::string access_level;
	std::string username;
	std::string password_hash;
	int course = 1;
	std::string direction;
	std::vector<std::string> specialties;
	std::vector<std::string> skills;
	std::string status;
	std::string experience;
};

struct Hackathon {
	int64_t id;
	std::string name;
	std::string description;
	int maxTeamSize = 5;
	int64_t creator_id = -1;
};

struct Vacancy {
	int64_t vacancy_id = -1;
	int64_t team_id;
	std::string team_name;
	std::string required_role;
	std::string description;
	bool is_active = true;
};

struct Team {
	int64_t team_id = -1;
	int64_t hackathon_id = -1;
	int64_t leader_id;
	std::string name;
	std::string external_event_info;
	std::string status;
	std::vector<Vacancy> vacancies;
};

struct Application {
	int64_t application_id = -1;
	int64_t team_id;
	int64_t user_id;
	int64_t vacancy_id = -1;
	std::string type;
	std::string status;
	std::string message;
};

struct CreateAppResult {
	int64_t application_id = -1;
	std::string error_message;
	bool success() const { return application_id != -1; }
};

namespace db {
    std::string generatePasswordHash(const std::string& password);
    bool verifyUserPassword(const std::string& password, const std::string& hashFromDB);

    std::string vectorToPgArray(const std::vector<std::string>& vec);
    std::vector<std::string> pgArrayToVector(const std::string& pgArray);

    AuthResult registerUser(pqxx::connection& conn, const RegisterRequest& req);
    AuthResult loginUser(pqxx::connection& conn, const LoginRequest& req);

    int updateProfile(pqxx::connection& conn, int64_t user_id, const Profile& profile);
    Profile getProfile(pqxx::connection& conn, int64_t user_id);

	std::vector<Hackathon> getAllHackathons(pqxx::connection& conn);

	std::vector<Profile> findCandidates(pqxx::connection& conn,
		const std::vector<std::string>& required_skills,
		const std::string& required_team_role);

	int countUserHackathons(pqxx::connection& conn, int64_t user_id);

	int64_t createHackathon(pqxx::connection& conn, const std::string& name, const std::string& description, int mxTeamSize, int64_t creator_id); int64_t createTeam(pqxx::connection& conn, const Team& team, int max_allowed_team_size);
	
	std::vector<Vacancy> getHackathonVacancies(pqxx::connection& conn, int64_t hackathon_id);
	std::vector<Profile> getTeamMembers(pqxx::connection& conn, int64_t team_id);
	bool addTeamMember(pqxx::connection& conn, int64_t team_id, int64_t user_id);

	bool isTeamLeader(pqxx::connection& conn, int64_t team_id, int64_t user_id);

	CreateAppResult createApplication(pqxx::connection& conn, const Application& app);

}
