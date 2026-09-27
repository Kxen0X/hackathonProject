#include "database.h"
#include <sodium.h>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace db {

    std::string generatePasswordHash(const std::string& password) {
        if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
        char hashed_password[crypto_pwhash_STRBYTES];
        crypto_pwhash_str(
            hashed_password, password.c_str(), password.size(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE
        );
        return std::string(hashed_password);
    }

    bool verifyUserPassword(const std::string& password, const std::string& hashFromDB) {
        if (sodium_init() < 0) return false;
        return crypto_pwhash_str_verify(hashFromDB.c_str(), password.c_str(), password.size()) == 0;
    }

    std::string vectorToPgArray(const std::vector<std::string>& vec) {
        if (vec.empty()) return "{}";
        std::stringstream ss;
        ss << "{";
        for (size_t i = 0; i < vec.size(); ++i) {
            ss << "\"" << vec[i] << "\"";
            if (i < vec.size() - 1) ss << ",";
        }
        ss << "}";
        return ss.str();
    }

    std::vector<std::string> pgArrayToVector(const std::string& pgArray) {
        std::vector<std::string> result;
        if (pgArray.size() <= 2) return result;
        std::string clean = pgArray.substr(1, pgArray.size() - 2);
        std::stringstream ss(clean);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (!item.empty() && item.front() == '"') item.erase(0, 1);
            if (!item.empty() && item.back() == '"') item.pop_back();
            result.push_back(item);
        }
        return result;
    }

    AuthResult registerUser(pqxx::connection& conn, const RegisterRequest& req) {
        AuthResult res;
        try {
            pqxx::work tx(conn);
            pqxx::result check = tx.exec_params("SELECT id FROM users WHERE email = $1", req.email);
            if (!check.empty()) {
                res.success = -1;
                return res;
            }

            std::string passHash = generatePasswordHash(req.password);
            pqxx::result insert_res = tx.exec_params(
                "INSERT INTO users (email, password_hash, username, access_level) VALUES ($1, $2, $3, $4) RETURNING id",
                req.email, passHash, req.username, req.access_level
            );

            res.user_id = insert_res[0]["id"].as<std::string>();
            res.access_level = req.access_level;
            res.success = 1;
            tx.commit();
        }
        catch (const std::exception& e) {
            std::cerr << "Database register error: " << e.what() << std::endl;
            res.success = -1;
        }
        return res;
    }

    AuthResult loginUser(pqxx::connection& conn, const LoginRequest& req) {
        AuthResult res;
        try {
            pqxx::work tx(conn);
            pqxx::result rows = tx.exec_params("SELECT id, password_hash, access_level FROM users WHERE email = $1", req.email);
            if (rows.empty()) {
                res.success = -1;
                return res;
            }

            std::string dbHash = rows[0]["password_hash"].as<std::string>();
            if (verifyUserPassword(req.password, dbHash)) {
                res.user_id = rows[0]["id"].as<std::string>();
                res.access_level = rows[0]["access_level"].as<std::string>();
                res.success = 1;
            }
            else {
                res.success = -1;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Database login error: " << e.what() << std::endl;
            res.success = -1;
        }
        return res;
    }

    int updateProfile(pqxx::connection& conn, int64_t user_id, const Profile& profile) {
        try {
            pqxx::work tx(conn);

            tx.exec_params(
                "UPDATE users SET username=$1, course=$2, direction=$3, experience=$4, status=$5 "
                "WHERE id=$6",
                profile.username, profile.course, profile.direction, profile.experience, profile.status, user_id
            );

            tx.exec_params("DELETE FROM user_skills WHERE user_id = $1", user_id);
            for (const auto& skill_name : profile.skills) {
                tx.exec_params(
                    "INSERT INTO user_skills (user_id, skill_id) "
                    "SELECT $1, id FROM skills WHERE name = $2",
                    user_id, skill_name
                );
            }

            tx.exec_params("DELETE FROM user_specialties WHERE user_id = $1", user_id);
            for (const auto& spec_name : profile.specialties) {
                tx.exec_params(
                    "INSERT INTO user_specialties (user_id, specialty_id) "
                    "SELECT $1, id FROM specialties WHERE name = $2",
                    user_id, spec_name
                );
            }

            tx.commit();
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "Database updateProfile error: " << e.what() << std::endl;
            return false;
        }
    }

    Profile getProfile(pqxx::connection& conn, int64_t user_id) {
        Profile profile;
        profile.user_id = user_id;
        try {
            pqxx::work tx(conn);

            pqxx::row userRow = tx.exec_params1(
                "SELECT email, username, password_hash, access_level, course, direction, experience, status "
                "FROM users WHERE id = $1",
                user_id
            );

            profile.email = userRow["email"].c_str();
            profile.username = userRow["username"].c_str();
            profile.password_hash = userRow["password_hash"].c_str();
            profile.access_level = userRow["access_level"].c_str();
            profile.course = userRow["course"].is_null() ? 1 : userRow["course"].as<int>();
            profile.direction = userRow["direction"].is_null() ? "" : userRow["direction"].c_str();
            profile.experience = userRow["experience"].is_null() ? "" : userRow["experience"].c_str();
            profile.status = userRow["status"].is_null() ? "" : userRow["status"].c_str();

            pqxx::result specRes = tx.exec_params(
                "SELECT s.name FROM specialties s "
                "JOIN user_specialties us ON s.id = us.specialty_id "
                "WHERE us.user_id = $1",
                user_id
            );
            for (auto row : specRes) {
                profile.specialties.push_back(row["name"].c_str());
            }

            pqxx::result skillsRes = tx.exec_params(
                "SELECT sk.name FROM skills sk "
                "JOIN user_skills usk ON sk.id = usk.skill_id "
                "WHERE usk.user_id = $1",
                user_id
            );
            for (auto row : skillsRes) {
                profile.skills.push_back(row["name"].c_str());
            }

            tx.commit();
        }
        catch (const std::exception& e) {
            std::cerr << "Database get profile error: " << e.what() << std::endl;
            profile.user_id = -1;
        }

        return profile;
    }

    std::vector<Hackathon> getAllHackathons(pqxx::connection& conn) {
        std::vector<Hackathon> list;
        try {
            pqxx::work tx(conn);
            pqxx::result rows = tx.exec("SELECT id, name, description FROM hackathons ORDER BY id DESC");
            for (const auto& row : rows) {
                list.push_back({ row["id"].as<int64_t>(), row["name"].as<std::string>(), row["description"].as<std::string>() });
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Database get hackathons error: " << e.what() << std::endl;
        }
        return list;
    }

    std::vector<Profile> findCandidates(pqxx::connection& conn,
        const std::vector<std::string>& required_skills,
        const std::string& required_team_role) {

        std::vector<Profile> candidates;
        try {
            pqxx::work tx(conn);

            pqxx::result rows = tx.exec_params(
                "SELECT u.id "
                "FROM users u "
                "JOIN user_specialties us ON u.id = us.user_id "
                "JOIN specialties s ON us.specialty_id = s.id "
                "WHERE u.status = 'В поиске команды' AND s.name = $1",
                required_team_role
            );

            for (const auto& row : rows) {
                int64_t uid = row["id"].as<int64_t>();
                Profile cp = getProfile(conn, uid);
                if (cp.user_id != -1) {
                    candidates.push_back(cp);
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Database matching error: " << e.what() << std::endl;
        }
        return candidates;
    }
    int countUserHackathons(pqxx::connection& conn, int64_t user_id) {
        try {
            pqxx::work tx(conn);
            pqxx::result res = tx.exec_params(
                "SELECT COUNT(*) FROM hackathons WHERE creator_id = $1",
                user_id
            );
            return res[0][0].as<int>();
        }
        catch (const std::exception& e) {
            std::cerr << "Database count hackathons error: " << e.what() << std::endl;
            return 0;
        }
    }
    int64_t createHackathon(pqxx::connection& conn, const std::string& name, const std::string& description, int max_team_size, int64_t creator_id) {
        try {
            pqxx::work tx(conn);
            pqxx::result res = tx.exec_params(
                "INSERT INTO hackathons (name, description, max_team_size, creator_id) VALUES ($1, $2, $3, $4) RETURNING id",
                name, description, max_team_size, creator_id
            );
            tx.commit();
            return res[0]["id"].as<int64_t>();
        }
        catch (const std::exception& e) {
            std::cerr << "Database create hackathon error: " << e.what() << std::endl;
            return -1;
        }
    }

    int64_t createTeam(pqxx::connection& conn, const Team& team, int max_allowed_team_size) {
        try {
            if (team.vacancies.size() + 1 > static_cast<size_t>(max_allowed_team_size)) {
                std::cerr << "Team size exceeds hackathon limit!" << std::endl;
                return -1;
            }
            pqxx::work tx(conn);

            pqxx::row teamRow;

            if (team.hackathon_id != -1) {
                teamRow = tx.exec_params1(
                    "INSERT INTO teams (hackathon_id, leader_id, name, status, external_event_info) "
                    "VALUES ($1, $2, $3, $4, $5) RETURNING team_id",
                    team.hackathon_id, team.leader_id, team.name, team.status, team.external_event_info
                );
            }
            else {
                teamRow = tx.exec_params1(
                    "INSERT INTO teams (hackathon_id, leader_id, name, status, external_event_info) "
                    "VALUES (NULL, $1, $2, $3, $4) RETURNING team_id",
                    team.leader_id, team.name, team.status, team.external_event_info
                );
            }

            int64_t new_team_id = teamRow["team_id"].as<int64_t>();

            tx.exec_params(
                "INSERT INTO team_members (team_id, user_id) VALUES ($1, $2)",
                new_team_id, team.leader_id
            );

            for (const auto& vacancy : team.vacancies) {
                tx.exec_params(
                    "INSERT INTO vacancies (team_id, required_role, description, is_active) "
                    "VALUES ($1, $2, $3, $4)",
                    new_team_id,
                    vacancy.required_role,
                    vacancy.description,
                    vacancy.is_active
                );
            }

            tx.commit();
            return new_team_id;
        }
        catch (const std::exception& e) {
            std::cerr << "Database createTeam error: " << e.what() << std::endl;
            return -1;
        }
    }

    bool addTeamMember(pqxx::connection& conn, int64_t team_id, int64_t user_id) {
        try {
            pqxx::work tx(conn);
            tx.exec_params("INSERT INTO team_members (team_id, user_id) VALUES ($1, $2)", team_id, user_id);
            tx.commit();
            return true;
        }
        catch(std::exception& e){
            std::cerr << "Database addTeamMember error: " << e.what() << std::endl;
            return false;
        }
    }

    bool isTeamLeader(pqxx::connection& conn, int64_t team_id, int64_t user_id) {
        try {
            pqxx::work tx(conn);
            pqxx::result res = tx.exec_params(
                "SELECT 1 FROM teams WHERE team_id = $1 AND leader_id = $2",
                team_id, user_id
            );
            return !res.empty();
        }
        catch (...) {
            return false;
        }
    }

    CreateAppResult createApplication(pqxx::connection& conn, const Application& app) {
        try {
            pqxx::work tx(conn);

            pqxx::result teamCheck = tx.exec_params(
                "SELECT 1 FROM teams WHERE team_id = $1", app.team_id
            );
            if (teamCheck.empty()) {
                return { -1, "User with given ID does not exist" };

            }

            if (app.vacancy_id != -1) {
                pqxx::result vacCheck = tx.exec_params(
                    "SELECT 1 FROM vacancies WHERE vacancy_id = $1 AND team_id = $2 AND is_active = TRUE",
                    app.vacancy_id, app.team_id
                );
                if (vacCheck.empty()) {
                    return { -1, "Vacancy does not belong to this team or is inactive" };
                }
            }

            pqxx::result memberCheck = tx.exec_params(
                "SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2",
                app.team_id, app.user_id
            );
            if (!memberCheck.empty()) {
                return { -1, "User is already a member of this team" };
            }

            pqxx::result duplicateCheck = tx.exec_params(
                "SELECT 1 FROM applications WHERE team_id = $1 AND user_id = $2 AND status = 'pending'",
                app.team_id, app.user_id
            );
            if (!duplicateCheck.empty()) {
                return { -1, "A pending application already exists between this user and team" };
            }

            pqxx::row row;
            if (app.vacancy_id != -1) {
                row = tx.exec_params1(
                    "INSERT INTO applications (team_id, user_id, vacancy_id, type, status, message) "
                    "VALUES ($1, $2, $3, $4, $5, $6) RETURNING application_id",
                    app.team_id, app.user_id, app.vacancy_id, app.type, app.status, app.message
                );
            }
            else {
                row = tx.exec_params1(
                    "INSERT INTO applications (team_id, user_id, vacancy_id, type, status, message) "
                    "VALUES ($1, $2, NULL, $3, $4, $5) RETURNING application_id",
                    app.team_id, app.user_id, app.type, app.status, app.message
                );
            }

            int64_t app_id = row["application_id"].as<int64_t>();
            tx.commit();

            return { app_id, "" };
        }
        catch (const std::exception& e) {
            std::cerr << "Database createApplication error: " << e.what() << std::endl;
            return { -1, "Internal database error" };
        }
    }

    std::vector<Vacancy> getHackathonVacancies(pqxx::connection& conn, int64_t hackathon_id) {
        std::vector<Vacancy> vacancies;
        try {
            pqxx::work tx(conn);

            pqxx::result rows = tx.exec_params(
                "SELECT v.vacancy_id, v.team_id, t.name AS team_name, v.required_role, v.description, v.is_active "
                "FROM vacancies v "
                "JOIN teams t ON v.team_id = t.team_id "
                "WHERE t.hackathon_id = $1 AND v.is_active = true",
                hackathon_id
            );

            for (const auto& row : rows) {
                Vacancy v;
                v.vacancy_id = row["vacancy_id"].as<int64_t>();
                v.team_id = row["team_id"].as<int64_t>();
                v.team_name = row["team_name"].c_str();
                v.required_role = row["required_role"].c_str();
                v.description = row["description"].c_str();
                v.is_active = row["is_active"].as<bool>();

                vacancies.push_back(v);
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Database get hackathon vacancies error: " << e.what() << std::endl;
        }
        return vacancies;
    }

    std::vector<Profile> getTeamMembers(pqxx::connection& conn, int64_t team_id) {
        std::vector<Profile> members;
        try {
            pqxx::work tx(conn);

            pqxx::result rows = tx.exec_params(
                "SELECT user_id FROM team_members WHERE team_id = $1",
                team_id
            );

            for (const auto& row : rows) {
                int64_t uid = row["user_id"].as<int64_t>();
                Profile memberProfile = getProfile(conn, uid);
                if (memberProfile.user_id != -1) {
                    members.push_back(memberProfile);
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Database get team members error: " << e.what() << std::endl;
        }
        return members;
    }

}
