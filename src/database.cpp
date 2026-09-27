#include "database.h"
#include <sstream>
#include <stdexcept>
#include "common.h"
namespace db {

    std::string generatePasswordHash(const std::string& password) {
        char hashed_password[crypto_pwhash_STRBYTES];
        crypto_pwhash_str(
            hashed_password, password.c_str(), password.size(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE
        );
        return std::string(hashed_password);
    }

    bool verifyUserPassword(const std::string& password, const std::string& hashFromDB) {
        
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
        std::vector<int64_t> user_ids;
        try {
                {


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
                        user_ids.push_back(row["id"].as<int64_t>());
                    }
                    tx.commit();
                }

                for (int64_t uid : user_ids) {
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
                return { -1, "Team with given ID does not exist" };

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

    bool db::removeTeamMember(pqxx::connection& conn, int64_t team_id, int64_t user_id) {
        try {
            pqxx::work tx(conn);

            pqxx::result leaderCheck = tx.exec_params(
                "SELECT leader_id FROM teams WHERE team_id = $1", team_id
            );
            if (!leaderCheck.empty() && leaderCheck[0]["leader_id"].as<int64_t>() == user_id) {
                return false;
            }

            pqxx::result res = tx.exec_params(
                "DELETE FROM team_members WHERE team_id = $1 AND user_id = $2",
                team_id, user_id
            );

            tx.commit();
            return res.affected_rows() > 0;
        }
        catch (const std::exception& e) {
            std::cerr << "Database removeTeamMember error: " << e.what() << std::endl;
            return false;
        }
    }

    int64_t db::addVacancy(pqxx::connection& conn, int64_t team_id, const std::string& role, const std::string& description) {
        try {
            pqxx::work tx(conn);
            pqxx::row row = tx.exec_params1(
                "INSERT INTO vacancies (team_id, required_role, description, is_active) "
                "VALUES ($1, $2, $3, TRUE) RETURNING vacancy_id",
                team_id, role, description
            );
            tx.commit();
            return row["vacancy_id"].as<int64_t>();
        }
        catch (const std::exception& e) {
            std::cerr << "Database addVacancy error: " << e.what() << std::endl;
            return -1;
        }
    }

    bool db::deleteVacancy(pqxx::connection& conn, int64_t team_id, int64_t vacancy_id) {
        try {
            pqxx::work tx(conn);
            pqxx::result res = tx.exec_params(
                "DELETE FROM vacancies WHERE vacancy_id = $1 AND team_id = $2",
                vacancy_id, team_id
            );
            tx.commit();
            return res.affected_rows() > 0;
        }
        catch (const std::exception& e) {
            std::cerr << "Database deleteVacancy error: " << e.what() << std::endl;
            return false;
        }
    }


    RespondAppResult db::respondToApplication(pqxx::connection& conn, int64_t application_id, int64_t responding_user_id, bool accept) {
        try{
            pqxx::work tx(conn);

            pqxx::result appRes = tx.exec_params(
                "SELECT team_id, user_id, vacancy_id, type, status FROM applications WHERE application_id = $1",
                application_id
            );

            if (appRes.empty()) {
                return { false, "Application not found" };
            }

            auto row = appRes[0];
            int64_t team_id = row["team_id"].as<int64_t>();
            int64_t candidate_id = row["user_id"].as<int64_t>();
            int64_t vacancy_id = row["vacancy_id"].is_null() ? -1 : row["vacancy_id"].as<int64_t>();
            std::string type = row["type"].as<std::string>();
            std::string status = row["status"].as<std::string>();

            if (status != "pending") {
                return { false, "Application has already been processed" };
            }

            if (type == "request") {
                pqxx::result leaderRes = tx.exec_params(
                    "SELECT 1 FROM teams WHERE team_id = $1 AND leader_id = $2",
                    team_id, responding_user_id
                );
                if (leaderRes.empty()) {
                    return { false, "Only the team leader can respond to join requests" };
                }
            }
            else if (type == "invite") {
                if (responding_user_id != candidate_id) {
                    return { false, "Only the invited user can respond to this invitation" };
                }
            }

            if (!accept) {
                tx.exec_params(
                    "UPDATE applications SET status = 'rejected' WHERE application_id = $1",
                    application_id
                );
                tx.commit();
                return { true, "" };
            }

            pqxx::result limitCheck = tx.exec_params(
                "SELECT "
                "  (SELECT COUNT(*) FROM team_members WHERE team_id = $1) AS current_size, "
                "  h.max_team_size "
                "FROM teams t "
                "LEFT JOIN hackathons h ON t.hackathon_id = h.id "
                "WHERE t.team_id = $1",
                team_id
            );

            if (!limitCheck.empty()) {
                int current_size = limitCheck[0]["current_size"].as<int>();
                if (!limitCheck[0]["max_team_size"].is_null()) {
                    int max_size = limitCheck[0]["max_team_size"].as<int>();
                    if (current_size >= max_size) {
                        return { false, "Team size limit exceeded for this hackathon" };
                    }
                }
            }
            tx.exec_params(
                "UPDATE applications SET status = 'accepted' WHERE application_id = $1",
                application_id
            );

            tx.exec_params(
                "INSERT INTO team_members (team_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                team_id, candidate_id
            );

            if (vacancy_id != -1) {
                tx.exec_params(
                    "UPDATE vacancies SET is_active = FALSE WHERE vacancy_id = $1",
                    vacancy_id
                );
            }

            tx.commit();
            return { true, "" };
        }
        catch (const std::exception& e) {
            std::cerr << "Database respondToApplication error: " << e.what() << std::endl;
            return { false, "Internal database error" };
        }
    }

    std::vector<Application> db::getUserApplications(pqxx::connection& conn, int64_t user_id) {
        std::vector<Application> apps;
        try {
            pqxx::work tx(conn);
            pqxx::result res = tx.exec_params(
                "SELECT application_id, team_id, user_id, vacancy_id, type, status, message "
                "FROM applications WHERE user_id = $1 ORDER BY application_id DESC",
                user_id
            );

            for (const auto& row : res) {
                Application app;
                app.application_id = row["application_id"].as<int64_t>();
                app.team_id = row["team_id"].as<int64_t>();
                app.user_id = row["user_id"].as<int64_t>();
                app.vacancy_id = row["vacancy_id"].is_null() ? -1 : row["vacancy_id"].as<int64_t>();
                app.type = row["type"].as<std::string>();
                app.status = row["status"].as<std::string>();
                app.message = row["message"].is_null() ? "" : row["message"].as<std::string>();
                apps.push_back(app);
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Database getUserApplications error: " << e.what() << std::endl;
        }
        return apps;
    }

    bool transferTeamLeadership(pqxx::connection& conn, int64_t team_id, int64_t current_leader_id, int64_t new_leader_id) {
        try {
            pqxx::work tx(conn);

            pqxx::result check = tx.exec_params(
                "SELECT leader_id FROM teams WHERE team_id = $1", team_id
            );
            if (check.empty() || check[0]["leader_id"].as<int64_t>() != current_leader_id) {
                return false;
            }

            pqxx::result memberCheck = tx.exec_params(
                "SELECT 1 FROM team_members WHERE team_id = $1 AND user_id = $2",
                team_id, new_leader_id
            );
            if (memberCheck.empty()) {
                return false;
            }

            tx.exec_params(
                "UPDATE teams SET leader_id = $1 WHERE team_id = $2",
                new_leader_id, team_id
            );

            tx.commit();
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "[DB Error] transferTeamLeadership: " << e.what() << std::endl;
            return false;
        }
    }

    bool updateTeam(pqxx::connection& conn, int64_t team_id, int64_t leader_id, const std::string& name, const std::string& description) {
        try {
            pqxx::work tx(conn);
            pqxx::result res = tx.exec_params(
                "UPDATE teams SET name = $1, description = $2 "
                "WHERE team_id = $3 AND leader_id = $4",
                name, description, team_id, leader_id
            );
            tx.commit();
            return res.affected_rows() > 0;
        }
        catch (const std::exception& e) {
            std::cerr << "[DB Error] updateTeam: " << e.what() << std::endl;
            return false;
        }
    }

    bool deleteTeam(pqxx::connection& conn, int64_t team_id, int64_t leader_id) {
        try {
            pqxx::work tx(conn);

            pqxx::result check = tx.exec_params(
                "SELECT 1 FROM teams WHERE team_id = $1 AND leader_id = $2",
                team_id, leader_id
            );
            if (check.empty()) {
                return false;
            }

            tx.exec_params("DELETE FROM applications WHERE team_id = $1", team_id);
            tx.exec_params("DELETE FROM vacancies WHERE team_id = $1", team_id);
            tx.exec_params("DELETE FROM team_members WHERE team_id = $1", team_id);
            tx.exec_params("DELETE FROM teams WHERE team_id = $1", team_id);

            tx.commit();
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "[DB Error] deleteTeam: " << e.what() << std::endl;
            return false;
        }
    }

    bool updateHackathon(pqxx::connection& conn, int64_t hackathon_id, int64_t requesting_user_id, bool is_admin, const std::string& title, const std::string& description, int max_team_size, bool is_active) {
        try {
            pqxx::work tx(conn);
            pqxx::result res;

            if (is_admin) {
                res = tx.exec_params(
                    "UPDATE hackathons SET name = $1, description = $2, max_team_size = $3, is_active = $4 "
                    "WHERE id = $5",
                    title, description, max_team_size, is_active, hackathon_id
                );
            }
            else {
                res = tx.exec_params(
                    "UPDATE hackathons SET name = $1, description = $2, max_team_size = $3, is_active = $4 "
                    "WHERE id = $5 AND creator_id = $6",
                    title, description, max_team_size, is_active, hackathon_id, requesting_user_id
                );
            }

            tx.commit();
            return res.affected_rows() > 0;
        }
        catch (const std::exception& e) {
            std::cerr << "[DB Error] updateHackathon: " << e.what() << std::endl;
            return false;
        }
    }

    std::vector<Application> db::getTeamApplications(pqxx::connection& conn, int64_t team_id) {
        std::vector<Application> apps;
        try {
            pqxx::work tx(conn);
            pqxx::result res = tx.exec_params(
                "SELECT application_id, team_id, user_id, vacancy_id, type, status, message "
                "FROM applications WHERE team_id = $1 ORDER BY application_id DESC",
                team_id
            );

            for (const auto& row : res) {
                Application app;
                app.application_id = row["application_id"].as<int64_t>();
                app.team_id = row["team_id"].as<int64_t>();
                app.user_id = row["user_id"].as<int64_t>();
                app.vacancy_id = row["vacancy_id"].is_null() ? -1 : row["vacancy_id"].as<int64_t>();
                app.type = row["type"].as<std::string>();
                app.status = row["status"].as<std::string>();
                app.message = row["message"].is_null() ? "" : row["message"].as<std::string>();
                apps.push_back(app);
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Database getTeamApplications error: " << e.what() << std::endl;
        }
        return apps;
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
        std::vector<int64_t> user_ids;
        try {
            {
                pqxx::work tx(conn);

                pqxx::result rows = tx.exec_params(
                    "SELECT user_id FROM team_members WHERE team_id = $1",
                    team_id
                );

                for (const auto& row : rows) {
                    user_ids.push_back(row["user_id"].as<int64_t>());
                }
                tx.commit();
            }

            for (int64_t uid : user_ids) {
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
