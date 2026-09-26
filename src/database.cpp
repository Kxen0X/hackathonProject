#include "database.h"
#include <algorithm>
#include <iostream>

// Локальный вектор, имитирующий таблицу пользователей в оперативной памяти
static std::vector<StudentProfile> mock_database;

// Простая функция симуляции хэширования (для теста просто переворачивает строку)
std::string hashPasswordMock(const std::string& password) {
    std::string hash = password;
    std::reverse(hash.begin(), hash.end());
    return hash;
}

namespace db {

    int64_t registerUser(pqxx::connection& conn, const RegisterRequest& req) {
        // Проверяем, нет ли уже такого email в нашей локальной "базе"
        for (const auto& student : mock_database) {
            if (student.email == req.email) {
                return -1; // Занято — возвращаем -1 по требованию Ильдара
            }
        }

        // Создаем нового пользователя и генерируем числовой ID
        StudentProfile new_student;
        new_student.user_id = static_cast<int64_t>(mock_database.size() + 1); // ID: 1, 2, 3...
        new_student.email = req.email;
        new_student.username = req.username;

        // "Хэшируем" пароль в отдельное поле password_hash.
        // ВАЖНО: раньше это писалось в поле direction, из-за чего
        // updateStudentProfile затирал пароль при обновлении анкеты.
        new_student.password_hash = hashPasswordMock(req.password);
        new_student.status = "В поиске команды";

        mock_database.push_back(new_student);
        return new_student.user_id;
    }

    int64_t loginUser(pqxx::connection& conn, const LoginRequest& req) {
        std::string input_hash = hashPasswordMock(req.password);

        for (const auto& student : mock_database) {
            if (student.email == req.email && student.password_hash == input_hash) {
                return student.user_id; // Успешный вход, возвращаем ID
            }
        }
        return -1; // Пользователь не найден или пароль неверен
    }

    int updateStudentProfile(pqxx::connection& conn, int64_t user_id, const StudentProfile& profile) {
        for (auto& student : mock_database) {
            if (student.user_id == user_id) {
                student.course = profile.course;
                student.direction = profile.direction;
                student.roles = profile.roles;
                student.skills = profile.skills;
                student.status = profile.status;
                // password_hash сюда намеренно не трогаем — обновление анкеты
                // не должно влиять на пароль пользователя.
                return 0;   // успех
            }
        }
        return -1;   // пользователь не найден
    }

    int getStudentProfile(pqxx::connection& conn, int64_t user_id, StudentProfile& out) {
        for (const auto& student : mock_database) {
            if (student.user_id == user_id) {
                out = student;
                return 0; // успех
            }
        }
        return -1; // не найдено, out не трогаем
    }

    std::vector<Hackathon> getAllHackathons(pqxx::connection& conn) {
        std::vector<Hackathon> list;
        list.push_back(Hackathon{ 1, "ТОП-ИТ УУНиТ", "Главный хакатон кампуса" });
        list.push_back(Hackathon{ 2, "Цифровой прорыв", "Всероссийский командный трек" });
        return list;
    }

    std::vector<StudentProfile> findCandidates(pqxx::connection& conn, const std::vector<std::string>& required_skills, const std::string& required_role) {
        std::vector<StudentProfile> candidates;
        for (const auto& student : mock_database) {
            if (student.status == "В поиске команды") {
                candidates.push_back(student);
            }
        }
        return candidates;
    }
}