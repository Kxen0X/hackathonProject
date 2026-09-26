#pragma once
#include "common.h"

struct RegisterRequest {
    std::string email;
    std::string password;   // Чистый пароль (камрад хэширует его перед INSERT в БД!)
    std::string username;   // Никнейм/Имя
};

struct LoginRequest {
    std::string email;
    std::string password;
};

// Полная анкета студента (Модуль 1 из ТЗ)
struct StudentProfile {
    int64_t user_id = -1;          // Внутренний ID пользователя в БД (из JWT)
    std::string email;
    std::string username;
    std::string password_hash;     // Хэш пароля. НЕ путать с полем direction!
    // Отдельное поле, чтобы обновление анкеты
    // (updateStudentProfile) не затирало пароль.
// Поля анкеты с хакатона
    int course = 1;                          // Курс (1, 2, 3...)
    std::string direction;                   // Направление
    std::vector<std::string> roles;          // Backend, Frontend, UI/UX Design и т.д.
    std::vector<std::string> skills;         // Стек/Теги: C++, Boost.Asio, PostgreSQL
    std::string status;                      // "В поиске команды" / "В команде"
};

// Модуль 2 из ТЗ (Афиша хакатонов)
struct Hackathon {
    int64_t id;
    std::string name;
    std::string description;
};

namespace db {

    // --- МОДУЛЬ 1. Идентификация (Почта + Пароль) и Профиль ---

    // Регистрация: камрад проверяет email. Если email свободен — хэширует пароль,
    // делает INSERT и возвращает сгенерированный user_id.
    // Если email уже занят или произошла ошибка БД — возвращает -1.
    int64_t registerUser(pqxx::connection& conn, const RegisterRequest& req);

    // Логин: камрад ищет email, сверяет хэш пароля.
    // Если всё верно — возвращает user_id.
    // Если пароль неверный / email не найден / ошибка БД — возвращает -1.
    int64_t loginUser(pqxx::connection& conn, const LoginRequest& req);

    // Сохранение/обновление анкеты (курс, стек, роли, статус).
    // Возвращает 0 при успехе, -1 при ошибке (например, такого user_id нет).
    int updateStudentProfile(pqxx::connection& conn, int64_t user_id, const StudentProfile& profile);

    // Получение анкеты (когда ты распарсил JWT, узнал user_id и запрашиваешь профиль).
    // Возвращает 0 и заполняет out, если профиль найден.
    // Возвращает -1 (out не трогается), если профиль не найден или ошибка БД.
    int getStudentProfile(pqxx::connection& conn, int64_t user_id, StudentProfile& out);

    // --- МОДУЛЬ 2. Мероприятия и Кружки Кампуса ---

    // Получить список всех хакатонов УУНиТ для Афиши.
    // При ошибке БД возвращает пустой vector.
    std::vector<Hackathon> getAllHackathons(pqxx::connection& conn);

    // --- МОДУЛЬ 3. Умный метчинг (Ядро) ---

    // Поиск участников для Капитанов: камрад делает SQL-запрос с фильтрацией
    // по стеку и роли. При ошибке БД или отсутствии совпадений возвращает
    // пустой vector (это не ошибка, а нормальный "ничего не нашли").
    std::vector<StudentProfile> findCandidates(pqxx::connection& conn,
        const std::vector<std::string>& required_skills,
        const std::string& required_role);

} // namespace db