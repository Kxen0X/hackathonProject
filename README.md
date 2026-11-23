# Hackathon Team Backend

A C++23 HTTP/JSON backend prototype for finding hackathon teammates and managing teams. It combines coroutine-based network sessions with PostgreSQL storage, JWT authentication, and password hashing.

The default branch is **`I`**. This repository contains the backend source; a frontend and database migration scripts are not included.

## Implemented areas

- User registration and login, with libsodium password hashing and JWT issuance/verification.
- User profiles with skills, team roles, and availability status.
- Hackathon creation, listing, and updates.
- Teams, membership, leadership transfer, and vacancies.
- Applications/invitations and accept/reject flows.
- Candidate lookup by team role and availability.
- A PostgreSQL connection pool with scoped connection guards.

Candidate matching currently filters by role and the stored availability value. Although the API accepts `skills`, the database search does not yet use that parameter for filtering or ranking.

## Stack

| Component | Technology |
| --- | --- |
| Language | C++23 |
| Networking | Standalone Asio, `co_spawn`, `co_await` |
| JSON | nlohmann/json |
| Authentication | jwt-cpp and OpenSSL |
| Password hashing | libsodium |
| Storage | PostgreSQL through libpqxx |
| Build | CMake, with Windows presets for Ninja/MSVC |

## Architecture

```text
HTTP client
    -> Server: accept TCP connections
    -> Session: parse HTTP, verify tokens, dispatch routes
    -> db functions: execute PostgreSQL queries
    -> ConnectionPool: acquire and return database connections
```

Network operations use coroutines. Database calls are synchronous, so they can block the I/O thread; this is not an asynchronous database driver.

## Setup and build

The existing configuration targets a Windows development environment. You need Visual Studio 2022 with C++23 support, Ninja, CMake, vcpkg, and a PostgreSQL instance. `CMakeLists.txt` declares CMake 3.15, but the version-3 presets require **CMake 3.21+**.

```sh
git clone --branch I https://github.com/Kxen0X/hackathonProject.git
cd hackathonProject
```

Before configuring:

1. In [CMakeLists.txt](CMakeLists.txt), replace the hard-coded `CMAKE_TOOLCHAIN_FILE` path with the path to your vcpkg installation. It is currently assigned with `FORCE`, so a command-line override alone will not replace it.
2. Install `libpqxx` and `libsodium` for the same architecture as your compiler. For an x64 Windows build, run this from your vcpkg directory:

   ```bat
   vcpkg install libpqxx:x64-windows libsodium:x64-windows
   ```

3. Check dependency compatibility. Asio, jwt-cpp, and nlohmann/json are fetched from their moving `master` branches. On Windows, OpenSSL is also fetched from a source wrapper; versions are not pinned.
4. Configure local database access and the JWT signing key as described below.

Then, in an x64 Visual Studio Developer Command Prompt, from the repository root:

```bat
cmake --preset x64-release
cmake --build out/build/x64-release
out\build\x64-release\hackatonServer.exe
```

The executable is spelled **`hackatonServer`**, matching the CMake target. If a recent CMake rejects the one-argument `FetchContent_Populate(jwt-cpp)` call, the build script needs an update for that CMake version. Linux/macOS also require build-configuration changes; the checked-in presets are Windows-only.

### Database and configuration

The server defaults to port **8080** and a pool of **10** PostgreSQL connections. Configuration is compiled into the program:

| Setting | Location |
| --- | --- |
| Database connection string, port, pool size | [src/main.cpp](src/main.cpp) |
| JWT signing key | [include/server.h](include/server.h) |
| Token creation and validation | [include/session.h](include/session.h) |

**The database schema is not included.** Creating an empty database is insufficient. Provision tables and reference data compatible with [src/database.cpp](src/database.cpp) before trying the API. The queries reference `users`, `skills`, `specialties`, `user_skills`, `user_specialties`, `hackathons`, `teams`, `team_members`, `vacancies`, and `applications`.

Use a dedicated local development database and your own credentials. The repository contains hard-coded credentials and a JWT key; do not reuse those values. Any values previously used outside a disposable development environment should be rotated.

## API overview

Requests and responses use JSON. Registration and login are public; other routes require an `Authorization: Bearer <token>` header, with additional ownership/role checks in individual handlers.

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/api/auth/register` | Create a user and return a token |
| POST | `/api/auth/login` | Authenticate and return a token |
| GET, PUT | `/api/user/profile` | Read or update the current user's profile |
| GET | `/api/user/profile/{id}` | Read a user's profile |
| GET, POST | `/api/hackathons` | List or create hackathons |
| PUT | `/api/hackathons/{id}` | Update a hackathon |
| POST | `/api/match/candidates` | Find available candidates by role |
| POST | `/api/teams` | Create a team |
| PUT, DELETE | `/api/teams/{id}` | Update or delete a team |
| POST | `/api/teams/members` | Add a member |
| GET | `/api/teams/{id}/members` | List members |
| DELETE | `/api/teams/{id}/members/{user_id}` | Remove a member |
| DELETE | `/api/teams/{id}/leave` | Leave a team |
| PUT | `/api/teams/{id}/transfer` | Transfer leadership |
| GET | `/api/hackathons/{id}/vacancies` | List vacancies for a hackathon |
| POST | `/api/teams/{id}/vacancies` | Add a vacancy |
| DELETE | `/api/teams/{id}/vacancies/{vacancy_id}` | Delete a vacancy |
| POST | `/api/applications` | Create an application or invitation |
| PUT | `/api/applications/respond` | Accept or reject an application |
| GET | `/api/applications/my` | Read the current user's applications |
| GET | `/api/applications/team/{id}` | Read a team's applications |

### Request examples

After the schema, configuration, and local server are ready, the following Bash examples demonstrate the payload format:

```sh
curl --max-time 5 -i http://localhost:8080/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"student@example.com","password":"local-demo-password","username":"student"}'
```

A successful registration returns a JSON object containing `token`. Use that value in subsequent requests:

```sh
curl --max-time 5 -i http://localhost:8080/api/user/profile \
  -H 'Authorization: Bearer <token>'

curl --max-time 5 -i http://localhost:8080/api/match/candidates \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"required_role":"Backend","skills":["C++"]}'
```

These are request examples, not a claim that a fresh clone is ready to run. The custom HTTP implementation still needs work on connection lifetime and buffering; `curl --max-time` bounds the wait if a connection remains open.

## Prototype limitations

- Registration currently accepts an `access_level` from the request. This is a development placeholder, not safe public role assignment.
- The server accepts plain TCP/HTTP connections; linking OpenSSL does not enable HTTPS for incoming traffic.
- There are no checked-in migrations, seed scripts, or end-to-end API tests.
- HTTP parsing, request limits, validation, and error handling need further hardening before external deployment.
- Database calls execute synchronously, and dependency revisions are not locked.

Keep this version in a local development environment. Moving secrets into configuration, enforcing server-side role assignment, adding migrations/tests, and using a robust HTTP layer are the main next steps.

## Source map

| File | Responsibility |
| --- | --- |
| [src/main.cpp](src/main.cpp) | Startup and local configuration |
| [include/server.h](include/server.h) | Listener and session creation |
| [include/session.h](include/session.h) | HTTP parsing, authentication, and route handlers |
| [include/db_pool.h](include/db_pool.h) | Connection pool and scoped guard |
| [include/database.h](include/database.h) | Data structures and database interface |
| [src/database.cpp](src/database.cpp) | SQL operations |
