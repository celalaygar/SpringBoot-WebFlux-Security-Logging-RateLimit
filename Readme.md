
# SecurityProject - Spring Boot 3, WebFlux, JWT, Role-Based Security, Rate Limiting

This project is a **reactive, modern Java backend application** built with **Spring Boot 3** and **WebFlux**.  
It demonstrates **Role-Based Security** with **JWT Authentication**, **Request Logging to MongoDB**, and **Rate Limiting** using MongoDB.

---

## 🛠️ Technologies Used

- **Spring Boot 3**
- **Spring WebFlux** (Reactive Programming)
- **JWT (JSON Web Token)** based Authentication
- **Role-Based Authorization**
- **Reactive MongoDB**
- **Custom Rate Limiting** (stored and managed in MongoDB)
- **Request and Response Logging** (logs requests and responses to MongoDB)

---

## 📂 Project Structure

```
├── src
│   ├── main
│   │   ├── java
│   │   │   └── com.security.securityProject
│   │   │       ├── SecurityProjectApplication.java
│   │   │       ├── config
│   │   │       │   ├── DataInitializer.java
│   │   │       │   ├── JwtUtil.java
│   │   │       │   └── SecurityConfig.java
│   │   │       ├── controller
│   │   │       │   ├── AuthController.java
│   │   │       │   └── ResourceController.java
│   │   │       ├── dto
│   │   │       │   ├── AuthRequest.java
│   │   │       │   ├── AuthResponse.java
│   │   │       │   └── RegisterRequest.java
│   │   │       ├── entity
│   │   │       │   ├── ApiLog.java
│   │   │       │   ├── RateLimitConfig.java
│   │   │       │   ├── RateLimitCounter.java
│   │   │       │   ├── Role.java
│   │   │       │   └── User.java
│   │   │       ├── exception
│   │   │       │   ├── ExpiredJwtTokenException.java
│   │   │       │   ├── GlobalExceptionHandler.java
│   │   │       │   ├── IllegalArgumentTokenException.java
│   │   │       │   ├── MalformedJwtTokenException.java
│   │   │       │   ├── SecurityJwtTokenException.java
│   │   │       │   ├── UnauthorizedException.java
│   │   │       │   └── UnsupportedJwtTokenException.java
│   │   │       ├── filter
│   │   │       │   ├── RateLimitingWebFilter.java
│   │   │       │   └── RequestResponseLoggingFilter.java
│   │   │       ├── repository
│   │   │       │   ├── ApiLogRepository.java
│   │   │       │   ├── RateLimitConfigRepository.java
│   │   │       │   ├── RateLimitCounterRepository.java
│   │   │       │   ├── RoleRepository.java
│   │   │       │   └── UserRepository.java
│   │   │       └── service
│   │   │           ├── AuthenticationManager.java
│   │   │           ├── CustomReactiveUserDetailsService.java
│   │   │           ├── LoggingService.java
│   │   │           └── SecurityContextRepository.java
│   │   └── resources
│   │       └── application.yml
```

---

## ⚙️ How to Run This Project

1️⃣ **Clone the Repository**

```bash
git clone https://github.com/celalaygar/securityProject.git
cd securityProject
```

2️⃣ **Configure MongoDB**

Make sure you have MongoDB running locally or update the `application.yml` with your MongoDB URI.

Example `application.yml`:
```yaml
spring:
  data:
    mongodb:
      uri: mongodb://localhost:27017/securityProject
server:
  port: 8080
```

3️⃣ **Run the Application**

You can run the project using your IDE or with Maven/Gradle:
```bash
# Using Maven
./mvnw spring-boot:run

# Or using Gradle
./gradlew bootRun
```

---

## ✅ Available REST Endpoints

### 🔑 Auth Endpoints

**Register a new user**
```bash
curl --location 'http://localhost:8080/auth/register' --header 'Content-Type: application/json' --data-raw '{
    "email": "testx3@example.com",
    "password": "testx3123"
}'
```

**Login and get JWT Token**
```bash
curl --location 'http://localhost:8080/auth/login' --header 'Content-Type: application/json' --data-raw '{
    "email": "testx3@example.com",
    "password": "testx3123"
}'
```

---

### 🔒 Secured API Endpoints

**Public Endpoint (No Auth Required)**
```bash
curl --location 'http://localhost:8080/api/public'
```

**User Endpoint (Requires JWT)**
```bash
curl --location 'http://localhost:8080/api/user' --header 'Authorization: Bearer <YOUR_JWT_TOKEN>' --header 'Content-Type: application/json' --data-raw '{
    "email": "test@example.com",
    "username": "testuser1",
    "password": "test123"
}'
```

**Admin Endpoint (Requires ADMIN Role)**
```bash
curl --location 'http://localhost:8080/api/admin' --header 'Authorization: Bearer <YOUR_JWT_TOKEN>' --header 'Content-Type: application/json' --data-raw '{
    "email": "admin@example.com",
    "username": "adminuser",
    "password": "admin123"
}'
```

---

## 📌 Planned or Suggested Additional Endpoints

Based on the existing structure, you can add more endpoints like:

- `/api/logs` → View logged API requests (Admin only)
- `/api/rate-limit/config` → Create/Update rate limit configs (Admin only)
- `/api/profile` → Get current user profile (User)
- `/api/roles` → Assign/modify roles (Admin only)

---

## ✅ Security

- Uses JWT for stateless authentication.
- Custom `SecurityContextRepository` for reactive security context.
- Supports role-based access (`ROLE_USER`, `ROLE_ADMIN`).
- Secure password hashing with `PasswordEncoder`.
- Logs unauthorized access attempts.
- Handles invalid/expired JWTs with custom exceptions.

---

## 🗂️ Logging

- All API requests and responses are logged using `RequestResponseLoggingFilter` and stored in MongoDB (`ApiLog` collection).
- Logs can be retrieved for audit and debugging.

---

## 🚦 Rate Limiting

- Uses MongoDB (`RateLimitConfig` and `RateLimitCounter`) to limit requests per user or IP.
- Custom `RateLimitingWebFilter` checks and enforces limits reactively.

---

## 📌 Next Steps

✅ **To do:**
- Implement `/api/logs` controller to fetch request logs.
- Implement `/api/rate-limit/config` controller to manage rate limit rules.
- Add more tests.

---

## 👤 Author

Created by **[Celal Aygar]**

---

## 📜 License

MIT License (or your preferred license)

---

**Happy Coding!**
