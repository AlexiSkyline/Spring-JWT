# Secure Authentication API with Spring Boot: JWT, Refresh Tokens, and Token Blacklisting 

This application demonstrates a complete **JWT-based authentication flow** using Spring Boot, featuring:

- **Secure Token Generation** - JWT implementation for endpoint protection
- **Token Refresh Mechanism** - Renew access tokens without re-authentication
- **Session Management** - Secure logout with token blacklisting
- **Protected Endpoints** - Role-based access control examples  

## 🚀 Key Features
✔️ Full JWT authentication flow (login/register)  
✔️ Refresh token implementation for seamless session handling  
✔️ Secure logout with token invalidation (blacklist)  
✔️ Role-based authorization (Admin/User)  
✔️ Ready-to-use endpoints for testing security scenarios  

## 🛠️ Tech Stack
- **Backend**:
    - Spring Boot 3.4.3
    - Spring Security
    - JJWT Library
- **Database**:
    - MySQL (User storage and credentials)
    - Redis (Token blacklist management)
- **Tools**:
    - Lombok
    - Spring Data JPA

## ⚙️ Development Requirements
**Essential:**
- Any Java IDE (IntelliJ, VS Code, Eclipse)
- Docker Engine (v20.10+)
- Docker Compose (v1.29+)

**Recommended:**
- JDK 17 or later
- API testing tool (Postman/curl)

## 🚀 Project Installation

This project uses Docker containers for easy setup. Follow these steps:

### 🐳 Docker Compose Setup
```
    docker-compose up -d
            or
    docker-compose up
```

Once the application will be running, you should get the next containers:

- **spring-boot-jwt** - Main application (port 8080)
- **mysql8** - Database server (MySQL 8.0)
- **redis6** - Token blacklist storage (Redis 6)

Verify with:
```bash
docker ps
```

## 🧪 Testing the Application

### 📚 API Documentation
Access the interactive Swagger UI documentation at:  
🔗 [http://localhost:8080/swagger-ui/index.html](http://localhost:8080/swagger-ui/index.html)
- Explore all available endpoints
- Test API calls directly from your browser
- View request/response models and examples  

### 🚀 Recommended Testing Workflow
1. Start by exploring the Swagger documentation
2. Use the `/api/v1/auth/register` endpoint to create a test user
3. Authenticate via `/api/v1/auth/login` to obtain JWT tokens
4. Test protected endpoints using the provided token
5. Verify data changes in MySQL

### 🛠️ Testing Tools
You can also test using:
- **Postman**
- **cURL** commands
- **Insomnia** REST client