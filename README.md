# AD-Reset

A Flask-based Active Directory password reset tool with email verification code support.

[中文文档](README_CN.md) | English

## Features

- Support password reset via email verification code
- Multiple username format support (username, email, UPN, etc.)
- Password complexity validation
- Detailed logging
- SSL/TLS encryption support
- Multi-language support (Chinese/English)

## Project Repository

[https://github.com/Jas0nxlee/AD-Reset](https://github.com/Jas0nxlee/AD-Reset)

## Requirements

- Python 3.8+
- Active Directory Server
- SMTP Mail Server
- Node.js 14+ (for frontend development)

## Installation

### Method 1: Traditional Installation

1. Clone the repository:
```bash
git clone https://github.com/Jas0nxlee/AD-Reset.git
cd AD-Reset
```

2. Install dependencies:
```bash
cd backend
pip install -r requirements.txt
cp .env-template .env
```

3. Configure environment variables:
Edit the `.env` file with the following variables:
```env
# LDAP Configuration
LDAP_SERVER=your_ldap_server
LDAP_PORT=636
LDAP_BASE_DN=your_base_dn
LDAP_USER_DN=your_user_dn
LDAP_USER=your_admin_user
LDAP_DOMAIN=your_domain
LDAP_PASSWORD=your_password

# SMTP Configuration
SMTP_SERVER=your_smtp_server
SMTP_PORT=587
SMTP_USERNAME=your_smtp_username
SMTP_PASSWORD=your_smtp_password

# Server Configuration
SERVER_IP=0.0.0.0
PORT=5001
```

## Usage

1. Start the backend service:
```bash
python backend/app.py
```

2. Start the frontend service:
```bash
cd frontend
npm install
npm run dev
```

3. Access the application:
Open your browser and visit `http://localhost:5173`

### Method 2: Docker Compose Installation

1. Clone the repository:
```bash
git clone https://github.com/Jas0nxlee/AD-Reset.git
cd AD-Reset
```

2. Create `.env` configuration file (refer to the configuration example in the traditional installation section above)

3. Create `docker-compose.yml` file:
```yaml
version: '3.8'
services:
  backend:
    build: 
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "5001:5001"
    env_file:
      - .env
    volumes:
      - ./logs:/app/logs

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "5173:80"
    depends_on:
      - backend

networks:
  default:
    driver: bridge
```

4. Start services:
```bash
docker-compose up -d
```

5. Access the application:
Visit `http://localhost:5173` in your browser

## Password Policy

Passwords must meet the following requirements:
- Minimum length of 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character
- Cannot contain username
- Cannot contain consecutive repeated characters
- Cannot contain keyboard sequences or consecutive number sequences
- Cannot contain repeated character patterns
- Cannot contain common words or organization names

## Logging

Log files are stored in the `logs` directory and include:
- User operation records
- Error messages
- System status
- Security events

## Security Features

- SSL/TLS encrypted communication
- Encrypted password transmission
- Verification code expiration
- Detailed error handling and logging
- Protection against brute force attacks

## Contributing

Issues and Pull Requests are welcome to help improve the project.

## License

MIT License

Copyright (c) 2025 Jas0nxlee 