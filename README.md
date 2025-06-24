# AD-Password-Reset

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

[https://github.com/Jas0nxlee/AD-Password-Reset](https://github.com/Jas0nxlee/AD-Password-Reset)

## Requirements

- Python 3.8+
- Active Directory Server
- SMTP Mail Server
- Node.js 14+ (for frontend development)

## Installation

### Method 1: Traditional Installation

1. Clone the repository:
```bash
git clone https://github.com/Jas0nxlee/AD-Password-Reset.git
cd AD-Password-Reset
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

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/Jas0nxlee/AD-Password-Reset.git
    cd AD-Password-Reset
    ```

2.  **Prepare Environment File**:
    *   Navigate to the `backend` directory:
        ```bash
        cd backend
        ```
    *   Copy the template:
        ```bash
        cp .env-template .env
        ```
    *   Edit the `backend/.env` file with your specific configurations (LDAP, SMTP details, etc.).
    *   **Important for Docker Compose**: Ensure the `backend/.env` file includes `REDIS_HOST=redis` for the backend to connect to the Redis container. For local development without Docker, you would typically use `REDIS_HOST=localhost`. Also set other variables like `FLASK_ENV=production` or `FLASK_ENV=development` as needed.
    *   Go back to the project root directory:
        ```bash
        cd ..
        ```

3.  **Build and Start Services with Docker Compose**:
    The `docker-compose.yml` file is located in the `docker/` directory. Run the following command from the **project root directory**:
    ```bash
    docker-compose -f docker/docker-compose.yml up -d --build
    ```
    This command tells Docker Compose to use the specific YAML file (located in `docker/`) and will build the images and start the services (backend, frontend, and Redis). The `env_file` path in `docker-compose.yml` is relative to the `docker-compose.yml` file itself, pointing to `../backend/.env`.

4.  **Access the application**:
    Visit `http://localhost:80` (for the frontend, as per the actual `docker-compose.yml` which maps port 80 on the host to port 80 of the frontend container) or `http://localhost:5173` if you adjust the frontend port mapping in `docker-compose.yml` to `5173:80`. The current `docker/docker-compose.yml` maps host port 80.

**Note on Redis**: The Docker Compose setup now includes a Redis service for managing verification codes. The backend service is configured to connect to Redis using the hostname `redis` (as defined in `docker-compose.yml` and expected in your `.env` file via `REDIS_HOST=redis`).

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

## Administrator Notes

### Password Reset Behavior

When a password is reset using this tool, specific Active Directory attributes are manipulated to ensure security and compliance with typical domain policies:

-   **`pwdLastSet` is set to -1**: This is a standard AD practice that forces the user to change their password immediately upon their next successful login. This ensures that the password set by the tool is temporary.
-   **`userAccountControl` is set to 66080**: This value typically corresponds to `NORMAL_ACCOUNT` (512) + `DONT_EXPIRE_PASSWORD` (65536) + `PASSWORD_NOTREQD` (32).
    -   `NORMAL_ACCOUNT` ensures it's a standard user account.
    -   `DONT_EXPIRE_PASSWORD` is often part of this combination for programmatically set passwords to avoid immediate expiry conflicts before the user can change it.
    -   `PASSWORD_NOTREQD` can be part of an admin reset scenario, indicating the user must set one.
    -   Crucially, the `pwdLastSet = -1` behavior overrides any "password never expires" implication for the *first* login. After the user changes their password, the domain's regular password expiration policies will apply.

Administrators should be aware of these settings as they align with common security practices for forcing user-initiated password changes after an administrative reset.

## Contributing

Issues and Pull Requests are welcome to help improve the project.

## License

MIT License

Copyright (c) 2025 Jas0nxlee 