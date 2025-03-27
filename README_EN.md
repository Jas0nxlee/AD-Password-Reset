# AD Password Reset System

A web application for Active Directory password reset, providing secure and convenient password reset functionality.

## Features

- Email-based password reset workflow
- LDAP and Active Directory integration
- Password complexity validation
- Email verification code functionality
- Comprehensive logging system
- Cross-origin support
- Responsive frontend interface

## System Requirements

- Python 3.x
- Active Directory server
- SMTP mail server

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd AD-Reset
```

2. Install backend dependencies:
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

3. Configure environment variables:
   - Copy `.env.example` to `.env`
   - Fill in necessary configuration information (LDAP server, SMTP server, etc.)

## Usage Guide

1. Start the backend service:
```bash
cd backend
python app.py
```

2. Open the frontend page:
   - Open `frontend/index.html` directly in browser
   - Or host the frontend files using a web server

3. Usage process:
   - Enter username
   - Receive verification code via email
   - Enter verification code
   - Set new password

## Security Features

- Password complexity validation
- Email verification code dual authentication
- Secure password transmission
- Comprehensive operation logging

## Logging System

The system automatically logs all important operations. Log files are located at:
- Backend logs: `backend/logs/password_reset.log`
- Log files are automatically rotated, with a maximum size of 10MB per file and 5 backup files retained

## Important Notes

- Ensure proper configuration of LDAP server connection information
- Verify SMTP server configuration
- Regularly check log files
- HTTPS is recommended for production environments

## License

[Add license information]

## Contact

[Add contact information]
