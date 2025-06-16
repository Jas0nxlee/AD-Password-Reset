from flask import Flask, request, jsonify
from flask_cors import CORS
import ldap3
import winrm
import secrets
import smtplib
from email.mime.text import MIMEText
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
import json
import ssl
import base64
import redis
from ldap3.utils.conv import escape_filter_chars

# Configure logging
def setup_logger():
    """Configure logger"""
    # Create logs directory (if it doesn't exist)
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Create logger
    logger = logging.getLogger('password_reset')
    logger.setLevel(logging.INFO)
    
    # Create file handler (max 10MB per file, keep 5 backup files)
    file_handler = RotatingFileHandler(
        'logs/password_reset.log',
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding='utf-8'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler()
    
    # Set log format
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Create Flask app and logger
app = Flask(__name__)
CORS(app)
logger = setup_logger()

# Load configuration from .env file
from dotenv import load_dotenv
load_dotenv()

# LDAP Configuration
LDAP_SERVER = os.getenv('LDAP_SERVER')
LDAP_PORT = int(os.getenv('LDAP_PORT', 636)) # Default to 636 as SSL is always used
# Process LDAP Base DN
raw_base_dn = os.getenv('LDAP_BASE_DN')
if not raw_base_dn:
    LDAP_BASE_DN = ''
elif 'DC=' in raw_base_dn:
    LDAP_BASE_DN = raw_base_dn
else:
    LDAP_BASE_DN = ','.join([f'DC={x}' for x in raw_base_dn.split('.')])
LDAP_USER_DN = os.getenv('LDAP_USER_DN')
LDAP_USER = os.getenv('LDAP_USER')
LDAP_DOMAIN = os.getenv('LDAP_DOMAIN')
LDAP_PASSWORD = os.getenv('LDAP_PASSWORD')
LDAP_SEARCH_OUS_RAW = os.getenv('LDAP_SEARCH_OUS')
LDAP_SEARCH_OUS = [ou.strip() for ou in LDAP_SEARCH_OUS_RAW.split(';') if ou.strip()] if LDAP_SEARCH_OUS_RAW else []

# Email server configuration
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

# Redis Configuration
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)
if REDIS_PASSWORD == '': REDIS_PASSWORD = None
REDIS_DB = int(os.getenv('REDIS_DB', 0))
VERIFICATION_CODE_EXPIRY_SECONDS = 5 * 60

# Initialize Redis Client
try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        db=REDIS_DB,
        socket_connect_timeout=5,
        decode_responses=True
    )
    redis_client.ping()
    logger.info(f"Successfully connected to Redis server at {REDIS_HOST}:{REDIS_PORT}, DB {REDIS_DB}")
except redis.exceptions.ConnectionError as e:
    logger.error(f"Could not connect to Redis server at {REDIS_HOST}:{REDIS_PORT}, DB {REDIS_DB}. Error: {e}")
    logger.warning("Verification codes will not work. Ensure Redis is running and configured correctly.")
    redis_client = None

# Define LDAP connection class
class LDAPConnection:
    """LDAP connection context manager"""
    def __init__(self):
        # LDAP_PORT is now globally defined with a default of 636
        logger.info(f"LDAP server configuration: Server={LDAP_SERVER}, Port={LDAP_PORT}, SSL=True")
        logger.info(f"LDAP domain: {LDAP_DOMAIN}, Base DN: {LDAP_BASE_DN}")

        self.server = ldap3.Server(
            LDAP_SERVER,
            port=LDAP_PORT, # Use global LDAP_PORT
            use_ssl=True,
            connect_timeout=10,
            get_info=ldap3.ALL
        )
        
        self.connection = ldap3.Connection(
            self.server,
            user=f'{LDAP_USER}@{LDAP_DOMAIN}',
            password=LDAP_PASSWORD,
            auto_bind=False
        )
        self.conn = None

    def __enter__(self):
        admin_user = f'{LDAP_USER}@{LDAP_DOMAIN}'
        logger.info(f"Using AD username (UPN format): {admin_user}")
        
        max_retries = 3
        retry_count = 0
        retry_delay = 2
        
        while retry_count < max_retries:
            try:
                self.conn = ldap3.Connection(
                    self.server,
                    user=admin_user,
                    password=LDAP_PASSWORD,
                    auto_bind=False
                )
                if self.conn.bind():
                    logger.info("LDAP connection binding successful")
                    return self.conn
                else:
                    logger.error(f"LDAP binding failed: {self.conn.result}")
                    logger.error(f"Error details: {self.conn.last_error}")
            except Exception as e:
                logger.error(f"LDAP connection exception: {str(e)}")
            
            retry_count += 1
            if retry_count < max_retries:
                logger.info(f"Attempting LDAP reconnect {retry_count}, waiting {retry_delay} seconds")
                import time
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                logger.error("LDAP connection retries exhausted")
                raise Exception(f"LDAP binding failed after {max_retries} retries")
        return self.conn # Should ideally not be reached if exception is raised

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.unbind()

def get_user_email_from_ad(username):
    """Get user's email address from Active Directory"""
    try:
        # LDAP_PORT is now globally defined with a default of 636
        logger.info(f"Connecting to LDAP server: {LDAP_SERVER}:{LDAP_PORT}")
        server = ldap3.Server(
            LDAP_SERVER,
            port=LDAP_PORT, # Use global LDAP_PORT
            use_ssl=True,
            connect_timeout=10,
            get_info=ldap3.ALL
        )
        
        if not LDAP_USER:
            logger.error("LDAP_USER environment variable not configured")
            return None
            
        admin_user = f"{LDAP_USER}@{LDAP_DOMAIN}"
        logger.info(f"Using AD username (UPN format): {admin_user}")
        
        conn = ldap3.Connection(
            server,
            user=admin_user,
            password=LDAP_PASSWORD,
            auto_bind=False
        )
        
        if not conn.bind():
            logger.error(f"LDAP binding failed: {conn.result}")
            logger.error(f"Error details: {conn.last_error}")
            return None
        
        username_formats = [
            username,
            f"{username}@{LDAP_DOMAIN}",
            f"{LDAP_DOMAIN}\\{username}",
            f"{username}@{LDAP_DOMAIN}",
        ]
        
        search_conditions = []
        escaped_username = escape_filter_chars(username)
        search_conditions.append(f"(sAMAccountName={escaped_username})")
        search_conditions.append(f"(cn={escaped_username})")
        search_conditions.append(f"(displayName=*{escaped_username}*)")

        for format_item_raw in username_formats:
            escaped_format_item = escape_filter_chars(format_item_raw)
            if format_item_raw != username:
                search_conditions.append(f"(userPrincipalName={escaped_format_item})")
                search_conditions.append(f"(mail={escaped_format_item})")
            elif username == format_item_raw :
                search_conditions.append(f"(userPrincipalName={escaped_format_item})")
                search_conditions.append(f"(mail={escaped_format_item})")

        search_conditions = list(dict.fromkeys(search_conditions))
        search_filter = f"(&(objectClass=user)(objectCategory=person)(|{''.join(search_conditions)}))"
        logger.info(f"Searching for user '{username}' (actual filter uses escaped values), filter string: {search_filter}")
        
        base_dn = LDAP_BASE_DN
        
        if LDAP_SEARCH_OUS:
            search_bases = LDAP_SEARCH_OUS
            logger.info(f"Using configured LDAP_SEARCH_OUS: {search_bases}")
        else:
            search_bases = [
                base_dn,
                f"CN=Users,{base_dn}",
                f"OU=Domain Users,{base_dn}",
                f"OU=Staff,{base_dn}"
            ]
            logger.info(f"LDAP_SEARCH_OUS not set, using default search bases: {search_bases}")
        
        user_found = False
        for search_base_item_loop in search_bases: # Renamed to avoid conflict
            try:
                logger.info(f"Searching for user {username} in {search_base_item_loop}")
                success = conn.search(
                    search_base=search_base_item_loop,
                    search_filter=search_filter,
                    attributes=['mail', 'userPrincipalName', 'sAMAccountName', 'displayName', 'givenName', 'sn', 'cn']
                )
                if success and len(conn.entries) > 0:
                    user_found = True
                    logger.info(f"User {username} found in {search_base_item_loop}")
                    break
            except ldap3.core.exceptions.LDAPNoSuchObjectResult:
                logger.warning(f"Search Base DN does not exist: {search_base_item_loop}")
            except Exception as e:
                logger.warning(f"Error searching in {search_base_item_loop}: {str(e)}")
        
        if not user_found:
            logger.warning(f"User not found in any search Base DNs: {username}")
            logger.info(f"Search result empty: {conn.result}")
            logger.info(f"LDAP server information: {server.info}")
            return None
            
        logger.info(f"Search results: {conn.entries}")
        if not conn.entries:
            logger.warning(f"User {username} returned no entries after search, even if user_found is True. This should not happen.")
            return None
            
        if hasattr(conn.entries[0], 'mail') and conn.entries[0].mail:
            user_email = conn.entries[0].mail.value
        elif hasattr(conn.entries[0], 'userPrincipalName') and conn.entries[0].userPrincipalName:
            user_email = conn.entries[0].userPrincipalName.value
        else:
            logger.error(f"User {username} has no email address")
            return None
            
        logger.info(f"Successfully retrieved email address for user {username}: {user_email}")
        return user_email
        
    except Exception as e:
        logger.error(f"Error getting user email address: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        import traceback
        logger.error(f"Stack trace: {traceback.format_exc()}")
        return None

def send_verification_code(email):
    """Send verification code to user's email"""
    logger.info(f"Starting to send verification code for email: {email}")
    code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    msg = MIMEText(f'Your password reset verification code is: {code}, valid for 5 minutes.', 'plain', 'utf-8')
    msg['Subject'] = 'Password Reset Verification Code'
    msg['From'] = f'Password Reset Service <{SMTP_USERNAME}>'
    msg['To'] = f'{email}'
    msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

    try:
        logger.info(f"Connecting to SMTP server: {SMTP_SERVER}:{SMTP_PORT}")
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=10)
        try:
            logger.info(f"Connected to SMTP server: {SMTP_SERVER}:{SMTP_PORT}")
            logger.info(f"Logging into SMTP server: {SMTP_USERNAME}")
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            logger.info("SMTP login successful")
            
            logger.info(f"Sending email to: {email}")
            server.send_message(msg)
            
            logger.info(f"Verification code email sent successfully to: {email}")
            
            if redis_client:
                try:
                    redis_key = f"verification_code:{email}"
                    redis_client.setex(redis_key, VERIFICATION_CODE_EXPIRY_SECONDS, code)
                    logger.info(f"Verification code stored in Redis: key={redis_key}, email={email}")
                    return True
                except redis.exceptions.RedisError as re:
                    logger.error(f"Redis error: Failed to store verification code for email {email}. Error: {re}")
                    return False
            else:
                logger.error("Redis client not available. Cannot store verification code.")
                return False
        finally:
            server.quit()
            
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {str(e)}")
        if hasattr(e, 'smtp_error') and e.smtp_error is not None:
            smtp_error_details = e.smtp_error.decode() if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
            logger.error(f"SMTP error details: {smtp_error_details}")
        else:
            logger.error("SMTP error details: No detailed error message available from exception object.")
        logger.error(f"SMTP error code: {e.smtp_code if hasattr(e, 'smtp_code') else 'No error code'}")
        logger.error(f"Email sending failed: Recipient={email}, Error details={str(e)}")
        return False
    except Exception as e:
        error_msg = f"Failed to send verification code to {email}"
        logger.error(error_msg)
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Error details: {str(e)}")
        logger.error(f"Email sending failed: Recipient={email}, Error details={str(e)}")
        return False

def verify_code(email, code):
    """Verify user-entered verification code"""
    logger.info(f"Starting to verify code for email {email}")

    if not redis_client:
        logger.error("Redis client not available. Cannot verify code.")
        return False

    try:
        redis_key = f"verification_code:{email}"
        stored_code = redis_client.get(redis_key)

        if not stored_code:
            logger.warning(f"No verification code record for email {email} (key: {redis_key}), it might have expired or was not sent")
            return False

        if stored_code == code:
            logger.info(f"Verification code for email {email} validated successfully")
            try:
                redis_client.delete(redis_key)
                logger.info(f"Verification code deleted from Redis: key={redis_key}")
            except redis.exceptions.RedisError as re:
                logger.error(f"Redis error: Failed to delete verification code for key {redis_key}. Error: {re}")
            return True
        else:
            logger.warning(f"Incorrect verification code provided for email {email} (key: {redis_key})")
            return False

    except redis.exceptions.RedisError as re:
        logger.error(f"Redis error: Failed to retrieve verification code for email {email}. Error: {re}")
        return False

def validate_password_complexity(username, password):
    """Validate if password meets AD complexity requirements"""
    errors = []
    if len(password) < 8: errors.append("Password must be at least 8 characters long")
    if not any(c.isupper() for c in password): errors.append("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password): errors.append("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password): errors.append("Password must contain at least one digit")
    special_chars = '!@#$%^&*()_+-=[]{};:,.<>?/'
    if not any(c in special_chars for c in password): errors.append("Password must contain at least one special character")
    if username.lower() in password.lower(): errors.append("Password cannot contain the username")
    for i in range(len(password)-2):
        if password[i] == password[i+1] == password[i+2]:
            errors.append("Password cannot contain consecutively repeated characters")
            break
    keyboard_sequences = ['qwerty', 'asdfgh', '123456', '654321', '123', '321', '456', '789']
    password_lower = password.lower()
    for seq in keyboard_sequences:
        if seq in password_lower:
            errors.append("Password cannot contain keyboard sequences or consecutive numerical sequences")
            break
    for i in range(len(password)-3):
        pattern = password[i:i+2]
        if pattern in password[i+2:]:
            errors.append("Password cannot contain repeated character patterns")
            break
    common_words = ['ucas', 'admin', 'password', 'welcome', 'login', 'user']
    for word in common_words:
        if word in password_lower:
            errors.append("Password cannot contain common words or organization names (e.g., ucas)")
            break
    if errors:
        return False, "\n".join(errors)
    return True, "Password meets complexity requirements"

def reset_ad_password(username, new_password):
    """Reset Active Directory user password"""
    logger.info(f"Starting to reset password for user {username}")
    
    is_valid, message = validate_password_complexity(username, new_password)
    if not is_valid:
        logger.error(f"Password does not meet complexity requirements for user '{username}': {message}")
        return False, f"Password does not meet requirements: {message}"
        
    try:
        with LDAPConnection() as conn:
            if conn is None:
                logger.error(f"LDAP connection could not be established for password reset of user '{username}'.")
                return False, "System error: Could not connect to user directory. Please contact support."

            escaped_username_for_reset = escape_filter_chars(username)
            search_filter = f'(&(objectClass=user)(|(userPrincipalName={escaped_username_for_reset})(sAMAccountName={escaped_username_for_reset})(mail={escaped_username_for_reset})))'
            logger.info(f"Sanitized LDAP search filter for password reset for '{username}' uses patterns like: (sAMAccountName={escaped_username_for_reset})")

            if LDAP_SEARCH_OUS:
                search_bases_for_reset = LDAP_SEARCH_OUS
                logger.info(f"User search for password reset (user: '{username}') will use configured LDAP_SEARCH_OUS: {search_bases_for_reset}")
            else:
                search_bases_for_reset = [
                    LDAP_BASE_DN,
                    f"CN=Users,{LDAP_BASE_DN}",
                    f"OU=Domain Users,{LDAP_BASE_DN}",
                    f"OU=Staff,{LDAP_BASE_DN}"
                ]
                logger.info(f"LDAP_SEARCH_OUS not set. User search for password reset (user: '{username}') will use default search bases: {search_bases_for_reset}")

            user_entry = None
            user_dn = None
            user_found_in_ou_search = False

            for search_base_item in search_bases_for_reset:
                logger.info(f"Searching for user '{username}' in '{search_base_item}' for password reset.")
                try:
                    search_success = conn.search(
                        search_base=search_base_item,
                        search_filter=search_filter,
                        attributes=['distinguishedName', 'pwdLastSet', 'lockoutTime', 'userPrincipalName', 'mail', 'entryDN']
                    )
                    if search_success and conn.entries:
                        if len(conn.entries) > 1:
                            logger.warning(f"Multiple users found for '{username}' in '{search_base_item}' during password reset. Using the first entry: {conn.entries[0].entry_dn}")

                        current_entry = conn.entries[0]
                        if hasattr(current_entry, 'entry_dn') and current_entry.entry_dn:
                            user_entry = current_entry
                            user_dn = user_entry.entry_dn
                            user_found_in_ou_search = True
                            logger.info(f"User '{username}' found in '{search_base_item}' for password reset. DN: {user_dn}")
                            break
                        else:
                            logger.error(f"User entry found for '{username}' in '{search_base_item}' but it is missing the 'entry_dn' attribute. This entry will be skipped.")

                except ldap3.core.exceptions.LDAPNoSuchObjectResult:
                    logger.warning(f"Search base '{search_base_item}' does not exist (during password reset search for '{username}').")
                except Exception as e:
                    logger.warning(f"Error searching for user '{username}' in '{search_base_item}' during password reset: {str(e)}")

            if not user_found_in_ou_search:
                logger.error(f"User '{username}' not found in any specified search OUs during password reset attempt.")
                return False, "User account not found. Cannot reset password."

            if not user_entry or not user_dn:
                logger.error(f"User entry or DN not properly obtained for '{username}' after search, though user_found_in_ou_search was true.")
                return False, "System error: Failed to retrieve complete user information. Please contact support."
                
            if hasattr(user_entry, 'lockoutTime'):
                lockout_time = user_entry.lockoutTime.value
                if lockout_time:
                    if isinstance(lockout_time, datetime):
                        lockout_time = int(lockout_time.timestamp())
                    if int(lockout_time) > 0:
                        logger.info(f"Attempting to unlock user account: {username}")
                        success_unlock = ldap3.extend.microsoft.unlockAccount.ad_unlock_account(conn, user_dn)
                        if not success_unlock:
                            logger.error(f"Account unlock failed for user {username} during password reset.")
                            return False, "Your account is currently locked and an attempt to unlock it failed. Please contact your administrator for assistance."
                        logger.info(f"Account unlock successful for user {username} during password reset.")

            try:
                modify_attrs = {
                    'unicodePwd': [(ldap3.MODIFY_REPLACE, [f'"{new_password}"'.encode('utf-16-le')])],
                    'userPassword': [(ldap3.MODIFY_REPLACE, [new_password])],
                    'userAccountControl': [(ldap3.MODIFY_REPLACE, ['66080'])],  # 66080 = NORMAL_ACCOUNT (512) + DONT_EXPIRE_PASSWORD (65536) + PASSWORD_NOTREQD (32)
                                                                                # PASSWORD_NOTREQD is often set temporarily during admin resets.
                                                                                # DONT_EXPIRE_PASSWORD flag is standard, actual expiry is governed by domain policy & pwdLastSet.
                    'pwdLastSet': [(ldap3.MODIFY_REPLACE, ['-1'])]  # Forces user to change password on next login.
                }
                success_reset = conn.modify(user_dn, modify_attrs)
                
                if not success_reset:
                    error_msg = conn.result.get('description', 'No description')
                    error_details = str(conn.result)
                    logger.error(f"Password modification failed for {username}: {error_msg}. Details: {error_details}")
                    if 'WILL_NOT_PERFORM' in error_details and 'problem 5003' in error_details:
                        return False, (
                            "Password does not meet domain policy requirements. Common reasons include:\n"
                            "- Too short (minimum 8 characters usually)\n"
                            "- Lacks complexity (uppercase, lowercase, numbers, special characters)\n"
                            "- Contains parts of your username or full name\n"
                            "- Too similar to recent passwords.\n"
                            "Please try a different password or contact your administrator for full policy details."
                        )
                    elif 'CONSTRAINT_VIOLATION' in error_details:
                         return False, "Password reset failed. This may be due to password complexity or history rules. Please try a different password or contact your administrator."
                    return False, "Password reset failed. Please ensure your new password meets the domain's complexity and history requirements. If you need assistance, contact your administrator."

                logger.info(f"Password reset successful: {username}")
                return True, "Password reset successful"

            except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
                logger.error(f"Password reset failed (LDAP service account authentication issue) for user {username}: {str(e)}")
                return False, "A system configuration error occurred. Please contact your administrator."
            except ldap3.core.exceptions.LDAPOperationResult as e:
                logger.error(f"Password reset failed (LDAP operation error) for user {username}: {str(e)}")
                return False, "Password reset operation failed due to a server error. Please try again later. If the issue persists, contact your administrator."
            except Exception as e:
                logger.error(f"Unexpected error during password reset LDAP modify operation for {username}: {str(e)}")
                return False, "An unexpected internal error occurred while resetting the password. Please contact your administrator."

    except Exception as e:
        logger.error(f"Outer exception in reset_ad_password for user {username}: {str(e)}")
        return False, "A system error occurred while processing your password reset request. Please try again later or contact support."

@app.route('/api/send-code', methods=['POST'])
def send_code():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    
    if not email:
        logger.warning("Received send code request, but email address is empty")
        return jsonify({'success': False, 'message': 'Please provide an email address.'}), 400
    
    if not username:
        logger.warning("Received send code request, but username is empty")
        return jsonify({'success': False, 'message': 'Please provide a username.'}), 400
    
    logger.info(f"Received send code request: username={username}, email={email}")
    
    ad_email = get_user_email_from_ad(username)
    if not ad_email:
        logger.warning(f"User '{username}' not found or user information cannot be retrieved for send-code API.")
        error_message = f"User '{username}' not found or unable to retrieve user information. Please check the username and try again. If the issue persists, contact support."
        return jsonify({'success': False, 'message': error_message}), 404
    
    if email.lower().strip() != ad_email.lower().strip():
        logger.warning(f"User-provided email address does not match the one in the domain for user '{username}': provided={email}, actual={ad_email}")
        masked_email = mask_email(ad_email)
        return jsonify({
            'success': False, 
            'message': f"The email address you provided does not match our records for user '{username}'. A hint for the correct email format is: {masked_email}. Please try again."
        }), 400
    
    try:
        if send_verification_code(email):
            logger.info(f"Successfully sent verification code to email: {email}")
            return jsonify({'success': True, 'message': 'Verification code has been sent. Please check your email.'}), 200
        else:
            logger.error(f"Failed to send verification code (send_verification_code returned False): email={email}")
            return jsonify({'success': False, 'message': 'Failed to send verification code. Please ensure your email address is correct and try again. If the problem continues, please contact your system administrator.'}), 500
    except Exception as e:
        logger.error(f"Exception during send_code route for email {email}: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        import traceback
        logger.error(f"Stack trace: {traceback.format_exc()}")
        return jsonify({'success': False, 'message': 'An unexpected error occurred while trying to send the verification code. Please try again later or contact your system administrator.'}), 500

def mask_email(email):
    """Partially hide email address, showing only the first character, @ symbol, and domain"""
    if not email or '@' not in email:
        return "***@***.***"
    
    parts = email.split('@')
    username_part = parts[0]
    domain = parts[1]
    
    if len(username_part) > 1:
        masked_username = username_part[0] + '*' * (len(username_part) - 1)
    else:
        masked_username = '*'
    
    return f"{masked_username}@{domain}"

@app.route('/api/get-config', methods=['GET'])
def get_config():
    """Get API configuration information"""
    logger.info("Getting API configuration")
    server_ip = os.getenv('SERVER_IP', '127.0.0.1')
    port = os.getenv('PORT', 5001)
    
    api_base_url = f"http://{server_ip}:{port}/api"
    logger.info(f"Returning API base URL: {api_base_url}")
    
    return jsonify({
        'success': True,
        'api_base_url': api_base_url
    })

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    code = data.get('code')
    new_password = data.get('new_password')
    
    logger.info(f"Received password reset request: Username={username}, Email={email}")
    
    if not all([username, email, code, new_password]):
        logger.warning(f"Password reset request is missing required fields: username={username}, email={email}")
        return jsonify({'success': False, 'message': 'Please fill in all required fields: username, email, verification code, and new password.'}), 400

    ad_email = get_user_email_from_ad(username)
    if not ad_email or email.lower().strip() != ad_email.lower().strip():
        logger.warning(f"Email address mismatch during password reset: provided={email}, ad_email_found={ad_email if ad_email else 'None'}")
        return jsonify({'success': False, 'message': 'Invalid username or email. Please ensure you are using the same username and email you used to request the verification code.'}), 400

    if not verify_code(email, code):
        logger.warning(f"Verification code validation failed: email={email}")
        return jsonify({'success': False, 'message': 'The verification code is invalid or has expired. Please request a new code.'}), 400
    
    success_op, message_op = reset_ad_password(username, new_password)
    if success_op:
        logger.info(f"Password reset successful: username={username}")
    else:
        logger.error(f"Password reset failed: username={username}, message={message_op}")
    return jsonify({'success': success_op, 'message': message_op}), 200 if success_op else 500

def main():
    """Start the application"""
    logger.info("Password reset service started")
    app.run(host='0.0.0.0', port=5001)

if __name__ == '__main__':
    main()