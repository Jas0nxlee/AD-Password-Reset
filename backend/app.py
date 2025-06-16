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
LDAP_PORT = int(os.getenv('LDAP_PORT', 389))
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
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None) # None if empty or not set
if REDIS_PASSWORD == '': REDIS_PASSWORD = None # Ensure empty string becomes None
REDIS_DB = int(os.getenv('REDIS_DB', 0))
VERIFICATION_CODE_EXPIRY_SECONDS = 5 * 60  # 5 minutes

# Initialize Redis Client
try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        db=REDIS_DB,
        socket_connect_timeout=5, # seconds
        decode_responses=True # Store and retrieve strings, not bytes
    )
    redis_client.ping()
    logger.info(f"Successfully connected to Redis server at {REDIS_HOST}:{REDIS_PORT}, DB {REDIS_DB}")
except redis.exceptions.ConnectionError as e:
    logger.error(f"Could not connect to Redis server at {REDIS_HOST}:{REDIS_PORT}, DB {REDIS_DB}. Error: {e}")
    logger.warning("Verification codes will not work. Ensure Redis is running and configured correctly.")
    redis_client = None # Set to None if connection fails

# Define LDAP connection class
class LDAPConnection:
    """LDAP connection context manager"""
    def __init__(self):
        # Determine LDAP port
        ldap_port_to_use = 636  # Default for SSL
        try:
            env_ldap_port = os.getenv('LDAP_PORT')
            if env_ldap_port:
                ldap_port_to_use = int(env_ldap_port)
                logger.info(f"LDAP_PORT environment variable found: {ldap_port_to_use}")
            else:
                logger.info(f"LDAP_PORT environment variable not set, defaulting to {ldap_port_to_use} for SSL.")
        except ValueError:
            logger.warning(f"Invalid LDAP_PORT value: '{env_ldap_port}'. Defaulting to {ldap_port_to_use} for SSL.")

        # Configure LDAP server connection
        logger.info(f"LDAP server configuration: Server={LDAP_SERVER}, Port={ldap_port_to_use}, SSL=True")
        logger.info(f"LDAP domain: {LDAP_DOMAIN}, Base DN: {LDAP_BASE_DN}")

        # Use simplified TLS settings
        self.server = ldap3.Server(
            LDAP_SERVER,
            port=ldap_port_to_use, # Use determined port
            use_ssl=True,  # Always use SSL
            connect_timeout=10,  # Increase connection timeout
            get_info=ldap3.ALL  # Get server information
        )
        
        # Use simple connection strategy
        self.connection = ldap3.Connection(
            self.server,
            user=f'{LDAP_USER}@{LDAP_DOMAIN}',  # Use UPN format
            password=LDAP_PASSWORD,
            auto_bind=False  # Explicitly set manual binding
        )
        self.conn = None

    def __enter__(self):
        # Always use UPN format (username@domain)
        admin_user = f'{LDAP_USER}@{LDAP_DOMAIN}'
        logger.info(f"Using AD username (UPN format): {admin_user}")
        
        # Add retry mechanism
        max_retries = 3
        retry_count = 0
        retry_delay = 2  # Initial delay 2 seconds
        
        while retry_count < max_retries:
            try:
                self.conn = ldap3.Connection(
                    self.server,
                    user=admin_user,
                    password=LDAP_PASSWORD,
                    auto_bind=False
                )
                
                # Manually bind and check result
                if self.conn.bind():
                    logger.info("LDAP connection binding successful")
                    return self.conn
                else:
                    logger.error(f"LDAP binding failed: {self.conn.result}")
                    logger.error(f"Error details: {self.conn.last_error}")
                    
            except Exception as e:
                logger.error(f"LDAP connection exception: {str(e)}")
            
            # Retry logic
            retry_count += 1
            if retry_count < max_retries:
                logger.info(f"Attempting LDAP reconnect {retry_count}, waiting {retry_delay} seconds")
                import time
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff strategy
            else:
                logger.error("LDAP connection retries exhausted")
                raise Exception(f"LDAP binding failed after {max_retries} retries")
        
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.unbind()

def get_user_email_from_ad(username):
    """Get user's email address from Active Directory"""
    try:
        # Determine LDAP port for SSL
        ldap_port_to_use = 636  # Default for SSL
        try:
            env_ldap_port = os.getenv('LDAP_PORT')
            if env_ldap_port:
                ldap_port_to_use = int(env_ldap_port)
                logger.info(f"LDAP_PORT environment variable found for get_user_email_from_ad: {ldap_port_to_use}")
            else:
                logger.info(f"LDAP_PORT environment variable not set for get_user_email_from_ad, defaulting to {ldap_port_to_use} for SSL.")
        except ValueError:
            logger.warning(f"Invalid LDAP_PORT value for get_user_email_from_ad: '{env_ldap_port}'. Defaulting to {ldap_port_to_use} for SSL.")

        logger.info(f"Connecting to LDAP server: {LDAP_SERVER}:{ldap_port_to_use}")
        server = ldap3.Server(
            LDAP_SERVER,
            port=ldap_port_to_use,  # Use determined port
            use_ssl=True,  # Always use SSL
            connect_timeout=10,  # Increase connection timeout
            get_info=ldap3.ALL  # Get server information
        )
        
        # Check LDAP user configuration
        if not LDAP_USER:
            logger.error("LDAP_USER environment variable not configured")
            return None
            
        # Always use UPN format (username@domain)
        admin_user = f"{LDAP_USER}@{LDAP_DOMAIN}"
        logger.info(f"Using AD username (UPN format): {admin_user}")
        
        conn = ldap3.Connection(
            server,
            user=admin_user,
            password=LDAP_PASSWORD,
            auto_bind=False  # Explicitly set manual binding
        )
        
        # Manually bind and check result
        if not conn.bind():
            logger.error(f"LDAP binding failed: {conn.result}")
            logger.error(f"Error details: {conn.last_error}")
            return None
        
        # Try searching with different username formats
        # 1. Original username
        # 2. username@domain
        # 3. domain\username
        # 4. Email format
        username_formats = [
            username,  # Original username
            f"{username}@{LDAP_DOMAIN}",  # UPN format
            f"{LDAP_DOMAIN}\\{username}",  # domain\username format
            f"{username}@{LDAP_DOMAIN}",  # Email format
        ]
        
        # Build a more comprehensive search filter
        search_conditions = []
        for format_item in username_formats: # Renamed 'format' to 'format_item' to avoid conflict with built-in
            search_conditions.append(f"(sAMAccountName={username})")
            search_conditions.append(f"(userPrincipalName={format_item})")
            search_conditions.append(f"(mail={format_item})")
            # Add CN and displayName search
            search_conditions.append(f"(cn={username})")
            search_conditions.append(f"(displayName=*{username}*)")
        
        search_filter = f"(&(objectClass=user)(objectCategory=person)(|{' '.join(search_conditions)}))"        
        logger.info(f"Searching for user {username}, filter: {search_filter}")
        
        # Ensure correct Base DN format
        base_dn = LDAP_BASE_DN
        # logger.info(f"Search Base DN: {base_dn}") # Base DN is part of search_bases now or used if LDAP_SEARCH_OUS is empty
        
        # Determine search bases
        if LDAP_SEARCH_OUS:
            search_bases = LDAP_SEARCH_OUS
            logger.info(f"Using configured LDAP_SEARCH_OUS: {search_bases}")
        else:
            search_bases = [
                base_dn,  # Main domain
                f"CN=Users,{base_dn}",  # Users container
                f"OU=Domain Users,{base_dn}",  # Domain Users OU
                f"OU=Staff,{base_dn}"  # Example/Staff OU (common default)
            ]
            logger.info(f"LDAP_SEARCH_OUS not set, using default search bases: {search_bases}")
        
        user_found = False
        for search_base in search_bases:
            try:
                logger.info(f"Searching for user {username} in {search_base}")
                success = conn.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    attributes=['mail', 'userPrincipalName', 'sAMAccountName', 'displayName', 'givenName', 'sn', 'cn']
                )
                
                if success and len(conn.entries) > 0:
                    user_found = True
                    logger.info(f"User {username} found in {search_base}")
                    break
            except ldap3.core.exceptions.LDAPNoSuchObjectResult:
                logger.warning(f"Search Base DN does not exist: {search_base}")
                continue
            except Exception as e:
                logger.warning(f"Error searching in {search_base}: {str(e)}")
                continue
        
        if not user_found:
            logger.warning(f"User not found in any search Base DNs: {username}")
            logger.info(f"Search result empty: {conn.result}")
            # Log more detailed diagnostic information
            logger.info(f"LDAP server information: {server.info}")
            return None
            
        logger.info(f"Search results: {conn.entries}")

        # Explicitly check conn.entries before accessing to prevent IndexError
        if not conn.entries:
            logger.warning(f"User {username} returned no entries after search, even if user_found is True. This should not happen.")
            return None
            
        # Prefer mail attribute, use userPrincipalName if it doesn't exist
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
        # Log stack trace for better diagnosis
        import traceback
        logger.error(f"Stack trace: {traceback.format_exc()}")
        return None

def send_verification_code(email):
    """Send verification code to user's email"""
    logger.info(f"Starting to send verification code for email: {email}")
    code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    # expiration_time = datetime.now() + timedelta(minutes=5) # Not needed with Redis TTL
    
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
            
            # Log complete verification code in development environment
            logger.info(f"Verification code email sent successfully to: {email}") # Removed code from log
            
            if redis_client:
                try:
                    redis_key = f"verification_code:{email}"
                    redis_client.setex(redis_key, VERIFICATION_CODE_EXPIRY_SECONDS, code)
                    logger.info(f"Verification code stored in Redis: key={redis_key}, email={email}")
                    return True
                except redis.exceptions.RedisError as re:
                    logger.error(f"Redis error: Failed to store verification code for email {email}. Error: {re}")
                    # Fallback or error message - for now, we just log and return False
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
        logger.error(f"Email sending failed: Recipient={email}, Error details={str(e)}") # Duplicates message but ok for now
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
                # Continue, as verification was successful
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
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")
    
    special_chars = '!@#$%^&*()_+-=[]{};:,.<>?/'
    if not any(c in special_chars for c in password):
        errors.append("Password must contain at least one special character")
    
    if username.lower() in password.lower():
        errors.append("Password cannot contain the username")
    
    # Check consecutively repeated characters
    for i in range(len(password)-2):
        if password[i] == password[i+1] == password[i+2]:
            errors.append("Password cannot contain consecutively repeated characters")
            break
    
    # Check keyboard sequences or consecutive numerical sequences
    keyboard_sequences = ['qwerty', 'asdfgh', '123456', '654321', '123', '321', '456', '789']
    password_lower = password.lower()
    for seq in keyboard_sequences:
        if seq in password_lower:
            errors.append("Password cannot contain keyboard sequences or consecutive numerical sequences")
            break
    
    # Check repeated character patterns
    for i in range(len(password)-3):
        pattern = password[i:i+2]
        if pattern in password[i+2:]:
            errors.append("Password cannot contain repeated character patterns")
            break
            
    # Check common words or organization names (e.g., ucas)
    common_words = ['ucas', 'admin', 'password', 'welcome', 'login', 'user']
    password_lower = password.lower()
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
    
    # First validate password complexity
    is_valid, message = validate_password_complexity(username, new_password)
    if not is_valid:
        logger.error(f"Password does not meet complexity requirements: {message}")
        return False, f"Password does not meet requirements: {message}"
        
    try:
        # Connect using LDAPConnection class
        with LDAPConnection() as conn:
            # Search user - supports multiple user identifiers
            search_filter = f'(&(objectClass=user)(|(userPrincipalName={username})(sAMAccountName={username})(mail={username})))'
            logger.info(f"Searching user, filter: {search_filter}")
            conn.search(
                search_base=LDAP_BASE_DN,
                search_filter=search_filter,
                attributes=['distinguishedName', 'pwdLastSet', 'lockoutTime', 'userPrincipalName', 'mail']
            )
            
            if not conn.entries:
                logger.error(f"User not found during reset_ad_password: {username}")
                return False, "User account not found. Cannot reset password."

            # Enhanced null check and error handling
            try:
                if len(conn.entries) == 0:
                    logger.error(f"LDAP query returned empty result for user {username} (reset_ad_password, should be caught by 'not conn.entries').")
                    return False, "User account not found. Cannot reset password."
                
                user_entry = conn.entries[0]
                if not hasattr(user_entry, 'entry_dn') or not user_entry.entry_dn:
                    logger.error(f"User entry is missing entry_dn attribute: {username}")
                    return False, "User information is incomplete. Please contact support."

            except IndexError as e:
                logger.error(f"LDAP query result index exception in reset_ad_password: {str(e)}")
                return False, "System error: Failed to retrieve user information. Please contact support."
            except Exception as e:
                logger.error(f"Unexpected error while processing LDAP results in reset_ad_password: {str(e)}")
                return False, "System error: Failed to process user information. Please contact support."
                
            try:
                user_dn = user_entry.entry_dn
                logger.debug(f"Retrieved valid user DN for password reset: {user_dn}")
                    
                logger.info(f"Found user DN for password reset: {user_dn}")
            except Exception as e:
                logger.error(f"Error retrieving user DN in reset_ad_password: {str(e)}")
                return False, "Failed to retrieve user details. Please contact support."
        
            # Check account lock status and attempt to unlock
            if hasattr(conn.entries[0], 'lockoutTime'):
                lockout_time = conn.entries[0].lockoutTime.value
                if lockout_time:
                    # Ensure lockoutTime is a numerical type
                    if isinstance(lockout_time, datetime):
                        lockout_time = int(lockout_time.timestamp())
                    if int(lockout_time) > 0:
                        logger.info(f"Attempting to unlock user account: {username}")
                        # Use AD-specific unlock method
                        success_unlock = ldap3.extend.microsoft.unlockAccount.ad_unlock_account(conn, user_dn) # Renamed success to success_unlock
                        if not success_unlock:
                            logger.error(f"Account unlock failed for user {username} during password reset.")
                            return False, "Your account is currently locked and an attempt to unlock it failed. Please contact your administrator for assistance."
                        logger.info(f"Account unlock successful for user {username} during password reset.")

            # Attempt to reset password
            try:
                # Modify password and account control
                modify_attrs = {
                    'unicodePwd': [(ldap3.MODIFY_REPLACE, [f'"{new_password}"'.encode('utf-16-le')])],
                    'userPassword': [(ldap3.MODIFY_REPLACE, [new_password])], # For some LDAP systems, may not be needed if unicodePwd is set
                    'userAccountControl': [(ldap3.MODIFY_REPLACE, ['66080'])],  # 66080 = NORMAL_ACCOUNT (512) + DONT_EXPIRE_PASSWORD (65536) + PASSWORD_NOTREQD (32) - this is a common value.
                                                                                # PASSWORD_NOTREQD is often set temporarily during admin resets.
                                                                                # The DONT_EXPIRE_PASSWORD flag is standard for normal accounts, actual expiry is governed by domain policy and pwdLastSet.
                    'pwdLastSet': [(ldap3.MODIFY_REPLACE, ['-1'])]  # Forces the user to change their password upon next login.
                }
                success_reset = conn.modify(user_dn, modify_attrs) # Renamed success to success_reset
                
                if not success_reset:
                    error_msg = conn.result.get('description', 'No description')
                    error_details = str(conn.result)
                    logger.error(f"Password modification failed for {username}: {error_msg}. Details: {error_details}")
                    # Check for specific LDAP error codes for more user-friendly messages
                    if 'WILL_NOT_PERFORM' in error_details and 'problem 5003' in error_details: # Standard AD password policy
                        return False, (
                            "Password does not meet domain policy requirements. Common reasons include:\n"
                            "- Too short (minimum 8 characters usually)\n"
                            "- Lacks complexity (uppercase, lowercase, numbers, special characters)\n"
                            "- Contains parts of your username or full name\n"
                            "- Too similar to recent passwords.\n"
                            "Please try a different password or contact your administrator for full policy details."
                        )
                    elif 'CONSTRAINT_VIOLATION' in error_details: # Other constraint, often complexity or history
                         return False, "Password reset failed. This may be due to password complexity or history rules. Please try a different password or contact your administrator."
                    return False, "Password reset failed. Please ensure your new password meets the domain's complexity and history requirements. If you need assistance, contact your administrator."

                # if success_reset: # This is implicitly true if we didn't return False above
                logger.info(f"Password reset successful: {username}")
                return True, "Password reset successful"
                # The 'else' part for success_reset=False is effectively handled by 'if not success_reset'

            except ldap3.core.exceptions.LDAPInvalidCredentialsResult as e:
                logger.error(f"Password reset failed (authentication error for service account): {username}, {str(e)}")
                return False, "A system configuration error occurred. Please contact your administrator."
            except ldap3.core.exceptions.LDAPOperationResult as e: # Catch other LDAP operation errors
                logger.error(f"Password reset failed (LDAP operation error): {username}, {str(e)}")
                # The specific conditions (WILL_NOT_PERFORM, CONSTRAINT_VIOLATION) are handled inside the 'if not success_reset' block
                # This will catch other LDAPOperationResult errors if any fall through or if success_reset was unexpectedly True but conn.result indicates error.
                return False, "Password reset operation failed due to a server error. Please try again later. If the issue persists, contact your administrator."
            except Exception as e: # Catch any other unexpected errors during the reset process
                logger.error(f"Unexpected error during password reset process for {username}: {str(e)}")
                return False, "An unexpected internal error occurred while resetting the password. Please contact your administrator."

    except Exception as e: # Catch errors from LDAPConnection context manager or initial setup
        logger.error(f"Outer exception in reset_ad_password for {username}: {str(e)}")
        return False, "A system error occurred while processing your request. Please contact support."

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
    
    # Validate email address match
    ad_email = get_user_email_from_ad(username)
    if not ad_email:
        logger.warning(f"User '{username}' not found or user information cannot be retrieved for send-code API.")
        error_message = f"User '{username}' not found or unable to retrieve user information. Please check the username and try again. If the issue persists, contact support."
        return jsonify({'success': False, 'message': error_message}), 404
    
    # Compare email addresses ignoring case and stripping whitespace
    if email.lower().strip() != ad_email.lower().strip():
        logger.warning(f"User-provided email address does not match the one in the domain for user '{username}': provided={email}, actual={ad_email}")
        masked_email = mask_email(ad_email) # Ensure mask_email is robust for None or unexpected ad_email if it can happen
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

# Helper function: Partially hide email address
def mask_email(email):
    """Partially hide email address, showing only the first character, @ symbol, and domain"""
    if not email or '@' not in email:
        return "***@***.***"
    
    parts = email.split('@')
    username_part = parts[0] # Renamed to avoid conflict
    domain = parts[1]
    
    # Show only the first character of the username, replace the rest with *
    if len(username_part) > 1:
        masked_username = username_part[0] + '*' * (len(username_part) - 1)
    else:
        masked_username = '*'
    
    return f"{masked_username}@{domain}"

@app.route('/api/get-config', methods=['GET'])
def get_config():
    """Get API configuration information"""
    logger.info("Getting API configuration")
    # Get server IP and port from environment variables
    server_ip = os.getenv('SERVER_IP', '127.0.0.1')
    port = os.getenv('PORT', 5001)
    
    # Build base API URL
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

    # Re-validate email address match
    ad_email = get_user_email_from_ad(username) # This already logs if user is not found in AD
    if not ad_email or email.lower().strip() != ad_email.lower().strip(): # Added strip for robustness
        logger.warning(f"Email address mismatch during password reset: provided={email}, ad_email_found={ad_email if ad_email else 'None'}")
        return jsonify({'success': False, 'message': 'Invalid username or email. Please ensure you are using the same username and email you used to request the verification code.'}), 400

    if not verify_code(email, code):
        logger.warning(f"Verification code validation failed: email={email}")
        return jsonify({'success': False, 'message': 'The verification code is invalid or has expired. Please request a new code.'}), 400
    
    success_op, message_op = reset_ad_password(username, new_password) # Renamed to avoid conflict with jsonify
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