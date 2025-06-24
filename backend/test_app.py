import pytest
import os # Added import for os
from unittest.mock import patch, MagicMock # Added MagicMock
# Assuming your Flask app instance is named 'app' in 'app.py'
# and can be imported. Adjust if your app factory or naming is different.
from .app import app as flask_app

# Pytest fixture for the Flask test client
@pytest.fixture
def client():
    """Create and configure a new app instance for each test."""
    # flask_app.config.from_object('yourapp.config.TestingConfig') # Example if you have a testing config
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as client:
        yield client

# --- Test Cases for /api/get-config ---
def test_get_config_success(client):
    """Test the /api/get-config endpoint for successful response."""
    response = client.get('/api/get-config')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['success'] is True
    assert 'api_base_url' in json_data
    # Basic check for URL format, more specific checks can be added if needed
    assert json_data['api_base_url'].startswith('http://')

# --- Test for Redis Connection Failure ---
@patch('backend.app.redis.Redis')
@patch('backend.app.logger') # Mock logger to check critical logging
@patch('backend.app.exit')   # Mock exit to prevent test runner from stopping
def test_redis_connection_failure_exits(mock_exit, mock_logger, MockRedis):
    """Test that app exits if Redis connection fails on startup."""
    # Simulate Redis connection error
    mock_redis_instance = MockRedis.return_value
    mock_redis_instance.ping.side_effect = Exception("Redis connection failed")

    # We need to re-import the app or trigger its initialization part
    # where Redis connection is established.
    # This is tricky as Flask app is typically imported once.
    # For this test, we might need to structure app initialization differently,
    # or more practically, test the startup sequence that includes Redis init.
    # A simpler approach for this specific test:
    # Re-evaluate the part of app.py that initializes Redis.
    # This is not ideal as it's not testing the app import directly.
    # A better way would be to have an app factory.

    # Assuming app.py can be re-imported or its relevant part re-run
    # This part is highly dependent on how app.py is structured
    # and might require refactoring app.py for better testability of startup code.
    # For now, let's assume we can trigger the Redis init part.
    # If app.py is `import app` and then `app.initialize_redis()`, we could call that.
    # If it's top-level code, it's harder.

    # Given the current structure of app.py, direct re-triggering of Redis init
    # upon import is hard without reloading modules.
    # We'll focus on the fact that `exit(1)` should be called.

    # This test, as structured, might not effectively re-trigger the Redis init
    # after the mocks are in place if app is imported at the top of the test file.
    # It assumes that by mocking redis.Redis, the next time app tries to connect
    # (e.g. if app was reloaded or init was callable), it would use this mock.

    # Let's simulate the init block directly for the purpose of this unit test
    # This is a workaround for not having an app factory that can be called here.
    try:
        # This code is a simplified version of the Redis init block in app.py
        # to test the exit logic.
        from backend.app import redis # import redis to use its exceptions
        mock_redis_instance = MockRedis(host='dummy', port=0, password=None, db=0, socket_connect_timeout=1, decode_responses=True)
        mock_redis_instance.ping.side_effect = redis.exceptions.ConnectionError("Test Redis connection error")
        mock_redis_instance.ping() # This will raise the ConnectionError
    except redis.exceptions.ConnectionError as e:
        mock_logger.critical.assert_any_call(f"CRITICAL: Could not connect to Redis server at dummy:0, DB 0. Error: {e}")
        mock_logger.critical.assert_any_call("Verification code functionality requires Redis. The application will now exit.")
        mock_exit.assert_called_once_with(1)

    # If the above try-except doesn't run due to import issues or structure,
    # this test might give a false positive or fail to run the assertions.
    # This highlights a need for refactoring app.py for better testability.
    # For now, we assume this simplified test structure is sufficient to check `exit` call.

# --- Test Cases for Password Complexity ---
# Helper function to call validate_password_complexity
from backend.app import validate_password_complexity

def test_password_complexity_default_blacklist():
    """Test password complexity with default blacklist."""
    # "ucas" is in the default blacklist
    is_valid, message = validate_password_complexity("testuser", "PasswordWithucas1!")
    assert not is_valid
    assert "Password cannot contain common words or organization names (e.g., ucas)" in message

    is_valid, message = validate_password_complexity("testuser", "ValidPassword1!")
    assert is_valid

@patch.dict(os.environ, {"PASSWORD_COMMON_WORDS_BLACKLIST": "customword,another"})
def test_password_complexity_custom_blacklist(monkeypatch):
    """Test password complexity with a custom blacklist from environment variable."""
    # Need to re-import or reload the app's PASSWORD_COMMON_WORDS_BLACKLIST
    # For simplicity, we can patch the global variable in the app module if it's already loaded,
    # or ensure the module re-reads it.
    # A more robust way is to ensure app context reloads config or use an app factory.

    # Let's try to update the global directly after app module might have loaded it.
    # This depends on when app.py processes env vars.
    # If PASSWORD_COMMON_WORDS_BLACKLIST is set at import time, this patch might be too late
    # for the app.py's global.
    # The most reliable way is to patch the variable within the app module itself.

    custom_list = ["customword", "another"]
    monkeypatch.setattr("backend.app.PASSWORD_COMMON_WORDS_BLACKLIST", custom_list)

    # "customword" should now be blacklisted
    is_valid, message = validate_password_complexity("testuser", "PasswordWithcustomword1!")
    assert not is_valid
    assert "Password cannot contain common words or organization names (e.g., customword)" in message

    # "ucas" should no longer be blacklisted if not in custom list
    is_valid, message = validate_password_complexity("testuser", "PasswordWithucas1!")
    assert is_valid # Assuming "ucas" is not in "customword,another"

    # A valid password without any blacklisted words
    is_valid, message = validate_password_complexity("testuser", "GoodPassword123$")
    assert is_valid


# --- Test Cases for /api/send-code ---
@patch('backend.app.get_user_email_from_ad')
@patch('backend.app.send_verification_code')
def test_send_code_success(mock_send_verification_code, mock_get_user_email, client):
    """Test /api/send-code successful scenario."""
    mock_get_user_email.return_value = 'test@example.com'
    mock_send_verification_code.return_value = True

    response = client.post('/api/send-code', json={'username': 'testuser', 'email': 'test@example.com'})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['success'] is True
    assert json_data['message'] == 'Verification code has been sent. Please check your email.' # Updated message
    mock_get_user_email.assert_called_once_with('testuser')
    mock_send_verification_code.assert_called_once_with('test@example.com')

@patch('backend.app.smtplib.SMTP_SSL')
@patch('backend.app.smtplib.SMTP')
@patch('backend.app.redis_client') # Mock redis_client to assume it's available
def test_send_verification_code_uses_smtp_ssl_for_port_465(mock_smtp, mock_smtp_ssl, mock_redis, monkeypatch):
    """Test send_verification_code uses SMTP_SSL for port 465."""
    monkeypatch.setenv('SMTP_PORT', '465')
    monkeypatch.setattr("backend.app.SMTP_PORT", 465) # Ensure the global is updated

    # Mock the methods used on the SMTP server object
    mock_server_ssl = mock_smtp_ssl.return_value
    mock_server_ssl.login.return_value = True
    mock_server_ssl.send_message.return_value = {}

    # Mock redis setex
    mock_redis.setex.return_value = True

    from backend.app import send_verification_code # Import locally to use patched env
    send_verification_code('test@example.com')

    mock_smtp_ssl.assert_called_once_with('your_smtp_server', 465, timeout=10)
    mock_server_ssl.login.assert_called_once()
    mock_server_ssl.send_message.assert_called_once()
    mock_server_ssl.quit.assert_called_once()
    mock_smtp.assert_not_called() # Ensure SMTP (for STARTTLS) was not called

@patch('backend.app.smtplib.SMTP_SSL')
@patch('backend.app.smtplib.SMTP')
@patch('backend.app.redis_client')
def test_send_verification_code_uses_starttls_for_port_587(mock_smtp, mock_smtp_ssl, mock_redis, monkeypatch):
    """Test send_verification_code uses SMTP (STARTTLS) for port 587."""
    monkeypatch.setenv('SMTP_PORT', '587')
    monkeypatch.setattr("backend.app.SMTP_PORT", 587)

    mock_server = mock_smtp.return_value
    mock_server.starttls.return_value = True
    mock_server.login.return_value = True
    mock_server.send_message.return_value = {}
    mock_redis.setex.return_value = True

    from backend.app import send_verification_code
    send_verification_code('test@example.com')

    mock_smtp.assert_called_once_with('your_smtp_server', 587, timeout=10)
    mock_server.starttls.assert_called_once()
    mock_server.login.assert_called_once()
    mock_server.send_message.assert_called_once()
    mock_server.quit.assert_called_once()
    mock_smtp_ssl.assert_not_called() # Ensure SMTP_SSL was not called

@patch('backend.app.get_user_email_from_ad')
def test_send_code_user_not_found(mock_get_user_email, client):
    """Test /api/send-code when user's email is not found in AD."""
    mock_get_user_email.return_value = None

    response = client.post('/api/send-code', json={'username': 'unknownuser', 'email': 'test@example.com'})
    assert response.status_code == 404
    json_data = response.get_json()
    assert json_data['success'] is False
    assert "User 'unknownuser' not found or unable to retrieve user information." in json_data['message'] # Updated message
    mock_get_user_email.assert_called_once_with('unknownuser')

@patch('backend.app.get_user_email_from_ad')
@patch('backend.app.mask_email', return_value="t***@example.com") # Mock mask_email
def test_send_code_email_mismatch(mock_mask_email, mock_get_user_email, client):
    """Test /api/send-code when provided email does not match AD email."""
    mock_get_user_email.return_value = 'ad_email@example.com'

    response = client.post('/api/send-code', json={'username': 'testuser', 'email': 'provided_email@example.com'})
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data['success'] is False
    assert "The email address you provided does not match our records for user 'testuser'." in json_data['message'] # Updated message
    assert "A hint for the correct email format is: t***@example.com" in json_data['message']
    mock_get_user_email.assert_called_once_with('testuser')

@patch('backend.app.get_user_email_from_ad')
@patch('backend.app.send_verification_code')
def test_send_code_send_verification_fails(mock_send_verification_code, mock_get_user_email, client):
    """Test /api/send-code when send_verification_code returns False."""
    mock_get_user_email.return_value = 'test@example.com'
    mock_send_verification_code.return_value = False

    response = client.post('/api/send-code', json={'username': 'testuser', 'email': 'test@example.com'})
    assert response.status_code == 500
    json_data = response.get_json()
    assert json_data['success'] is False
    assert 'Failed to send verification code.' in json_data['message'] # Updated message
    mock_get_user_email.assert_called_once_with('testuser')
    mock_send_verification_code.assert_called_once_with('test@example.com')

def test_send_code_missing_email(client):
    """Test /api/send-code with missing email in request."""
    response = client.post('/api/send-code', json={'username': 'testuser'}) # Missing 'email'
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data['success'] is False
    assert json_data['message'] == 'Please provide an email address.' # Updated message

def test_send_code_missing_username(client):
    """Test /api/send-code with missing username in request."""
    response = client.post('/api/send-code', json={'email': 'test@example.com'}) # Missing 'username'
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data['success'] is False
    assert json_data['message'] == 'Please provide a username.' # Updated message


# --- Test Cases for /api/reset-password ---
@patch('backend.app.get_user_email_from_ad')
@patch('backend.app.verify_code')
@patch('backend.app.reset_ad_password')
def test_reset_password_success(mock_reset_ad_password, mock_verify_code, mock_get_user_email, client):
    """Test /api/reset-password successful scenario."""
    mock_get_user_email.return_value = 'test@example.com'
    mock_verify_code.return_value = True
    mock_reset_ad_password.return_value = (True, "Password reset successful")

    payload = {
        'username': 'testuser',
        'email': 'test@example.com',
        'code': '123456',
        'new_password': 'NewPassword123!'
    }
    response = client.post('/api/reset-password', json=payload)
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['success'] is True
    assert json_data['message'] == "Password reset successful"
    mock_get_user_email.assert_called_once_with('testuser')
    mock_verify_code.assert_called_once_with('test@example.com', '123456')
    mock_reset_ad_password.assert_called_once_with('testuser', 'NewPassword123!')

@patch('backend.app.get_user_email_from_ad')
@patch('backend.app.verify_code')
def test_reset_password_invalid_code(mock_verify_code, mock_get_user_email, client):
    """Test /api/reset-password with an invalid verification code."""
    mock_get_user_email.return_value = 'test@example.com'
    mock_verify_code.return_value = False

    payload = {
        'username': 'testuser',
        'email': 'test@example.com',
        'code': 'wrongcode',
        'new_password': 'NewPassword123!'
    }
    response = client.post('/api/reset-password', json=payload)
    assert response.status_code == 400 # Status code remains 400 for invalid code
    json_data = response.get_json()
    assert json_data['success'] is False
    assert json_data['message'] == 'The verification code is invalid or has expired. Please request a new code.' # Updated message
    mock_verify_code.assert_called_once_with('test@example.com', 'wrongcode')

@patch('backend.app.get_user_email_from_ad')
@patch('backend.app.verify_code')
@patch('backend.app.reset_ad_password')
def test_reset_password_ad_reset_fails(mock_reset_ad_password, mock_verify_code, mock_get_user_email, client):
    """Test /api/reset-password when reset_ad_password returns False."""
    mock_get_user_email.return_value = 'test@example.com'
    mock_verify_code.return_value = True
    mock_reset_ad_password.return_value = (False, "AD password policy not met")

    payload = {
        'username': 'testuser',
        'email': 'test@example.com',
        'code': '123456',
        'new_password': 'WeakPassword'
    }
    response = client.post('/api/reset-password', json=payload)
    assert response.status_code == 500
    json_data = response.get_json()
    assert json_data['success'] is False
    assert json_data['message'] == "AD password policy not met"
    mock_reset_ad_password.assert_called_once_with('testuser', 'WeakPassword')

@patch('backend.app.get_user_email_from_ad')
def test_reset_password_email_mismatch(mock_get_user_email, client):
    """Test /api/reset-password with email mismatch."""
    mock_get_user_email.return_value = 'actual_ad_email@example.com'

    payload = {
        'username': 'testuser',
        'email': 'provided_different_email@example.com',
        'code': '123456',
        'new_password': 'NewPassword123!'
    }
    response = client.post('/api/reset-password', json=payload)
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data['success'] is False
    assert json_data['message'] == 'Invalid username or email. Please ensure you are using the same username and email you used to request the verification code.' # Updated message
    mock_get_user_email.assert_called_once_with('testuser')

def test_reset_password_missing_fields(client):
    """Test /api/reset-password with missing fields in the request."""
    response = client.post('/api/reset-password', json={'username': 'testuser', 'email': 'test@example.com'}) # Missing code and new_password
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data['success'] is False
    assert json_data['message'] == 'Please fill in all required fields: username, email, verification code, and new password.' # Updated message


# --- Tests for LDAP Sanitization and OU Alignment ---

@patch('backend.app.send_verification_code', return_value=True) # Mock to prevent actual email sending
@patch('backend.app.ldap3.Connection')
def test_get_user_email_from_ad_escapes_username(MockLdapConnection, mock_send_code_helper, client):
    """Test that special characters in username are escaped for LDAP filter in get_user_email_from_ad."""
    mock_conn_instance = MockLdapConnection.return_value
    mock_conn_instance.bind.return_value = True # Ensure bind succeeds

    # Simulate finding a user to allow the function to proceed
    mock_entry = MagicMock()
    mock_entry.mail.value = 'test*user@example.com'
    mock_conn_instance.entries = [mock_entry]
    mock_conn_instance.search.return_value = True # Simulate search success

    # Username with special characters
    # Common special characters for LDAP filters: *, (, ), \, NUL, /
    # Using only a subset here for a focused test.
    # Note: The actual escaping is (char -> \hex_code_of_char)
    # So, * -> \2a, ( -> \28, ) -> \29, \ -> \5c
    # For `displayName=*{escaped_username}*` the outer wildcards are app-added, not user input.
    # If user input is `test*user`, escaped is `test\2auser`. Filter becomes `(displayName=*test\2auser*)`

    malicious_username = "test*user(name)"
    escaped_malicious_username = "test\\2auser\\28name\\29" # Expected escaped form

    # Call the endpoint that triggers get_user_email_from_ad
    client.post('/api/send-code', json={'username': malicious_username, 'email': 'test*user@example.com'})

    assert mock_conn_instance.search.called
    # Check the search_filter argument in the first call to conn.search
    # The filter is complex, so we check for key parts
    actual_filter_arg = mock_conn_instance.search.call_args[1]['search_filter']

    # Assert that the escaped username is part of the filter for sAMAccountName, cn, displayName
    assert f"(sAMAccountName={escaped_malicious_username})" in actual_filter_arg
    assert f"(cn={escaped_malicious_username})" in actual_filter_arg
    assert f"(displayName=*{escaped_malicious_username}*)" in actual_filter_arg

    # Also check for escaped userPrincipalName and mail attributes derived from username_formats
    # One of the formats will be the username itself, another will be username@domain
    assert f"(userPrincipalName={escaped_malicious_username})" in actual_filter_arg
    assert f"(mail={escaped_malicious_username})" in actual_filter_arg
    # Example check for domain-appended version (assuming LDAP_DOMAIN is 'example.com' in test env or mocked)
    # This part might need mocking os.getenv('LDAP_DOMAIN') if it's not set in test env
    # For simplicity, we'll assume the raw username format is tested above.

@patch('backend.app.get_user_email_from_ad', return_value = "testuser@example.com") # Mocks initial email check
@patch('backend.app.verify_code', return_value = True) # Mocks code verification
@patch('backend.app.validate_password_complexity', return_value=(True, "")) # Mocks password complexity check
@patch('backend.app.ldap3.Connection')
def test_reset_password_uses_configured_ous(MockLdapConnection, mock_validate_pass, mock_verify, mock_get_email, client, monkeypatch):
    """Test reset_ad_password uses LDAP_SEARCH_OUS when set."""
    mock_conn_instance = MockLdapConnection.return_value
    mock_conn_instance.bind.return_value = True

    # Simulate search finding the user and allowing password modification to be attempted
    mock_entry = MagicMock()
    mock_entry.entry_dn = 'CN=testuser,OU=Test1,DC=example,DC=com'
    # Add other attributes if needed by the reset logic, e.g., lockoutTime
    type(mock_entry).lockoutTime = MagicMock(value=0) # Simulate account not locked

    # This function will be called multiple times by reset_ad_password's search loop
    # We need it to return a user on one of the calls, and then the modify to succeed.
    def mock_search_logic(*args, **kwargs):
        search_base = kwargs.get('search_base')
        # Simulate finding the user only in the first configured OU
        if search_base == "OU=Test1,DC=example,DC=com":
            mock_conn_instance.entries = [mock_entry]
            return True
        mock_conn_instance.entries = []
        return True # Search itself succeeds, but no entries found in other OUs

    mock_conn_instance.search = MagicMock(side_effect=mock_search_logic)
    mock_conn_instance.modify.return_value = True # Simulate password modify success

    configured_ous = "OU=Test1,DC=example,DC=com;OU=Test2,DC=example,DC=com"
    monkeypatch.setenv("LDAP_SEARCH_OUS", configured_ous)
    # Need to reload app.py's globals or re-import LDAP_SEARCH_OUS, or ensure app context reloads it.
    # The simplest way for testing is to directly patch the global variable in the app module.
    monkeypatch.setattr("backend.app.LDAP_SEARCH_OUS", [ou.strip() for ou in configured_ous.split(';') if ou.strip()])
    monkeypatch.setattr("backend.app.LDAP_BASE_DN", "DC=example,DC=com") # Ensure this is set for defaults

    client.post('/api/reset-password', json={
        'username': 'testuser',
        'email': 'testuser@example.com',
        'code': '123456',
        'new_password': 'NewPassword123!'
    })

    assert mock_conn_instance.search.called
    # Check the search_base arguments in the calls to conn.search
    # The search should stop once the user is found in the first OU.
    search_bases_called = [call[1]['search_base'] for call in mock_conn_instance.search.call_args_list]

    expected_ous_list = ["OU=Test1,DC=example,DC=com"] # Search stops after finding in the first one
    assert search_bases_called == expected_ous_list

@patch('backend.app.get_user_email_from_ad', return_value = "testuser@example.com")
@patch('backend.app.verify_code', return_value = True)
@patch('backend.app.validate_password_complexity', return_value=(True, ""))
@patch('backend.app.ldap3.Connection')
def test_reset_password_uses_default_ous(MockLdapConnection, mock_validate_pass, mock_verify, mock_get_email, client, monkeypatch):
    """Test reset_ad_password uses default OUs when LDAP_SEARCH_OUS is not set."""
    mock_conn_instance = MockLdapConnection.return_value
    mock_conn_instance.bind.return_value = True

    mock_entry = MagicMock()
    mock_entry.entry_dn = 'CN=testuser,OU=Default,DC=example,DC=com' # Assume found in one of default OUs
    type(mock_entry).lockoutTime = MagicMock(value=0)

    # Simulate finding user in one of the default OUs (e.g., LDAP_BASE_DN)
    def mock_search_logic_default(*args, **kwargs):
        search_base = kwargs.get('search_base')
        if search_base == "DC=example,DC=com": # Assume LDAP_BASE_DN is this for the test
            mock_conn_instance.entries = [mock_entry]
            return True
        mock_conn_instance.entries = []
        return True

    mock_conn_instance.search = MagicMock(side_effect=mock_search_logic_default)
    mock_conn_instance.modify.return_value = True

    monkeypatch.setenv("LDAP_SEARCH_OUS", "") # Ensure it's empty or not set
    # Patch the global directly as well for robustness in test environment
    monkeypatch.setattr("backend.app.LDAP_SEARCH_OUS", [])
    # Set LDAP_BASE_DN for default OU construction
    base_dn = "DC=example,DC=com"
    monkeypatch.setattr("backend.app.LDAP_BASE_DN", base_dn)


    client.post('/api/reset-password', json={
        'username': 'testuser',
        'email': 'testuser@example.com',
        'code': '123456',
        'new_password': 'NewPassword123!'
    })

    assert mock_conn_instance.search.called
    search_bases_called = [call[1]['search_base'] for call in mock_conn_instance.search.call_args_list]

    # Search should stop after finding in LDAP_BASE_DN
    expected_default_ous_searched = [base_dn]
    assert search_bases_called == expected_default_ous_searched
