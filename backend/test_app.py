import pytest
from unittest.mock import patch
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
    assert json_data['message'] == 'Verification code has been sent, please check your email'
    mock_get_user_email.assert_called_once_with('testuser')
    mock_send_verification_code.assert_called_once_with('test@example.com')

@patch('backend.app.get_user_email_from_ad')
def test_send_code_user_not_found(mock_get_user_email, client):
    """Test /api/send-code when user's email is not found in AD."""
    mock_get_user_email.return_value = None

    response = client.post('/api/send-code', json={'username': 'unknownuser', 'email': 'test@example.com'})
    assert response.status_code == 404
    json_data = response.get_json()
    assert json_data['success'] is False
    assert 'User unknownuser not found' in json_data['message'] # Check for part of the message
    mock_get_user_email.assert_called_once_with('unknownuser')

@patch('backend.app.get_user_email_from_ad')
def test_send_code_email_mismatch(mock_get_user_email, client):
    """Test /api/send-code when provided email does not match AD email."""
    mock_get_user_email.return_value = 'ad_email@example.com'

    response = client.post('/api/send-code', json={'username': 'testuser', 'email': 'provided_email@example.com'})
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data['success'] is False
    assert "Provided email address does not match the user's email in AD" in json_data['message']
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
    assert json_data['message'] == 'Failed to send verification code, please check if the email address is correct or contact the system administrator'
    mock_get_user_email.assert_called_once_with('testuser')
    mock_send_verification_code.assert_called_once_with('test@example.com')

def test_send_code_missing_email(client):
    """Test /api/send-code with missing email in request."""
    response = client.post('/api/send-code', json={'username': 'testuser'})
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data['success'] is False
    assert json_data['message'] == 'Email address cannot be empty'

def test_send_code_missing_username(client):
    """Test /api/send-code with missing username in request."""
    response = client.post('/api/send-code', json={'email': 'test@example.com'})
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data['success'] is False
    assert json_data['message'] == 'Username cannot be empty'


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
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data['success'] is False
    assert json_data['message'] == 'Verification code is invalid or has expired'
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
    assert json_data['message'] == 'Username or email address is invalid'
    mock_get_user_email.assert_called_once_with('testuser')

def test_reset_password_missing_fields(client):
    """Test /api/reset-password with missing fields in the request."""
    response = client.post('/api/reset-password', json={'username': 'testuser', 'email': 'test@example.com'})
    assert response.status_code == 400
    json_data = response.get_json()
    assert json_data['success'] is False
    assert json_data['message'] == 'All fields are required'


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
