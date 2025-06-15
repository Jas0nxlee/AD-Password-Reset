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
