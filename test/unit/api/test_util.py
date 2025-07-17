# Copyright 2025 University of Southern California

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pytest
import json
import time
import hashlib
import requests
from unittest.mock import Mock, patch, MagicMock
from flask import Flask, g, Response
from requests import JSONDecodeError

import deriva.web.groups.api.util as util
from deriva.web.groups.api.util import (
    make_json_response, SessionManager, require_auth, is_browser_client
)


class TestUtilFunctions:
    def test_make_json_response(self):
        data = {"message": "success", "count": 42}
        response = make_json_response(data)
        assert isinstance(response, Response)
        assert response.mimetype == "application/json"
        response_data = json.loads(response.get_data(as_text=True))
        assert response_data == data

    def test_make_json_response_preserves_order(self):
        data = {"z": 1, "a": 2, "m": 3}
        response = make_json_response(data)
        response_text = response.get_data(as_text=True)
        assert '"z"' in response_text
        assert '"a"' in response_text
        assert '"m"' in response_text


class TestSessionManager:
    def test_init(self, memory_storage):
        session_manager = SessionManager(
            storage=memory_storage,
            auth_base_url="https://localhost/authn/",
            cache_ttl=600
        )
        assert session_manager.storage == memory_storage
        assert session_manager.auth_base_url == "https://localhost/authn"
        assert session_manager.cache_ttl == 600
        assert session_manager.refresh_threshold == 480

    def test_generate_cache_key(self):
        token = "test_token_123"
        expected_key = hashlib.sha256(token.encode()).hexdigest()
        cache_key = SessionManager._generate_cache_key(token)
        assert cache_key == expected_key
        assert len(cache_key) == 64

    def test_extract_authorization_bearer_token(self):
        app = Flask(__name__)
        app.config["COOKIE_NAME"] = "webauthn"
        with app.test_request_context(headers={"Authorization": "Bearer test_token_123"}):
            auth, is_token = SessionManager._extract_authorization()
            assert auth == "test_token_123"
            assert is_token is True

    def test_extract_authorization_cookie(self):
        app = Flask(__name__)
        app.config["COOKIE_NAME"] = "webauthn"
        with app.test_request_context(environ_base={"HTTP_COOKIE": "webauthn=cookie_token_456"}):
            auth, is_token = SessionManager._extract_authorization()
            assert auth == "cookie_token_456"
            assert is_token is False

    def test_extract_authorization_no_auth(self):
        app = Flask(__name__)
        app.config["COOKIE_NAME"] = "webauthn"
        with app.test_request_context():
            auth, is_token = SessionManager._extract_authorization()
            assert auth is None
            assert is_token is False

    def test_fetch_session_from_auth_service_request_exception(self, memory_storage):
        app = Flask(__name__)
        app.config["COOKIE_NAME"] = "webauthn"
        with app.app_context():
            session_manager = SessionManager(memory_storage, "https://localhost/authn")
            with patch.object(util.requests, "get", side_effect=requests.RequestException("Network error")), \
                 patch.object(session_manager, "_extract_authorization", return_value=("token123", True)), \
                 patch("deriva.web.groups.api.util.logger.error") as mock_logger:
                result = session_manager._fetch_session_from_auth_service()
                assert result is None
                mock_logger.assert_called()

    def test_extend_session_at_auth_service_exception(self, memory_storage):
        app = Flask(__name__)
        app.config["COOKIE_NAME"] = "webauthn"
        with app.app_context():
            session_manager = SessionManager(memory_storage, "https://localhost/authn")
            with patch.object(util.requests, "put", side_effect=requests.RequestException("Network error")), \
                 patch.object(session_manager, "_extract_authorization", return_value=("token123", True)), \
                 patch("deriva.web.groups.api.util.logger.error") as mock_logger:
                result = session_manager._extend_session_at_auth_service()
                assert result is None
                mock_logger.assert_called()

    def test_validate_session_active_exception(self, memory_storage):
        app = Flask(__name__)
        app.config["COOKIE_NAME"] = "webauthn"
        with app.app_context():
            session_manager = SessionManager(memory_storage, "https://localhost/authn")
            with patch.object(util.requests, "head", side_effect=requests.RequestException("Network error")), \
                 patch.object(session_manager, "_extract_authorization", return_value=("token123", True)), \
                 patch("deriva.web.groups.api.util.logger.error") as mock_logger:
                result = session_manager._validate_session_active()
                assert result is False

    def test_get_user_session_stale_cache_valid_session(self, memory_storage):
        app = Flask(__name__)
        app.config["COOKIE_NAME"] = "webauthn"
        with app.app_context():
            session_manager = SessionManager(memory_storage, "https://localhost/authn", cache_ttl=300)
            cache_key = SessionManager._generate_cache_key("token123")
            cached_data = {
                'session_data': {"sub": "user123", "email": "user@example.com"},
                'cached_at': time.time() - 350  # stale by 50s
            }
            memory_storage.set_session(cache_key, cached_data, 300)
            with patch.object(session_manager, '_extract_authorization', return_value=("token123", True)), \
                    patch.object(session_manager, '_validate_session_active', return_value=True), \
                    patch.object(session_manager, '_extend_session_at_auth_service',
                                 return_value={"sub": "user123", "email": "user@example.com"}), \
                    patch.object(session_manager, '_fetch_session_from_auth_service',
                                 return_value={"sub": "user123", "email": "user@example.com"}):
                result = session_manager.get_user_session()
                assert result == {"sub": "user123", "email": "user@example.com"}

    def test_get_user_session_json_decode_error(self, memory_storage):
        app = Flask(__name__)
        app.config['COOKIE_NAME'] = 'webauthn'
        with app.app_context():
            session_manager = SessionManager(memory_storage, "https://localhost/authn", cache_ttl=300)
            cache_key = SessionManager._generate_cache_key("token123")
            memory_storage.backend.set(f"session:{cache_key}", "invalid_json")
            session_data = {"sub": "user123", "email": "user@example.com"}
            with patch.object(session_manager, '_extract_authorization', return_value=("token123", True)), \
                 patch.object(session_manager, '_fetch_session_from_auth_service', return_value=session_data), \
                 patch.object(memory_storage, 'get_session', side_effect=JSONDecodeError("error", "invalid_json", 0)), \
                 patch('deriva.web.groups.api.util.logger.error') as mock_log_error:
                result = session_manager.get_user_session()
                assert result == session_data
                mock_log_error.assert_called()

    def test_get_user_session_storage_error(self, memory_storage):
        """Test get_user_session with storage error"""
        session_manager = SessionManager(memory_storage, "/authn", cache_ttl=300)

        session_data = {"sub": "user123", "email": "user@example.com"}

        with patch.object(session_manager, '_extract_authorization', return_value=("token123", True)), \
             patch.object(session_manager, '_fetch_session_from_auth_service', return_value=session_data), \
             patch.object(memory_storage, 'get_session', side_effect=Exception("Storage error")), \
             patch('deriva.web.groups.api.util.logger') as mock_logger:

            result = session_manager.get_user_session()

        assert result == session_data
        # Should log the storage error
        mock_logger.error.assert_called()

    def test_invalidate_session_success(self, memory_storage):
        """Test successful session invalidation"""
        session_manager = SessionManager(memory_storage, "/authn")

        # Set up cache data
        cache_key = SessionManager._generate_cache_key("token123")
        cached_data = {"session_data": {"sub": "user123"}, "cached_at": time.time()}
        memory_storage.set_session(cache_key, cached_data, 300)

        result = session_manager.invalidate_session(cache_key)

        assert result is True
        assert memory_storage.get_session(cache_key) is None

    def test_invalidate_session_empty_key(self, memory_storage):
        """Test session invalidation with empty key"""
        session_manager = SessionManager(memory_storage, "/authn")

        result = session_manager.invalidate_session("")

        assert result is False

    def test_invalidate_session_storage_error(self, memory_storage):
        """Test session invalidation with storage error"""
        session_manager = SessionManager(memory_storage, "/authn")

        with patch.object(memory_storage, 'delete_session', side_effect=Exception("Storage error")), \
             patch('deriva.web.groups.api.util.logger') as mock_logger:

            result = session_manager.invalidate_session("some_key")

        assert result is False
        mock_logger.error.assert_called()


class TestRequireAuthDecorator:
    """Test require_auth decorator"""

    def test_require_auth_success(self):
        """Test successful authentication"""
        app = Flask(__name__)
        app.config['TESTING'] = True

        # Mock session manager
        mock_session_manager = Mock()
        mock_session_manager.get_user_session.return_value = {
            'sub': 'user123',
            'email': 'user@example.com',
            'name': 'Test User'
        }
        app.config['SESSION_MANAGER'] = mock_session_manager
        app.config['ENABLE_LEGACY_AUTH_API'] = False

        @require_auth
        def test_route():
            return {"user_id": g.user_id, "user_email": g.user_email}

        with app.test_request_context():
            result = test_route()

            assert result == {"user_id": "user123", "user_email": "user@example.com"}
            assert g.current_user['sub'] == 'user123'
            assert g.user_id == 'user123'
            assert g.user_email == 'user@example.com'
            assert g.user_name == 'Test User'

    def test_require_auth_legacy_api(self):
        """Test authentication with legacy API enabled"""
        app = Flask(__name__)
        app.config['TESTING'] = True

        # Mock session manager
        mock_session_manager = Mock()
        mock_session_manager.get_user_session.return_value = {
            'client': {
                'id': 'user123',
                'email': 'user@example.com',
                'full_name': 'Test User'
            }
        }
        app.config['SESSION_MANAGER'] = mock_session_manager
        app.config['ENABLE_LEGACY_AUTH_API'] = True

        @require_auth
        def test_route():
            return {"user_id": g.user_id, "user_email": g.user_email}

        with app.test_request_context():
            result = test_route()

            assert result == {"user_id": "user123", "user_email": "user@example.com"}
            assert g.user_id == 'user123'
            assert g.user_email == 'user@example.com'
            assert g.user_name == 'Test User'

    def test_require_auth_no_session(self):
        """Test authentication failure"""
        app = Flask(__name__)
        app.config['TESTING'] = True

        # Mock session manager returning None
        mock_session_manager = Mock()
        mock_session_manager.get_user_session.return_value = None
        app.config['SESSION_MANAGER'] = mock_session_manager

        @require_auth
        def test_route():
            return {"message": "success"}

        with app.test_request_context():
            with pytest.raises(Exception):  # Should abort with 401
                test_route()


class TestIsBrowserClient:
    """Test is_browser_client function"""

    def test_is_browser_client_with_cookie_and_html(self):
        """Test browser detection with cookie and HTML accept header"""
        app = Flask(__name__)
        app.config['COOKIE_NAME'] = 'webauthn'

        with app.test_request_context():
            # Create a mock request object
            mock_request = Mock()
            mock_request.cookies = {'webauthn': 'test_token'}
            mock_request.headers = Mock()
            mock_request.headers.get = Mock(side_effect=lambda key, default="": {
                'Accept': 'text/html,application/xhtml+xml',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }.get(key, default))

            result = is_browser_client(mock_request)

            assert result is True

    def test_is_browser_client_with_cookie_and_browser_ua(self):
        """Test browser detection with cookie and browser user agent"""
        app = Flask(__name__)
        app.config['COOKIE_NAME'] = 'webauthn'

        with app.test_request_context():
            mock_request = Mock()
            mock_request.cookies = {'webauthn': 'test_token'}
            mock_request.headers = Mock()
            mock_request.headers.get = Mock(side_effect=lambda key, default="": {
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (compatible; Chrome/91.0.4472.124)'
            }.get(key, default))

            result = is_browser_client(mock_request)

            assert result is True

    def test_is_browser_client_no_cookie(self):
        """Test browser detection without cookie"""
        app = Flask(__name__)
        app.config['COOKIE_NAME'] = 'webauthn'

        with app.test_request_context():
            mock_request = Mock()
            mock_request.cookies = {}
            mock_request.headers = Mock()
            mock_request.headers.get = Mock(side_effect=lambda key, default="": {
                'Accept': 'text/html',
                'User-Agent': 'Mozilla/5.0'
            }.get(key, default))

            result = is_browser_client(mock_request)

            assert result is False

    def test_is_browser_client_api_client(self):
        """Test API client detection"""
        app = Flask(__name__)
        app.config['COOKIE_NAME'] = 'webauthn'

        with app.test_request_context():
            mock_request = Mock()
            mock_request.cookies = {'webauthn': 'test_token'}
            mock_request.headers = Mock()
            mock_request.headers.get = Mock(side_effect=lambda key, default="": {
                'Accept': 'application/json',
                'User-Agent': 'python-requests/2.25.1'
            }.get(key, default))

            result = is_browser_client(mock_request)

            assert result is False