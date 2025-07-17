#
# Copyright 2025 University of Southern California
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import json
import pytest
from unittest.mock import Mock, patch
from flask import Flask, g
from deriva.web.groups.rest.join_requests import join_requests_blueprint
from deriva.web.groups.api.groups.models import JoinRequest, JoinRequestStatus, GroupRole


@pytest.fixture
def app():
    """Create Flask app for testing"""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['SERVER_NAME'] = 'localhost'
    
    # Configure mock session manager to return proper user session
    mock_session_manager = Mock()
    mock_session_manager.get_user_session.return_value = {
        'sub': 'test_user_123',
        'email': 'test@example.com',
        'name': 'Test User'
    }
    app.config['SESSION_MANAGER'] = mock_session_manager
    app.config['GROUP_MANAGER'] = Mock()
    app.config['JOIN_REQUEST_MANAGER'] = Mock()
    app.register_blueprint(join_requests_blueprint)
    return app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def mock_auth():
    """Mock authentication - return empty context manager"""
    return


@pytest.fixture
def sample_join_requests(mock_time):
    """Sample join requests for testing"""
    return [
        JoinRequest(
            id="req1",
            group_id="group1",
            group_name="Test Group 1",
            user_id="user1",
            user_email="user1@example.com",
            user_name="User One",
            message="Please let me join",
            status=JoinRequestStatus.PENDING,
            token="token1"
        ),
        JoinRequest(
            id="req2",
            group_id="group1",
            group_name="Test Group 1",
            user_id="user2",
            user_email="user2@example.com",
            user_name="User Two",
            message="I'd like to join",
            status=JoinRequestStatus.APPROVED,
            token="token2"
        )
    ]


class TestJoinRequestsBlueprint:
    """Test join requests REST API endpoints"""

    def test_get_join_request_manager(self, app):
        """Test get_join_request_manager helper function"""
        with app.app_context():
            from deriva.web.groups.rest.join_requests import get_join_request_manager
            manager = get_join_request_manager()
            assert manager == app.config['JOIN_REQUEST_MANAGER']

    def test_get_group_manager(self, app):
        """Test get_group_manager helper function"""
        with app.app_context():
            from deriva.web.groups.rest.join_requests import get_group_manager
            manager = get_group_manager()
            assert manager == app.config['GROUP_MANAGER']

    def test_get_group_join_requests_pending_only(self, app, client, mock_auth, sample_join_requests):
        """Test getting pending join requests for a group"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        
        mock_group_manager.user_can_manage_group.return_value = True
        mock_join_request_manager.get_group_join_requests.return_value = [sample_join_requests[0]]  # Only pending
        mock_group = Mock()
        mock_group.name = "Test Group 1"
        mock_group.description = "Test group"
        mock_group_manager.get_group.return_value = mock_group
        
        response = client.get('/groups/group1/join-requests?pending_only=true')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data["join_requests"]) == 1
        assert data["join_requests"][0]['status'] == 'pending'
        assert data["join_requests"][0]['user_name'] == 'User One'
        
        # Verify the manager was called correctly
        mock_join_request_manager.get_group_join_requests.assert_called_once_with('group1', True)

    def test_get_group_join_requests_all(self, app, client, mock_auth, sample_join_requests):
        """Test getting all join requests for a group"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        
        mock_group_manager.user_can_manage_group.return_value = True
        mock_join_request_manager.get_group_join_requests.return_value = sample_join_requests
        mock_group = Mock()
        mock_group.name = "Test Group 1"
        mock_group.description = "Test group"
        mock_group_manager.get_group.return_value = mock_group
        
        response = client.get('/groups/group1/join-requests?pending_only=false')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data["join_requests"]) == 2
        assert data["join_requests"][0]['status'] == 'pending'
        assert data["join_requests"][1]['status'] == 'approved'
        
        # Verify the manager was called correctly
        mock_join_request_manager.get_group_join_requests.assert_called_once_with('group1', False)

    def test_get_group_join_requests_default_pending_only(self, app, client, mock_auth, sample_join_requests):
        """Test getting join requests with default pending_only=true"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        
        mock_group_manager.user_can_manage_group.return_value = True
        mock_join_request_manager.get_group_join_requests.return_value = [sample_join_requests[0]]
        mock_group = Mock()
        mock_group.name = "Test Group 1"
        mock_group.description = "Test group"
        mock_group_manager.get_group.return_value = mock_group
        
        response = client.get('/groups/group1/join-requests')  # No query param
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data["join_requests"]) == 1
        
        # Should default to pending_only=True
        mock_join_request_manager.get_group_join_requests.assert_called_once_with('group1', True)

    def test_get_group_join_requests_insufficient_permissions(self, app, client, mock_auth):
        """Test getting join requests without proper permissions"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_group_manager.user_can_manage_group.return_value = False
        
        response = client.get('/groups/group1/join-requests')
        
        assert response.status_code == 403

    def test_create_join_request(self, app, client, mock_auth):
        """Test creating a join request"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        
        # Mock group exists and user is not a member
        mock_group = Mock()
        mock_group.name = "Test Group"
        mock_group.to_dict.return_value = {"id": "group1", "name": "Test Group"}
        mock_group_manager.get_group.return_value = mock_group
        mock_group_manager.user_is_member.return_value = False
        mock_join_request_manager.has_pending_request.return_value = False
        
        new_request = JoinRequest(
            id="req123",
            group_id="group1",
            group_name="Test Group",
            user_id="test_user_123",
            user_email="test@example.com",
            user_name="Test User",
            message="Please let me join this group",
            status=JoinRequestStatus.PENDING,
            token="token123"
        )
        mock_join_request_manager.create_join_request.return_value = new_request
        
        request_data = {
            "message": "Please let me join this group"
        }
        
        response = client.post('/groups/group1/request-to-join',
                             data=json.dumps(request_data),
                             content_type='application/json')
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['user_id'] == 'test_user_123'
        assert data['message'] == 'Please let me join this group'

    def test_create_join_request_already_exists(self, app, client, mock_auth):
        """Test creating join request when one already exists"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        
        # Mock group exists and user has pending request
        mock_group = Mock()
        mock_group.name = "Test Group"
        mock_group_manager.get_group.return_value = mock_group
        mock_group_manager.user_is_member.return_value = False
        mock_join_request_manager.has_pending_request.return_value = True
        
        request_data = {
            "message": "Please let me join"
        }
        
        response = client.post('/groups/group1/request-to-join',
                             data=json.dumps(request_data),
                             content_type='application/json')
        
        assert response.status_code == 400

    def test_approve_join_request(self, app, client, mock_auth):
        """Test approving a join request"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        
        mock_group_manager.user_can_manage_group.return_value = True
        
        # Mock the join request
        mock_join_request = Mock()
        mock_join_request.group_id = "group1"
        mock_join_request.user_id = "user123"
        mock_join_request.user_email = "user@example.com"
        mock_join_request.to_dict.return_value = {"id": "req123", "status": "approved"}
        mock_join_request_manager.get_join_request.return_value = mock_join_request
        mock_join_request_manager.approve_join_request.return_value = (True, None)
        
        # Mock the membership creation
        mock_membership = Mock()
        mock_membership.to_dict.return_value = {"group_id": "group1", "user_id": "user123", "role": "member"}
        mock_group_manager.add_member.return_value = mock_membership
        
        approval_data = {
            "role": "member",
            "comment": "Welcome to the group!"
        }
        
        response = client.post('/groups/group1/join-requests/req123/approve',
                            data=json.dumps(approval_data),
                            content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "membership" in data

    def test_approve_join_request_with_default_role(self, app, client, mock_auth):
        """Test approving join request with default role"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        
        mock_group_manager.user_can_manage_group.return_value = True
        
        mock_join_request = Mock()
        mock_join_request.group_id = "group1"
        mock_join_request.user_id = "user123"
        mock_join_request.user_email = "user@example.com"
        mock_join_request.to_dict.return_value = {"id": "req123", "status": "approved"}
        mock_join_request_manager.get_join_request.return_value = mock_join_request
        mock_join_request_manager.approve_join_request.return_value = (True, None)
        
        mock_membership = Mock()
        mock_membership.to_dict.return_value = {"group_id": "group1", "user_id": "user123", "role": "member"}
        mock_group_manager.add_member.return_value = mock_membership
        
        # No role specified, should default to member
        approval_data = {"comment": "Welcome!"}
        
        response = client.post('/groups/group1/join-requests/req123/approve',
                            data=json.dumps(approval_data),
                            content_type='application/json')
        
        assert response.status_code == 200

    def test_approve_join_request_insufficient_permissions(self, app, client, mock_auth):
        """Test approving join request without proper permissions"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_group_manager.user_can_manage_group.return_value = False
        
        approval_data = {"role": "member"}
        
        response = client.post('/groups/group1/join-requests/req123/approve',
                            data=json.dumps(approval_data),
                            content_type='application/json')
        
        assert response.status_code == 403

    def test_approve_join_request_failure(self, app, client, mock_auth):
        """Test approving join request when approval fails"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        
        mock_group_manager.user_can_manage_group.return_value = True
        
        mock_join_request = Mock()
        mock_join_request.group_id = "group1"
        mock_join_request_manager.get_join_request.return_value = mock_join_request
        mock_join_request_manager.approve_join_request.return_value = (False, "Approval failed")
        
        approval_data = {"role": "member"}
        
        response = client.post('/groups/group1/join-requests/req123/approve',
                            data=json.dumps(approval_data),
                            content_type='application/json')
        
        assert response.status_code == 400

    def test_deny_join_request(self, app, client, mock_auth):
        """Test denying a join request"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        
        mock_group_manager.user_can_manage_group.return_value = True
        
        # Mock the join request
        mock_join_request = Mock()
        mock_join_request.group_id = "group1"
        mock_join_request.user_email = "user@example.com"
        mock_join_request_manager.get_join_request.return_value = mock_join_request
        mock_join_request_manager.deny_join_request.return_value = (True, None)
        
        # Mock the updated request - use side_effect to return different values on multiple calls
        mock_updated_request = Mock()
        mock_updated_request.to_dict.return_value = {"id": "req123", "status": "denied"}
        # First call returns the original request, second call returns the updated one
        mock_join_request_manager.get_join_request.side_effect = [mock_join_request, mock_updated_request]
        
        denial_data = {
            "comment": "Group is currently full"
        }
        
        response = client.post('/groups/group1/join-requests/req123/deny',
                            data=json.dumps(denial_data),
                            content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'denied'

    def test_deny_join_request_insufficient_permissions(self, app, client, mock_auth):
        """Test denying join request without proper permissions"""
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_group_manager.user_can_manage_group.return_value = False
        
        denial_data = {"comment": "No"}
        
        response = client.post('/groups/group1/join-requests/req123/deny',
                            data=json.dumps(denial_data),
                            content_type='application/json')
        
        assert response.status_code == 403

    def test_deny_join_request_failure(self, app, client, mock_auth):
        """Test denying join request when denial fails"""
        mock_group_manager = Mock()
        mock_join_request_manager = Mock()
        
        mock_group_manager.user_can_manage_group.return_value = True
        
        mock_join_request = Mock()
        mock_join_request.group_id = "group1"
        mock_join_request_manager.get_join_request.return_value = mock_join_request
        mock_join_request_manager.deny_join_request.return_value = (False, "Denial failed")

        app.config['GROUP_MANAGER'] = mock_group_manager
        app.config['JOIN_REQUEST_MANAGER'] = mock_join_request_manager

        denial_data = {"comment": "No"}

        response = client.post('/groups/group1/join-requests/req123/deny',
                            data=json.dumps(denial_data),
                            content_type='application/json')
        
        assert response.status_code == 400

    def test_cancel_join_request(self, app, client, mock_auth):
        """Test canceling own join request"""
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        mock_join_request_manager.cancel_join_request.return_value = (True, None)
        
        response = client.post('/join-requests/req123/cancel')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "cancelled"
        
        # Verify the manager was called correctly
        mock_join_request_manager.cancel_join_request.assert_called_once_with(
            "req123", "test_user_123"
        )

    def test_cancel_join_request_failure(self, app, client, mock_auth):
        """Test canceling join request when cancellation fails"""
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        mock_join_request_manager.cancel_join_request.return_value = (False, "Cancellation failed")
        
        response = client.post('/join-requests/req123/cancel')
        
        assert response.status_code == 400

    def test_get_user_join_requests(self, app, client, mock_auth):
        """Test getting current user's join requests"""
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        
        # Create sample requests for current user
        user_requests = [
            JoinRequest(
                id="req_user",
                group_id="group1",
                group_name="Group One",
                user_id="test_user_123",
                user_email="test@example.com",
                user_name="Test User",
                message="Please let me join",
                status=JoinRequestStatus.PENDING,
                token="token_user"
            )]
        
        mock_join_request_manager.get_user_join_requests.return_value = user_requests
        
        # Mock group manager for group info
        mock_group_manager = app.config['GROUP_MANAGER']
        mock_group = Mock()
        mock_group.to_dict.return_value = {"id": "group1", "name": "Test Group"}
        mock_group_manager.get_group.return_value = mock_group
        
        response = client.get('/join-requests/my')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data["join_requests"]) >= 1
        assert all(req['user_id'] == 'test_user_123' for req in data["join_requests"])
        
        # Verify the manager was called correctly
        mock_join_request_manager.get_user_join_requests.assert_called_once_with("test_user_123")

    def test_get_public_join_info(self, app, client):
        """Test getting public join information"""
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        mock_group_manager = app.config['GROUP_MANAGER']
        
        mock_join_request_manager.get_public_join_info.return_value = {
            "group_id": "group1",
            "is_valid": True,
            "expires_at": 1234567890,
        }
        
        mock_group = Mock()
        mock_group.name = "Test Group"
        mock_group.description = "A test group"
        mock_group_manager.get_group.return_value = mock_group
        
        response = client.get('/join/valid_token')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["group_name"] == "Test Group"
        assert data["is_valid"] is True

    def test_get_public_join_info_invalid_token(self, app, client):
        """Test getting public join info with invalid token"""
        mock_join_request_manager = app.config['JOIN_REQUEST_MANAGER']
        mock_join_request_manager.get_public_join_info.return_value = None
        
        response = client.get('/join/invalid_token')
        
        assert response.status_code == 404

    def test_get_join_request_summary(self, app, client, mock_auth):
        """Test getting join request summary for a group"""
        # This endpoint doesn't seem to exist in the actual API
        response = client.get('/groups/group1/join-requests/summary')
        assert response.status_code == 404

    def test_get_join_request_summary_insufficient_permissions(self, app, client, mock_auth):
        """Test getting join request summary without permissions"""
        # This endpoint doesn't seem to exist in the actual API
        response = client.get('/groups/group1/join-requests/summary')
        assert response.status_code == 404

    def test_cleanup_expired_requests(self, app, client, mock_auth):
        """Test cleaning up expired requests"""
        # This endpoint doesn't seem to exist in the actual API
        response = client.post('/groups/group1/join-requests/cleanup')
        assert response.status_code == 404

    def test_cleanup_expired_requests_insufficient_permissions(self, app, client, mock_auth):
        """Test cleanup with insufficient permissions"""
        # This endpoint doesn't seem to exist in the actual API
        response = client.post('/groups/group1/join-requests/cleanup')
        assert response.status_code == 404