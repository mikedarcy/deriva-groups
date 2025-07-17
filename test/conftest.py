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
import sys
import pathlib
import pytest
import time
import uuid
from unittest.mock import Mock, patch, MagicMock
from flask import Flask

# Insert the project root (one level up from tests/) onto sys.path
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from deriva.web.groups.api.storage.core import Storage
from deriva.web.groups.api.storage.backends.memory import MemoryBackend
from deriva.web.groups.api.groups.models import Group, GroupMembership, GroupInvitation, JoinRequest, GroupRole, InvitationStatus, JoinRequestStatus
from deriva.web.groups.api.groups.group_manager import GroupManager
from deriva.web.groups.api.groups.join_request_manager import JoinRequestManager
from deriva.web.groups.api.groups.email_service import EmailService
from deriva.web.groups.api.util import SessionManager


@pytest.fixture
def memory_storage():
    """Memory storage backend for testing"""
    backend = MemoryBackend()
    return Storage(backend)


@pytest.fixture
def group_manager(memory_storage):
    """Group manager with memory storage"""
    return GroupManager(memory_storage)


@pytest.fixture
def join_request_manager(memory_storage):
    """Join request manager with memory storage"""
    return JoinRequestManager(memory_storage)


@pytest.fixture
def mock_email_service():
    """Mock email service"""
    email_service = Mock(spec=EmailService)
    email_service.send_invitation_email.return_value = True
    email_service.send_join_request_notification.return_value = True
    email_service.send_join_request_decision_email.return_value = True
    email_service.test_connection.return_value = True
    return email_service


@pytest.fixture
def group_manager_with_email(memory_storage, mock_email_service):
    """Group manager with mocked email service"""
    return GroupManager(memory_storage, mock_email_service)


@pytest.fixture
def sample_group(mock_time):
    """Sample group for testing"""
    return Group(
        id=str(uuid.uuid4()),
        name="Test Group",
        description="A test group",
        visibility="private",
        created_by="user123",
        metadata={"department": "IT"}
    )


@pytest.fixture
def sample_user():
    """Sample user data for testing"""
    return {
        "id": "user123",
        "email": "user@example.com",
        "name": "Test User"
    }


@pytest.fixture
def sample_membership(sample_group, sample_user, mock_time):
    """Sample membership for testing"""
    return GroupMembership(
        group_id=sample_group.id,
        user_id=sample_user["id"],
        user_email=sample_user["email"],
        role=GroupRole.MEMBER,
        added_by="admin123"
    )


@pytest.fixture
def sample_invitation(sample_group, mock_time):
    """Sample invitation for testing"""
    return GroupInvitation(
        id=str(uuid.uuid4()),
        group_id=sample_group.id,
        group_name=sample_group.name,
        email="invitee@example.com",
        role=GroupRole.MEMBER,
        token=str(uuid.uuid4().hex),
        invited_by="admin123"
    )


@pytest.fixture
def sample_join_request(sample_group, mock_time):
    """Sample join request for testing"""
    return JoinRequest(
        id=str(uuid.uuid4()),
        group_id=sample_group.id,
        group_name=sample_group.name,
        user_id="requester123",
        user_email="requester@example.com",
        user_name="Requester User",
        message="Please let me join this group",
        token=str(uuid.uuid4().hex)
    )


@pytest.fixture
def flask_app():
    """Basic Flask app for testing"""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['COOKIE_NAME'] = 'test_cookie'
    app.config['SESSION_MANAGER'] = Mock()
    return app


@pytest.fixture
def app_context(flask_app):
    """Flask app context for testing"""
    with flask_app.app_context():
        yield flask_app


@pytest.fixture
def mock_session_manager():
    """Mock session manager"""
    session_manager = Mock(spec=SessionManager)
    session_manager.get_user_session.return_value = {
        'sub': 'user123',
        'email': 'user@example.com',
        'name': 'Test User'
    }
    return session_manager


@pytest.fixture
def mock_requests():
    """Mock requests for external HTTP calls"""
    with patch('requests.get') as mock_get, \
         patch('requests.put') as mock_put, \
         patch('requests.post') as mock_post, \
         patch('requests.head') as mock_head:
        
        # Mock successful auth responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'sub': 'user123',
            'email': 'user@example.com',
            'name': 'Test User'
        }
        
        mock_get.return_value = mock_response
        mock_put.return_value = mock_response
        mock_post.return_value = mock_response
        mock_head.return_value = mock_response
        
        yield {
            'get': mock_get,
            'put': mock_put,
            'post': mock_post,
            'head': mock_head
        }


@pytest.fixture
def mock_smtp():
    """Mock SMTP for email testing"""
    with patch('smtplib.SMTP') as mock_smtp_class, \
         patch('smtplib.SMTP_SSL') as mock_smtp_ssl_class:
        
        mock_server = Mock()
        mock_server.login.return_value = None
        mock_server.send_message.return_value = None
        mock_server.quit.return_value = None
        mock_server.starttls.return_value = None
        
        mock_smtp_class.return_value = mock_server
        mock_smtp_ssl_class.return_value = mock_server
        
        yield mock_server


@pytest.fixture
def mock_time():
    """Mock time.time() to control timestamps for testing"""
    import time
    from unittest.mock import patch
    
    start_time = 1000000000.0
    time_counter = [start_time]
    
    def mock_time_func():
        time_counter[0] += 1.0  # Each call adds 1 second
        return time_counter[0]
    
    # Patch time.time in all the modules that use it
    patches = [
        patch('time.time', side_effect=mock_time_func),
        patch('deriva.web.groups.api.groups.models.time.time', side_effect=mock_time_func),
        patch('deriva.web.groups.api.groups.group_manager.time.time', side_effect=mock_time_func),
        patch('deriva.web.groups.api.groups.join_request_manager.time.time', side_effect=mock_time_func),
        patch('deriva.web.groups.api.storage.core.time.time', side_effect=mock_time_func),
        patch('deriva.web.groups.api.storage.backends.memory.time.time', side_effect=mock_time_func),
    ]
    
    # Start all patches
    for p in patches:
        p.start()
    
    try:
        yield mock_time_func
    finally:
        # Stop all patches
        for p in patches:
            p.stop()


@pytest.fixture
def time_freeze():
    """Freeze time for testing"""
    frozen_time = time.time()
    with patch('time.time', return_value=frozen_time):
        yield frozen_time


@pytest.fixture
def admin_user():
    """Admin user for testing"""
    return {
        "id": "admin123",
        "email": "admin@example.com",
        "name": "Admin User"
    }


@pytest.fixture
def manager_user():
    """Manager user for testing"""
    return {
        "id": "manager123", 
        "email": "manager@example.com",
        "name": "Manager User"
    }


@pytest.fixture
def member_user():
    """Member user for testing"""
    return {
        "id": "member123",
        "email": "member@example.com", 
        "name": "Member User"
    }


@pytest.fixture
def populated_group(memory_storage, sample_group, admin_user, manager_user, member_user, mock_time):
    """Group with multiple members for testing"""
    storage = memory_storage
    
    # Create the group
    storage.create_group(sample_group)
    
    # Add admin
    admin_membership = GroupMembership(
        group_id=sample_group.id,
        user_id=admin_user["id"],
        user_email=admin_user["email"],
        role=GroupRole.ADMINISTRATOR,
        added_by="system"
    )
    storage.add_membership(admin_membership)
    
    # Add manager
    manager_membership = GroupMembership(
        group_id=sample_group.id,
        user_id=manager_user["id"],
        user_email=manager_user["email"],
        role=GroupRole.MANAGER,
        added_by=admin_user["id"]
    )
    storage.add_membership(manager_membership)
    
    # Add member
    member_membership = GroupMembership(
        group_id=sample_group.id,
        user_id=member_user["id"],
        user_email=member_user["email"],
        role=GroupRole.MEMBER,
        added_by=admin_user["id"]
    )
    storage.add_membership(member_membership)
    
    return sample_group


# Test utilities
def create_test_group(name="Test Group", description="A test group", visibility="private"):
    """Helper to create a test group"""
    return Group(
        id=str(uuid.uuid4()),
        name=name,
        description=description,
        visibility=visibility,
        created_by="test_user",
        metadata={}
    )


def create_test_membership(group_id, user_id, user_email, role=GroupRole.MEMBER):
    """Helper to create a test membership"""
    return GroupMembership(
        group_id=group_id,
        user_id=user_id,
        user_email=user_email,
        role=role,
        added_by="test_admin"
    )


def create_test_invitation(group_id, group_name, email, role=GroupRole.MEMBER):
    """Helper to create a test invitation"""
    return GroupInvitation(
        id=str(uuid.uuid4()),
        group_id=group_id,
        group_name=group_name,
        email=email,
        role=role,
        token=str(uuid.uuid4().hex),
        invited_by="test_admin"
    )


def create_test_join_request(group_id, group_name, user_id, user_email, user_name):
    """Helper to create a test join request"""
    return JoinRequest(
        id=str(uuid.uuid4()),
        group_id=group_id,
        group_name=group_name,
        user_id=user_id,
        user_email=user_email,
        user_name=user_name,
        message="Test join request",
        token=str(uuid.uuid4().hex)
    )