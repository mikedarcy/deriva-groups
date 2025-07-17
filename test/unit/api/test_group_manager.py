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

import pytest
import time
import uuid
from unittest.mock import Mock, patch
from deriva.web.groups.api.groups.group_manager import GroupManager
from deriva.web.groups.api.groups.models import Group, GroupMembership, GroupInvitation, GroupRole, InvitationStatus


class TestGroupManagerGroupOperations:
    """Test GroupManager group operations"""
    
    def test_create_group(self, group_manager):
        """Test creating a group"""
        group = group_manager.create_group(
            name="Test Group",
            description="A test group",
            visibility="public",
            created_by="user123",
            metadata={"department": "IT"}
        )
        
        assert group is not None
        assert group.name == "Test Group"
        assert group.description == "A test group"
        assert group.visibility == "public"
        assert group.created_by == "user123"
        assert group.metadata == {"department": "IT"}
        assert isinstance(group.id, str)
        assert len(group.id) == 36  # UUID length
        
        # Verify group was stored
        retrieved_group = group_manager.get_group(group.id)
        assert retrieved_group is not None
        assert retrieved_group.name == "Test Group"
    
    def test_create_group_with_defaults(self, group_manager):
        """Test creating a group with default values"""
        group = group_manager.create_group(name="Minimal Group")
        
        assert group.name == "Minimal Group"
        assert group.description == ""
        assert group.visibility == "private"
        assert group.created_by == ""
        assert group.metadata == {}
    
    def test_get_group_success(self, group_manager, sample_group):
        """Test getting an existing group"""
        # Create group first
        group_manager.store.create_group(sample_group)
        
        # Get group
        retrieved_group = group_manager.get_group(sample_group.id)
        
        assert retrieved_group is not None
        assert retrieved_group.id == sample_group.id
        assert retrieved_group.name == sample_group.name
    
    def test_get_group_not_found(self, group_manager):
        """Test getting non-existent group"""
        result = group_manager.get_group("nonexistent_id")
        assert result is None
    
    def test_update_group_success(self, group_manager, sample_group, mock_time):
        """Test updating a group"""
        # Create group first
        group_manager.store.create_group(sample_group)
        original_updated_at = sample_group.updated_at
        
        # Update group (mock_time ensures different timestamp)
        updated_group = group_manager.update_group(
            sample_group.id,
            name="Updated Group",
            description="Updated description",
            visibility="public",
            metadata={"new": "metadata"}
        )
        
        assert updated_group is not None
        assert updated_group.name == "Updated Group"
        assert updated_group.description == "Updated description"
        assert updated_group.visibility == "public"
        assert updated_group.metadata == {"new": "metadata"}
        # Check that updated_at was changed from the original
        assert updated_group.updated_at != original_updated_at
    
    def test_update_group_partial(self, group_manager, sample_group):
        """Test partially updating a group"""
        # Create group first
        group_manager.store.create_group(sample_group)
        original_description = sample_group.description
        
        # Update only name
        updated_group = group_manager.update_group(
            sample_group.id,
            name="New Name Only"
        )
        
        assert updated_group is not None
        assert updated_group.name == "New Name Only"
        assert updated_group.description == original_description  # Unchanged
    
    def test_update_group_not_found(self, group_manager):
        """Test updating non-existent group"""
        result = group_manager.update_group("nonexistent_id", name="New Name")
        assert result is None
    
    def test_delete_group_success(self, group_manager, sample_group):
        """Test deleting a group"""
        # Create group first
        group_manager.store.create_group(sample_group)
        
        # Delete group
        result = group_manager.delete_group(sample_group.id)
        
        assert result is True
        assert group_manager.get_group(sample_group.id) is None
    
    def test_delete_group_not_found(self, group_manager):
        """Test deleting non-existent group"""
        result = group_manager.delete_group("nonexistent_id")
        assert result is False
    
    def test_list_groups(self, group_manager):
        """Test listing groups"""
        # Create multiple groups
        group1 = group_manager.create_group(name="Group 1")
        group2 = group_manager.create_group(name="Group 2")
        group3 = group_manager.create_group(name="Group 3")
        
        # List groups
        groups = group_manager.list_groups()
        
        assert len(groups) == 3
        group_names = [g.name for g in groups]
        assert "Group 1" in group_names
        assert "Group 2" in group_names
        assert "Group 3" in group_names
    
    def test_list_groups_empty(self, group_manager):
        """Test listing when no groups exist"""
        groups = group_manager.list_groups()
        assert groups == []
    
    def test_get_user_groups(self, group_manager, sample_user):
        """Test getting user groups"""
        # Create groups
        group1 = group_manager.create_group(name="Group 1")
        group2 = group_manager.create_group(name="Group 2")
        
        # Add user to groups
        group_manager.add_member(group1.id, sample_user["id"], sample_user["email"], GroupRole.MEMBER)
        group_manager.add_member(group2.id, sample_user["id"], sample_user["email"], GroupRole.ADMINISTRATOR)
        
        # Get user groups
        user_groups = group_manager.get_user_groups(sample_user["id"])
        
        assert len(user_groups) == 2
        
        # Verify structure (list of tuples)
        for group, membership in user_groups:
            assert isinstance(group, Group)
            assert isinstance(membership, GroupMembership)
            assert membership.user_id == sample_user["id"]
            assert group.id == membership.group_id


class TestGroupManagerMembershipOperations:
    """Test GroupManager membership operations"""
    
    def test_add_member_success(self, group_manager, sample_group, sample_user):
        """Test adding a member to a group"""
        # Create group first
        group_manager.store.create_group(sample_group)
        
        # Add member
        membership = group_manager.add_member(
            sample_group.id,
            sample_user["id"],
            sample_user["email"],
            GroupRole.MEMBER,
            added_by="admin123",
            metadata={"source": "invitation"}
        )
        
        assert membership is not None
        assert membership.group_id == sample_group.id
        assert membership.user_id == sample_user["id"]
        assert membership.user_email == sample_user["email"]
        assert membership.role == GroupRole.MEMBER
        assert membership.added_by == "admin123"
        assert membership.metadata == {"source": "invitation"}
    
    def test_add_member_to_nonexistent_group(self, group_manager, sample_user):
        """Test adding member to non-existent group"""
        membership = group_manager.add_member(
            "nonexistent_group",
            sample_user["id"],
            sample_user["email"],
            GroupRole.MEMBER
        )
        assert membership is None
    
    def test_add_member_already_exists(self, group_manager, sample_group, sample_user):
        """Test adding member who is already a member"""
        # Create group and add member
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.MEMBER)
        
        # Try to add same member again
        membership = group_manager.add_member(
            sample_group.id,
            sample_user["id"],
            sample_user["email"],
            GroupRole.ADMINISTRATOR
        )
        assert membership is None
    
    def test_update_member_role_success(self, group_manager, sample_group, sample_user):
        """Test updating member role"""
        # Create group and add member
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.MEMBER)
        
        # Update role
        updated_membership = group_manager.update_member_role(
            sample_group.id,
            sample_user["id"],
            GroupRole.ADMINISTRATOR
        )
        
        assert updated_membership is not None
        assert updated_membership.role == GroupRole.ADMINISTRATOR
        assert updated_membership.user_id == sample_user["id"]
    
    def test_update_member_role_not_found(self, group_manager, sample_group):
        """Test updating role for non-existent member"""
        group_manager.store.create_group(sample_group)
        
        result = group_manager.update_member_role(
            sample_group.id,
            "nonexistent_user",
            GroupRole.ADMINISTRATOR
        )
        assert result is None
    
    def test_remove_member_success(self, group_manager, sample_group, sample_user):
        """Test removing a member"""
        # Create group and add member
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.MEMBER)
        
        # Remove member
        result = group_manager.remove_member(sample_group.id, sample_user["id"])
        
        assert result is True
        assert group_manager.get_membership(sample_group.id, sample_user["id"]) is None
    
    def test_remove_member_not_found(self, group_manager, sample_group):
        """Test removing non-existent member"""
        group_manager.store.create_group(sample_group)
        
        result = group_manager.remove_member(sample_group.id, "nonexistent_user")
        assert result is False
    
    def test_get_group_members(self, group_manager, sample_group):
        """Test getting group members"""
        # Create group
        group_manager.store.create_group(sample_group)
        
        # Add members
        user1 = {"id": "user1", "email": "user1@example.com"}
        user2 = {"id": "user2", "email": "user2@example.com"}
        
        group_manager.add_member(sample_group.id, user1["id"], user1["email"], GroupRole.ADMINISTRATOR)
        group_manager.add_member(sample_group.id, user2["id"], user2["email"], GroupRole.MEMBER)
        
        # Get members
        members = group_manager.get_group_members(sample_group.id)
        
        assert len(members) == 2
        user_ids = [m.user_id for m in members]
        assert user1["id"] in user_ids
        assert user2["id"] in user_ids
    
    def test_get_membership_success(self, group_manager, sample_group, sample_user):
        """Test getting specific membership"""
        # Create group and add member
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.MEMBER)
        
        # Get membership
        membership = group_manager.get_membership(sample_group.id, sample_user["id"])
        
        assert membership is not None
        assert membership.group_id == sample_group.id
        assert membership.user_id == sample_user["id"]
        assert membership.role == GroupRole.MEMBER
    
    def test_get_membership_not_found(self, group_manager, sample_group):
        """Test getting non-existent membership"""
        group_manager.store.create_group(sample_group)
        
        membership = group_manager.get_membership(sample_group.id, "nonexistent_user")
        assert membership is None


class TestGroupManagerRoleChecking:
    """Test GroupManager role checking methods"""
    
    def test_check_user_role_success(self, group_manager, sample_group, sample_user):
        """Test checking user role"""
        # Create group and add member
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.ADMINISTRATOR)
        
        # Check role
        role = group_manager.check_user_role(sample_group.id, sample_user["id"])
        assert role == GroupRole.ADMINISTRATOR
    
    def test_check_user_role_with_required_role(self, group_manager, sample_group, sample_user):
        """Test checking user role with required role"""
        # Create group and add member
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.ADMINISTRATOR)
        
        # Check with required role - should pass
        role = group_manager.check_user_role(sample_group.id, sample_user["id"], GroupRole.MANAGER)
        assert role == GroupRole.ADMINISTRATOR
        
        # Check with higher required role - should fail
        role = group_manager.check_user_role(sample_group.id, sample_user["id"], GroupRole.ADMINISTRATOR)
        assert role == GroupRole.ADMINISTRATOR
    
    def test_check_user_role_insufficient_permissions(self, group_manager, sample_group, sample_user):
        """Test checking user role with insufficient permissions"""
        # Create group and add member with lower role
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.MEMBER)
        
        # Check with higher required role - should fail
        role = group_manager.check_user_role(sample_group.id, sample_user["id"], GroupRole.ADMINISTRATOR)
        assert role is None
    
    def test_check_user_role_not_member(self, group_manager, sample_group):
        """Test checking role for non-member"""
        group_manager.store.create_group(sample_group)
        
        role = group_manager.check_user_role(sample_group.id, "nonexistent_user")
        assert role is None
    
    def test_user_can_manage_group(self, group_manager, sample_group, sample_user):
        """Test user can manage group"""
        # Create group and add manager
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.MANAGER)
        
        # Manager should be able to manage
        assert group_manager.user_can_manage_group(sample_group.id, sample_user["id"]) is True
    
    def test_user_can_manage_group_admin(self, group_manager, sample_group, sample_user):
        """Test admin can manage group"""
        # Create group and add admin
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.ADMINISTRATOR)
        
        # Admin should be able to manage
        assert group_manager.user_can_manage_group(sample_group.id, sample_user["id"]) is True
    
    def test_user_can_manage_group_member_cannot(self, group_manager, sample_group, sample_user):
        """Test member cannot manage group"""
        # Create group and add member
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.MEMBER)
        
        # Member should not be able to manage
        assert group_manager.user_can_manage_group(sample_group.id, sample_user["id"]) is False
    
    def test_user_can_admin_group(self, group_manager, sample_group, sample_user):
        """Test user can admin group"""
        # Create group and add admin
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.ADMINISTRATOR)
        
        # Admin should be able to admin
        assert group_manager.user_can_admin_group(sample_group.id, sample_user["id"]) is True
    
    def test_user_can_admin_group_manager_cannot(self, group_manager, sample_group, sample_user):
        """Test manager cannot admin group"""
        # Create group and add manager
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.MANAGER)
        
        # Manager should not be able to admin
        assert group_manager.user_can_admin_group(sample_group.id, sample_user["id"]) is False
    
    def test_user_is_member(self, group_manager, sample_group, sample_user):
        """Test user is member check"""
        # Create group and add member
        group_manager.store.create_group(sample_group)
        group_manager.add_member(sample_group.id, sample_user["id"], sample_user["email"], GroupRole.MEMBER)
        
        # User should be member
        assert group_manager.user_is_member(sample_group.id, sample_user["id"]) is True
    
    def test_user_is_member_false(self, group_manager, sample_group):
        """Test user is not member"""
        group_manager.store.create_group(sample_group)
        
        # User should not be member
        assert group_manager.user_is_member(sample_group.id, "nonexistent_user") is False


class TestGroupManagerInvitations:
    """Test GroupManager invitation operations"""
    
    def test_create_invitation_success(self, group_manager_with_email, sample_group):
        """Test creating invitation with email service"""
        # Create group
        group_manager_with_email.store.create_group(sample_group)
        
        # Create invitation
        invitation = group_manager_with_email.create_invitation(
            sample_group.id,
            "invitee@example.com",
            GroupRole.MEMBER,
            invited_by="admin123",
            base_url="https://example.com",
            invited_by_name="Admin User"
        )
        
        assert invitation is not None
        assert invitation.group_id == sample_group.id
        assert invitation.email == "invitee@example.com"
        assert invitation.role == GroupRole.MEMBER
        assert invitation.invited_by == "admin123"
        assert invitation.status == InvitationStatus.PENDING
        assert len(invitation.token) == 32  # UUID hex length
        
        # Verify email service was called
        group_manager_with_email.email_service.send_invitation_email.assert_called_once()
    
    def test_create_invitation_nonexistent_group(self, group_manager_with_email):
        """Test creating invitation for non-existent group"""
        invitation = group_manager_with_email.create_invitation(
            "nonexistent_group",
            "invitee@example.com",
            GroupRole.MEMBER
        )
        assert invitation is None
    
    def test_create_invitation_existing_member(self, group_manager_with_email, sample_group):
        """Test creating invitation for existing member"""
        # Create group and add member
        group_manager_with_email.store.create_group(sample_group)
        group_manager_with_email.add_member(
            sample_group.id,
            "user123",
            "invitee@example.com",
            GroupRole.MEMBER
        )
        
        # Try to invite existing member
        invitation = group_manager_with_email.create_invitation(
            sample_group.id,
            "invitee@example.com",
            GroupRole.MEMBER
        )
        assert invitation is None
    
    def test_create_invitation_existing_pending_invitation(self, group_manager_with_email, sample_group):
        """Test creating invitation when pending invitation exists"""
        # Create group
        group_manager_with_email.store.create_group(sample_group)
        
        # Create first invitation
        invitation1 = group_manager_with_email.create_invitation(
            sample_group.id,
            "invitee@example.com",
            GroupRole.MEMBER
        )
        assert invitation1 is not None
        
        # Try to create second invitation for same email
        invitation2 = group_manager_with_email.create_invitation(
            sample_group.id,
            "invitee@example.com",
            GroupRole.ADMINISTRATOR
        )
        assert invitation2 is None
    
    @patch('deriva.web.groups.api.groups.group_manager.logger')
    def test_send_invitation_no_email_service(self, mock_logger, group_manager, sample_group):
        """Test sending invitation without email service"""
        # Create group
        group_manager.store.create_group(sample_group)
        
        # Create invitation (should succeed even without email service)
        invitation = group_manager.create_invitation(
            sample_group.id,
            "invitee@example.com",
            GroupRole.MEMBER,
            base_url="https://example.com"
        )
        
        assert invitation is not None
        # The method should log that email service is not configured
        mock_logger.debug.assert_called_with("Email service not configured or unavailable")
    
    def test_accept_invitation_success(self, group_manager, sample_group, sample_invitation):
        """Test accepting invitation"""
        # Create group and invitation
        group_manager.store.create_group(sample_group)
        group_manager.store.create_invitation(sample_invitation)
        
        # Accept invitation
        membership = group_manager.accept_invitation(
            sample_invitation.token,
            "user123",
            sample_invitation.email
        )
        
        assert membership is not None
        assert membership.group_id == sample_group.id
        assert membership.user_id == "user123"
        assert membership.user_email == sample_invitation.email
        assert membership.role == sample_invitation.role
        assert membership.added_by == sample_invitation.invited_by
        assert membership.metadata["invitation_id"] == sample_invitation.id
        
        # Verify invitation status updated
        updated_invitation = group_manager.store.get_invitation(sample_invitation.id)
        assert updated_invitation.status == InvitationStatus.ACCEPTED
        assert updated_invitation.accepted_by == "user123"
    
    def test_accept_invitation_invalid_token(self, group_manager):
        """Test accepting invitation with invalid token"""
        membership = group_manager.accept_invitation(
            "invalid_token",
            "user123",
            "user@example.com"
        )
        assert membership is None
    
    def test_accept_invitation_email_mismatch(self, group_manager, sample_group, sample_invitation):
        """Test accepting invitation with mismatched email"""
        # Create group and invitation
        group_manager.store.create_group(sample_group)
        group_manager.store.create_invitation(sample_invitation)
        
        # Try to accept with different email
        membership = group_manager.accept_invitation(
            sample_invitation.token,
            "user123",
            "different@example.com"
        )
        assert membership is None
    
    def test_accept_invitation_expired(self, group_manager, sample_group):
        """Test accepting expired invitation"""
        # Create expired invitation
        expired_invitation = GroupInvitation(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            email="invitee@example.com",
            role=GroupRole.MEMBER,
            token=str(uuid.uuid4().hex),
            expires_at=time.time() - 3600,  # 1 hour ago
            status=InvitationStatus.PENDING
        )
        
        group_manager.store.create_group(sample_group)
        group_manager.store.create_invitation(expired_invitation)
        
        # Try to accept expired invitation
        membership = group_manager.accept_invitation(
            expired_invitation.token,
            "user123",
            expired_invitation.email
        )
        assert membership is None
    
    def test_revoke_invitation_success(self, group_manager, sample_group, sample_invitation):
        """Test revoking invitation"""
        # Create group and invitation
        group_manager.store.create_group(sample_group)
        group_manager.store.create_invitation(sample_invitation)
        
        # Revoke invitation
        result = group_manager.revoke_invitation(sample_invitation.id)
        
        assert result is True
        
        # Verify invitation status updated
        updated_invitation = group_manager.store.get_invitation(sample_invitation.id)
        assert updated_invitation.status == InvitationStatus.REVOKED
    
    def test_revoke_invitation_not_found(self, group_manager):
        """Test revoking non-existent invitation"""
        result = group_manager.revoke_invitation("nonexistent_id")
        assert result is False
    
    def test_get_group_invitations(self, group_manager, sample_group):
        """Test getting group invitations"""
        # Create group
        group_manager.store.create_group(sample_group)
        
        # Create invitations
        invitation1 = GroupInvitation(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            email="user1@example.com",
            role=GroupRole.MEMBER,
            token=str(uuid.uuid4().hex)
        )
        invitation2 = GroupInvitation(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            email="user2@example.com",
            role=GroupRole.ADMINISTRATOR,
            token=str(uuid.uuid4().hex)
        )
        
        group_manager.store.create_invitation(invitation1)
        group_manager.store.create_invitation(invitation2)
        
        # Get invitations
        invitations = group_manager.get_group_invitations(sample_group.id)
        
        assert len(invitations) == 2
        emails = [inv.email for inv in invitations]
        assert "user1@example.com" in emails
        assert "user2@example.com" in emails
    
    def test_get_user_invitations(self, group_manager):
        """Test getting user invitations"""
        # Create groups
        group1 = Group(id=str(uuid.uuid4()), name="Group 1")
        group2 = Group(id=str(uuid.uuid4()), name="Group 2")
        
        group_manager.store.create_group(group1)
        group_manager.store.create_group(group2)
        
        # Create invitations
        invitation1 = GroupInvitation(
            id=str(uuid.uuid4()),
            group_id=group1.id,
            group_name=group1.name,
            email="user@example.com",
            role=GroupRole.MEMBER,
            token=str(uuid.uuid4().hex),
            status=InvitationStatus.PENDING
        )
        invitation2 = GroupInvitation(
            id=str(uuid.uuid4()),
            group_id=group2.id,
            group_name=group2.name,
            email="user@example.com",
            role=GroupRole.ADMINISTRATOR,
            token=str(uuid.uuid4().hex),
            status=InvitationStatus.PENDING
        )
        
        group_manager.store.create_invitation(invitation1)
        group_manager.store.create_invitation(invitation2)
        
        # Get user invitations
        invitations = group_manager.get_user_invitations("user@example.com")
        
        assert len(invitations) == 2
        group_ids = [inv.group_id for inv in invitations]
        assert group1.id in group_ids
        assert group2.id in group_ids
    
    def test_get_invitation_by_token(self, group_manager, sample_group, sample_invitation):
        """Test getting invitation by token"""
        # Create group and invitation
        group_manager.store.create_group(sample_group)
        group_manager.store.create_invitation(sample_invitation)
        
        # Get invitation by token
        retrieved_invitation = group_manager.get_invitation_by_token(sample_invitation.token)
        
        assert retrieved_invitation is not None
        assert retrieved_invitation.id == sample_invitation.id
        assert retrieved_invitation.token == sample_invitation.token


class TestGroupManagerSummary:
    """Test GroupManager summary operations"""
    
    def test_get_group_summary(self, group_manager, sample_group):
        """Test getting group summary"""
        # Create group
        group_manager.store.create_group(sample_group)
        
        # Add members
        group_manager.add_member(sample_group.id, "user1", "user1@example.com", GroupRole.ADMINISTRATOR)
        group_manager.add_member(sample_group.id, "user2", "user2@example.com", GroupRole.MANAGER)
        group_manager.add_member(sample_group.id, "user3", "user3@example.com", GroupRole.MEMBER)
        
        # Add invitation
        invitation = GroupInvitation(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            email="pending@example.com",
            role=GroupRole.MEMBER,
            token=str(uuid.uuid4().hex),
            status=InvitationStatus.PENDING
        )
        group_manager.store.create_invitation(invitation)
        
        # Get summary
        summary = group_manager.get_group_summary(sample_group.id)
        
        assert summary is not None
        assert summary["group"]["id"] == sample_group.id
        assert summary["member_count"] == 3
        assert summary["pending_invitations"] == 1
        assert summary["role_distribution"]["administrator"] == 1
        assert summary["role_distribution"]["manager"] == 1
        assert summary["role_distribution"]["member"] == 1
        assert len(summary["recent_members"]) == 3
    
    def test_get_group_summary_not_found(self, group_manager):
        """Test getting summary for non-existent group"""
        summary = group_manager.get_group_summary("nonexistent_id")
        assert summary is None
    
    def test_get_group_summary_empty_group(self, group_manager, sample_group):
        """Test getting summary for empty group"""
        # Create empty group
        group_manager.store.create_group(sample_group)
        
        # Get summary
        summary = group_manager.get_group_summary(sample_group.id)
        
        assert summary is not None
        assert summary["member_count"] == 0
        assert summary["pending_invitations"] == 0
        assert summary["role_distribution"]["administrator"] == 0
        assert summary["role_distribution"]["manager"] == 0
        assert summary["role_distribution"]["member"] == 0
        assert len(summary["recent_members"]) == 0