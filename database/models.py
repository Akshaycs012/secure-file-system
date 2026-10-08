from datetime import datetime

import uuid

from database.db import db

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ============================================================
# USER
# ============================================================

class User(db.Model):

    __tablename__ = "users"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    username = db.Column(
        db.String(100),
        nullable=False,
        unique=True
    )

    email = db.Column(
        db.String(255),
        nullable=False,
        unique=True
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    # --------------------------------------------------------
    # FILES OWNED BY USER
    # --------------------------------------------------------

    files = db.relationship(
        "File",
        back_populates="owner"
    )

    # --------------------------------------------------------
    # WORKSPACES OWNED BY USER
    # --------------------------------------------------------

    owned_workspaces = db.relationship(
        "Workspace",
        foreign_keys="Workspace.owner_id",
        back_populates="owner"
    )

    # --------------------------------------------------------
    # WORKSPACE MEMBERSHIPS
    # --------------------------------------------------------

    workspace_memberships = db.relationship(
        "WorkspaceMember",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    # --------------------------------------------------------
    # DELETION REQUESTS CREATED BY USER
    # --------------------------------------------------------

    deletion_requests = db.relationship(
        "DeletionRequest",
        foreign_keys="DeletionRequest.requester_id",
        back_populates="requester"
    )

    # --------------------------------------------------------
    # DELETION APPROVALS MADE BY USER
    # --------------------------------------------------------

    deletion_approvals = db.relationship(
        "DeletionApproval",
        foreign_keys="DeletionApproval.approver_id",
        back_populates="approver"
    )

    # --------------------------------------------------------
    # NOTIFICATIONS
    # --------------------------------------------------------

    notifications = db.relationship(
        "Notification",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    # --------------------------------------------------------
    # PASSWORD
    # --------------------------------------------------------

    def set_password(self, password):

        if not password:
            raise ValueError(
                "Password is required."
            )

        if len(password) < 8:
            raise ValueError(
                "Password must be at least 8 characters long."
            )

        self.password_hash = generate_password_hash(
            password
        )

    def check_password(self, password):

        return check_password_hash(
            self.password_hash,
            password
        )

    # --------------------------------------------------------
    # SERIALIZATION
    # --------------------------------------------------------

    def to_dict(self):

        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at.isoformat()
        }


# ============================================================
# WORKSPACE
# ============================================================

class Workspace(db.Model):

    __tablename__ = "workspaces"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    name = db.Column(
        db.String(150),
        nullable=False
    )

    type = db.Column(
        db.String(20),
        nullable=False
    )

    owner_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    # Number of approvals required before deletion.
    #
    # Personal:
    #     normally 1
    #
    # Organization:
    #     e.g. 3 for a 3-of-M policy.

    required_approvals = db.Column(
        db.Integer,
        nullable=False,
        default=1
    )

    # Mandatory waiting period before deletion.
    #
    # Personal:
    #     can be 0 or configured
    #
    # Organization:
    #     default 24 hours.

    approval_delay_hours = db.Column(
        db.Integer,
        nullable=False,
        default=24
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    # --------------------------------------------------------
    # OWNER
    # --------------------------------------------------------

    owner = db.relationship(
        "User",
        foreign_keys=[owner_id],
        back_populates="owned_workspaces"
    )

    # --------------------------------------------------------
    # MEMBERS
    # --------------------------------------------------------

    members = db.relationship(
        "WorkspaceMember",
        back_populates="workspace",
        cascade="all, delete-orphan"
    )

    # --------------------------------------------------------
    # FILES
    # --------------------------------------------------------

    files = db.relationship(
        "File",
        back_populates="workspace"
    )

    # --------------------------------------------------------
    # INVITATIONS
    # --------------------------------------------------------

    invitations = db.relationship(
        "WorkspaceInvitation",
        back_populates="workspace",
        cascade="all, delete-orphan"
    )

    # --------------------------------------------------------
    # DELETION REQUESTS
    # --------------------------------------------------------

    deletion_requests = db.relationship(
        "DeletionRequest",
        back_populates="workspace",
        cascade="all, delete-orphan"
    )

    # --------------------------------------------------------
    # NOTIFICATIONS
    # --------------------------------------------------------

    notifications = db.relationship(
        "Notification",
        back_populates="workspace",
        cascade="all, delete-orphan"
    )

    # --------------------------------------------------------
    # SERIALIZATION
    # --------------------------------------------------------

    def to_dict(self):

        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "owner_id": self.owner_id,
            "required_approvals": self.required_approvals,
            "approval_delay_hours": self.approval_delay_hours,
            "created_at": self.created_at.isoformat()
        }


# ============================================================
# WORKSPACE MEMBER
# ============================================================

class WorkspaceMember(db.Model):

    __tablename__ = "workspace_members"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    workspace_id = db.Column(
        db.String(36),
        db.ForeignKey("workspaces.id"),
        nullable=False,
        index=True
    )

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="MEMBER"
    )

    can_approve_deletion = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    # --------------------------------------------------------
    # RELATIONSHIPS
    # --------------------------------------------------------

    workspace = db.relationship(
        "Workspace",
        back_populates="members"
    )

    user = db.relationship(
        "User",
        back_populates="workspace_memberships"
    )

    __table_args__ = (
        db.UniqueConstraint(
            "workspace_id",
            "user_id",
            name="uq_workspace_member"
        ),
    )

    # --------------------------------------------------------
    # SERIALIZATION
    # --------------------------------------------------------

    def to_dict(self):

        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "user_id": self.user_id,
            "role": self.role,
            "can_approve_deletion":
                self.can_approve_deletion,
            "created_at":
                self.created_at.isoformat()
        }


# ============================================================
# FILE
# ============================================================

class File(db.Model):

    __tablename__ = "files"

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    owner_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    workspace_id = db.Column(
        db.String(36),
        db.ForeignKey("workspaces.id"),
        nullable=False,
        index=True
    )

    original_name = db.Column(
        db.String(255),
        nullable=False
    )

    encrypted_path = db.Column(
        db.String(500),
        nullable=False,
        unique=True
    )

    size = db.Column(
        db.Integer,
        nullable=False
    )

    sha256 = db.Column(
        db.String(64),
        nullable=False
    )

    key_id = db.Column(
        db.String(32),
        nullable=False
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="PROTECTED"
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    # --------------------------------------------------------
    # OWNER
    # --------------------------------------------------------

    owner = db.relationship(
        "User",
        back_populates="files"
    )

    # --------------------------------------------------------
    # WORKSPACE
    # --------------------------------------------------------

    workspace = db.relationship(
        "Workspace",
        back_populates="files"
    )

    # --------------------------------------------------------
    # DELETION REQUESTS
    # --------------------------------------------------------

    deletion_requests = db.relationship(
        "DeletionRequest",
        back_populates="file",
        cascade="all, delete-orphan"
    )

    # --------------------------------------------------------
    # SERIALIZATION
    # --------------------------------------------------------

    def to_dict(self):

        return {
            "id": self.id,
            "original_name": self.original_name,
            "encrypted_path": self.encrypted_path,
            "size": self.size,
            "sha256": self.sha256,
            "key_id": self.key_id,
            "status": self.status,
            "workspace_id": self.workspace_id,
            "created_at":
                self.created_at.isoformat()
        }


# ============================================================
# WORKSPACE INVITATION
# ============================================================

class WorkspaceInvitation(db.Model):

    __tablename__ = "workspace_invitations"

    id = db.Column(
        db.String(36),
        primary_key=True
    )

    workspace_id = db.Column(
        db.String(36),
        db.ForeignKey("workspaces.id"),
        nullable=False,
        index=True
    )

    invited_email = db.Column(
        db.String(255),
        nullable=False,
        index=True
    )

    invitation_code = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        index=True
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="MEMBER"
    )

    can_approve_deletion = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="PENDING"
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=False
    )

    # --------------------------------------------------------
    # WORKSPACE
    # --------------------------------------------------------

    workspace = db.relationship(
        "Workspace",
        back_populates="invitations"
    )

    # --------------------------------------------------------
    # SERIALIZATION
    # --------------------------------------------------------

    def to_dict(self):

        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "invited_email": self.invited_email,
            "role": self.role,
            "can_approve_deletion":
                self.can_approve_deletion,
            "status": self.status,
            "created_at":
                self.created_at.isoformat(),
            "expires_at":
                self.expires_at.isoformat()
        }


# ============================================================
# DELETION REQUEST
# ============================================================

class DeletionRequest(db.Model):

    __tablename__ = "deletion_requests"

    id = db.Column(
        db.String(36),
        primary_key=True
    )

    workspace_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "workspaces.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    file_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "files.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    requester_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="PENDING"
    )

    required_approvals = db.Column(
        db.Integer,
        nullable=False
    )

    approval_count = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    rejection_count = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    requested_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    approved_at = db.Column(
        db.DateTime,
        nullable=True
    )

    execute_after = db.Column(
        db.DateTime,
        nullable=True
    )

    completed_at = db.Column(
        db.DateTime,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # --------------------------------------------------------
    # RELATIONSHIPS
    # --------------------------------------------------------

    workspace = db.relationship(
        "Workspace",
        back_populates="deletion_requests"
    )

    file = db.relationship(
        "File",
        back_populates="deletion_requests"
    )

    requester = db.relationship(
        "User",
        foreign_keys=[requester_id],
        back_populates="deletion_requests"
    )

    approvals = db.relationship(
        "DeletionApproval",
        back_populates="request",
        cascade="all, delete-orphan"
    )

    notifications = db.relationship(
        "Notification",
        back_populates="deletion_request",
        cascade="all, delete-orphan"
    )

    # --------------------------------------------------------
    # SERIALIZATION
    # --------------------------------------------------------

    def to_dict(self):

        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "file_id": self.file_id,
            "requester_id": self.requester_id,
            "status": self.status,
            "required_approvals":
                self.required_approvals,
            "approval_count":
                self.approval_count,
            "rejection_count":
                self.rejection_count,
            "requested_at": (
                self.requested_at.isoformat()
                if self.requested_at
                else None
            ),
            "approved_at": (
                self.approved_at.isoformat()
                if self.approved_at
                else None
            ),
            "execute_after": (
                self.execute_after.isoformat()
                if self.execute_after
                else None
            ),
            "completed_at": (
                self.completed_at.isoformat()
                if self.completed_at
                else None
            )
        }


# ============================================================
# DELETION APPROVAL
# ============================================================

class DeletionApproval(db.Model):

    __tablename__ = "deletion_approvals"

    id = db.Column(
        db.String(36),
        primary_key=True
    )

    request_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "deletion_requests.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    approver_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    decision = db.Column(
        db.String(20),
        nullable=False
    )

    comment = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # --------------------------------------------------------
    # RELATIONSHIPS
    # --------------------------------------------------------

    request = db.relationship(
        "DeletionRequest",
        back_populates="approvals"
    )

    approver = db.relationship(
        "User",
        back_populates="deletion_approvals"
    )

    __table_args__ = (
        db.UniqueConstraint(
            "request_id",
            "approver_id",
            name="uq_deletion_request_approver"
        ),
    )

    # --------------------------------------------------------
    # SERIALIZATION
    # --------------------------------------------------------

    def to_dict(self):

        return {
            "id": self.id,
            "request_id": self.request_id,
            "approver_id": self.approver_id,
            "decision": self.decision,
            "comment": self.comment,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            )
        }


# ============================================================
# NOTIFICATION
# ============================================================

class Notification(db.Model):

    __tablename__ = "notifications"

    id = db.Column(
        db.String(36),
        primary_key=True
    )

    user_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    workspace_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "workspaces.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    type = db.Column(
        db.String(50),
        nullable=False
    )

    message = db.Column(
        db.Text,
        nullable=False
    )

    related_request_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "deletion_requests.id",
            ondelete="CASCADE"
        ),
        nullable=True,
        index=True
    )

    is_read = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # --------------------------------------------------------
    # RELATIONSHIPS
    # --------------------------------------------------------

    user = db.relationship(
        "User",
        back_populates="notifications"
    )

    workspace = db.relationship(
        "Workspace",
        back_populates="notifications"
    )

    deletion_request = db.relationship(
        "DeletionRequest",
        back_populates="notifications"
    )

    # --------------------------------------------------------
    # SERIALIZATION
    # --------------------------------------------------------

    def to_dict(self):

        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "type": self.type,
            "message": self.message,
            "related_request_id":
                self.related_request_id,
            "is_read": self.is_read,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            )
        }