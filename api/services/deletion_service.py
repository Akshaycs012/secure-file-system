import uuid

from datetime import datetime, timedelta

from database.db import db

from database.models import (
    File,
    Workspace,
    WorkspaceMember,
    DeletionRequest,
    DeletionApproval,
    Notification,
)

from api.services.workspace_service import (
    require_workspace_membership,
    get_deletion_approvers,
    validate_deletion_policy,
)

from api.services.file_service import delete_file_by_id


# ============================================================
# CONSTANTS
# ============================================================

STATUS_PENDING = "PENDING"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_EXECUTING = "EXECUTING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"
STATUS_CANCELLED = "CANCELLED"


DECISION_APPROVED = "APPROVED"
DECISION_REJECTED = "REJECTED"


NOTIFICATION_DELETION_REQUEST = "DELETION_REQUEST"
NOTIFICATION_DELETION_APPROVED = "DELETION_APPROVED"
NOTIFICATION_DELETION_REJECTED = "DELETION_REJECTED"
NOTIFICATION_DELETION_COMPLETED = "DELETION_COMPLETED"
NOTIFICATION_DELETION_FAILED = "DELETION_FAILED"


DEFAULT_APPROVAL_DELAY_HOURS = 24


# ============================================================
# INTERNAL HELPERS
# ============================================================

def get_deletion_request(request_id):
    request = db.session.get(
        DeletionRequest,
        request_id
    )

    if request is None:
        raise ValueError(
            "Deletion request not found."
        )

    return request


def get_file_for_workspace(file_id, workspace_id):
    file_record = File.query.filter_by(
        id=file_id,
        workspace_id=workspace_id
    ).first()

    if file_record is None:
        raise FileNotFoundError(
            "File not found in this workspace."
        )

    return file_record


def get_eligible_approver_ids(workspace_id):
    approvers = get_deletion_approvers(
        workspace_id
    )

    return {
        member.user_id
        for member in approvers
    }


def create_notification(
    user_id,
    workspace_id,
    notification_type,
    message,
    related_request_id=None
):
    notification = Notification(
        id=str(uuid.uuid4()),
        user_id=user_id,
        workspace_id=workspace_id,
        type=notification_type,
        message=message,
        related_request_id=related_request_id,
        is_read=False
    )

    db.session.add(notification)

    return notification


def notify_eligible_approvers(
    workspace_id,
    request_id,
    message,
    notification_type
):
    approvers = get_deletion_approvers(
        workspace_id
    )

    for member in approvers:

        create_notification(
            user_id=member.user_id,
            workspace_id=workspace_id,
            notification_type=notification_type,
            message=message,
            related_request_id=request_id
        )


# ============================================================
# CREATE DELETION REQUEST
# ============================================================

def create_deletion_request(
    file_id,
    workspace_id,
    requester_id
):
    """
    Create a deletion request.

    PERSONAL workspace:
        Deletion is handled immediately by the existing
        secure deletion engine.

    ORGANIZATION workspace:
        A governance request is created and approvals
        are required before deletion.
    """

    membership = require_workspace_membership(
        workspace_id,
        requester_id
    )

    workspace = membership.workspace

    file_record = get_file_for_workspace(
        file_id,
        workspace_id
    )

    # --------------------------------------------------------
    # Prevent duplicate active requests
    # --------------------------------------------------------

    existing_request = DeletionRequest.query.filter(
        DeletionRequest.file_id == file_id,
        DeletionRequest.status.in_([
            STATUS_PENDING,
            STATUS_APPROVED,
            STATUS_EXECUTING
        ])
    ).first()

    if existing_request is not None:
        raise ValueError(
            "A deletion request already exists for this file."
        )

    # --------------------------------------------------------
    # PERSONAL WORKSPACE
    # --------------------------------------------------------

    if workspace.type == "PERSONAL":

        delete_file_by_id(
            file_id=file_id,
            workspace_id=workspace_id,
            requester_id=requester_id
        )

        return {
            "type": "IMMEDIATE",
            "message": "File deleted successfully.",
            "request": None
        }

    # --------------------------------------------------------
    # ORGANIZATION WORKSPACE
    # --------------------------------------------------------

    if workspace.type != "ORGANIZATION":

        raise ValueError(
            "Invalid workspace type."
        )

    # --------------------------------------------------------
    # Validate deletion policy
    # --------------------------------------------------------

    validate_deletion_policy(
        workspace
    )

    approvers = get_deletion_approvers(
        workspace_id
    )

    eligible_count = len(approvers)

    if eligible_count == 0:

        raise ValueError(
            "No eligible deletion approvers exist."
        )

    if workspace.required_approvals > eligible_count:

        raise ValueError(
            "Deletion policy is invalid."
        )

    # --------------------------------------------------------
    # Create request
    # --------------------------------------------------------

    request_id = str(uuid.uuid4())

    deletion_request = DeletionRequest(
        id=request_id,
        workspace_id=workspace_id,
        file_id=file_id,
        requester_id=requester_id,
        status=STATUS_PENDING,
        required_approvals=workspace.required_approvals,
        approval_count=0,
        rejection_count=0,
        requested_at=datetime.utcnow()
    )

    db.session.add(
        deletion_request
    )

    db.session.flush()

    # --------------------------------------------------------
    # Notify eligible approvers
    # --------------------------------------------------------

    message = (
        f"Deletion requested for file "
        f"'{file_record.original_name}'. "
        f"Approval required: "
        f"{workspace.required_approvals}."
    )

    notify_eligible_approvers(
        workspace_id=workspace_id,
        request_id=request_id,
        message=message,
        notification_type=NOTIFICATION_DELETION_REQUEST
    )

    db.session.flush()

    return {
        "type": "GOVERNED",
        "message": "Deletion request created successfully.",
        "request": deletion_request
    }


# ============================================================
# APPROVE DELETION
# ============================================================

def approve_deletion_request(
    request_id,
    approver_id,
    comment=None
):
    """
    Approve a deletion request.

    Rules:
        - Approver must be eligible.
        - Approver can vote only once.
        - Request must be PENDING.
        - When N approvals are reached,
          request becomes APPROVED.
        - Workspace-specific approval delay starts
          at approval time.
    """

    deletion_request = get_deletion_request(
        request_id
    )

    if deletion_request.status != STATUS_PENDING:

        raise ValueError(
            "This deletion request is no longer pending."
        )

    eligible_approver_ids = (
        get_eligible_approver_ids(
            deletion_request.workspace_id
        )
    )

    if approver_id not in eligible_approver_ids:

        raise PermissionError(
            "You are not authorized to approve this deletion request."
        )

    # --------------------------------------------------------
    # Prevent duplicate vote
    # --------------------------------------------------------

    existing_vote = DeletionApproval.query.filter_by(
        request_id=request_id,
        approver_id=approver_id
    ).first()

    if existing_vote is not None:

        raise ValueError(
            "You have already voted on this deletion request."
        )

    # --------------------------------------------------------
    # Create approval
    # --------------------------------------------------------

    approval = DeletionApproval(
        id=str(uuid.uuid4()),
        request_id=request_id,
        approver_id=approver_id,
        decision=DECISION_APPROVED,
        comment=comment
    )

    db.session.add(
        approval
    )

    db.session.flush()

    # --------------------------------------------------------
    # Update approval count
    # --------------------------------------------------------

    approval_count = DeletionApproval.query.filter_by(
        request_id=request_id,
        decision=DECISION_APPROVED
    ).count()

    rejection_count = DeletionApproval.query.filter_by(
        request_id=request_id,
        decision=DECISION_REJECTED
    ).count()

    deletion_request.approval_count = approval_count
    deletion_request.rejection_count = rejection_count

    # --------------------------------------------------------
    # Check quorum
    # --------------------------------------------------------

    if approval_count >= deletion_request.required_approvals:

        deletion_request.status = STATUS_APPROVED

        approval_time = datetime.utcnow()

        deletion_request.approved_at = approval_time

        # Use the actual workspace policy.
        delay_hours = (
            deletion_request.workspace.approval_delay_hours
        )

        deletion_request.execute_after = (
            approval_time
            + timedelta(hours=delay_hours)
        )

        file_record = db.session.get(
            File,
            deletion_request.file_id
        )

        if file_record is not None:

            message = (
                f"Deletion request for "
                f"'{file_record.original_name}' "
                f"has received the required approvals. "
                f"Deletion will be eligible after "
                f"{delay_hours} hours."
            )

        else:

            message = (
                "Deletion request has received "
                "the required approvals."
            )

        # Notify requester.
        create_notification(
            user_id=deletion_request.requester_id,
            workspace_id=deletion_request.workspace_id,
            notification_type=NOTIFICATION_DELETION_APPROVED,
            message=message,
            related_request_id=request_id
        )

    else:

        file_record = db.session.get(
            File,
            deletion_request.file_id
        )

        filename = (
            file_record.original_name
            if file_record
            else "file"
        )

        message = (
            f"Deletion request for '{filename}' "
            f"received an approval. "
            f"Current approvals: "
            f"{approval_count}/"
            f"{deletion_request.required_approvals}."
        )

        create_notification(
            user_id=deletion_request.requester_id,
            workspace_id=deletion_request.workspace_id,
            notification_type=NOTIFICATION_DELETION_APPROVED,
            message=message,
            related_request_id=request_id
        )

    db.session.flush()

    return deletion_request


# ============================================================
# REJECT DELETION
# ============================================================

def reject_deletion_request(
    request_id,
    approver_id,
    comment=None
):
    """
    Reject a deletion request.

    A rejection acts as a veto.

    Once an eligible approver rejects the request,
    the request becomes REJECTED and cannot continue.
    """

    deletion_request = get_deletion_request(
        request_id
    )

    if deletion_request.status != STATUS_PENDING:

        raise ValueError(
            "This deletion request is no longer pending."
        )

    eligible_approver_ids = (
        get_eligible_approver_ids(
            deletion_request.workspace_id
        )
    )

    if approver_id not in eligible_approver_ids:

        raise PermissionError(
            "You are not authorized to reject this deletion request."
        )

    # --------------------------------------------------------
    # Prevent duplicate vote
    # --------------------------------------------------------

    existing_vote = DeletionApproval.query.filter_by(
        request_id=request_id,
        approver_id=approver_id
    ).first()

    if existing_vote is not None:

        raise ValueError(
            "You have already voted on this deletion request."
        )

    # --------------------------------------------------------
    # Create rejection
    # --------------------------------------------------------

    rejection = DeletionApproval(
        id=str(uuid.uuid4()),
        request_id=request_id,
        approver_id=approver_id,
        decision=DECISION_REJECTED,
        comment=comment
    )

    db.session.add(
        rejection
    )

    db.session.flush()

    # --------------------------------------------------------
    # Update counts
    # --------------------------------------------------------

    approval_count = DeletionApproval.query.filter_by(
        request_id=request_id,
        decision=DECISION_APPROVED
    ).count()

    rejection_count = DeletionApproval.query.filter_by(
        request_id=request_id,
        decision=DECISION_REJECTED
    ).count()

    deletion_request.approval_count = approval_count
    deletion_request.rejection_count = rejection_count

    # --------------------------------------------------------
    # Rejection is a veto
    # --------------------------------------------------------

    deletion_request.status = STATUS_REJECTED

    file_record = db.session.get(
        File,
        deletion_request.file_id
    )

    filename = (
        file_record.original_name
        if file_record
        else "file"
    )

    message = (
        f"Deletion request for '{filename}' "
        f"was rejected by an eligible approver."
    )

    create_notification(
        user_id=deletion_request.requester_id,
        workspace_id=deletion_request.workspace_id,
        notification_type=NOTIFICATION_DELETION_REJECTED,
        message=message,
        related_request_id=request_id
    )

    db.session.flush()

    return deletion_request


# ============================================================
# CHECK WHETHER REQUEST CAN BE EXECUTED
# ============================================================

def can_execute_deletion(request_id):
    """
    Check whether an approved deletion request has
    completed its required waiting period.
    """

    deletion_request = get_deletion_request(
        request_id
    )

    if deletion_request.status != STATUS_APPROVED:

        return False

    if deletion_request.execute_after is None:

        return False

    return (
        datetime.utcnow()
        >= deletion_request.execute_after
    )


# ============================================================
# EXECUTE APPROVED DELETION
# ============================================================

def execute_deletion_request(
    request_id,
    executor_id=None
):
    """
    Execute an approved deletion request after the
    required waiting period.

    This function calls the existing secure deletion
    engine. It does NOT duplicate the encryption/WORM
    deletion logic.
    """

    deletion_request = get_deletion_request(
        request_id
    )

    # --------------------------------------------------------
    # Validate status
    # --------------------------------------------------------

    if deletion_request.status != STATUS_APPROVED:

        raise ValueError(
            "Deletion request is not approved."
        )

    # --------------------------------------------------------
    # Validate waiting period
    # --------------------------------------------------------

    if not can_execute_deletion(request_id):

        raise ValueError(
            "Deletion request is still within "
            "the approval delay period."
        )

    # --------------------------------------------------------
    # Get file
    # --------------------------------------------------------

    file_record = db.session.get(
        File,
        deletion_request.file_id
    )

    if file_record is None:

        deletion_request.status = STATUS_FAILED

        db.session.flush()

        raise FileNotFoundError(
            "File associated with deletion request was not found."
        )

    # --------------------------------------------------------
    # IMPORTANT:
    # Save filename BEFORE secure deletion.
    #
    # delete_file_by_id() can commit the transaction and
    # delete the File database record.
    # --------------------------------------------------------

    filename = file_record.original_name

    deletion_request.status = STATUS_EXECUTING

    db.session.flush()

    try:

        # ----------------------------------------------------
        # CALL EXISTING SECURE DELETE ENGINE
        # ----------------------------------------------------

        delete_file_by_id(
            file_id=deletion_request.file_id,
            workspace_id=deletion_request.workspace_id,
            requester_id=(
                executor_id
                or deletion_request.requester_id
            )
        )

        # ----------------------------------------------------
        # Mark governance request completed
        # ----------------------------------------------------

        deletion_request.status = STATUS_COMPLETED

        deletion_request.completed_at = (
            datetime.utcnow()
        )

        message = (
            f"File '{filename}' "
            f"was securely deleted."
        )

        create_notification(
            user_id=deletion_request.requester_id,
            workspace_id=deletion_request.workspace_id,
            notification_type=NOTIFICATION_DELETION_COMPLETED,
            message=message,
            related_request_id=request_id
        )

        db.session.commit()

        return deletion_request

    except Exception as error:

        db.session.rollback()

        # ----------------------------------------------------
        # Reload governance request after rollback.
        # ----------------------------------------------------

        deletion_request = get_deletion_request(
            request_id
        )

        deletion_request.status = STATUS_FAILED

        create_notification(
            user_id=deletion_request.requester_id,
            workspace_id=deletion_request.workspace_id,
            notification_type=NOTIFICATION_DELETION_FAILED,
            message=(
                "Secure deletion failed: "
                f"{str(error)}"
            ),
            related_request_id=request_id
        )

        db.session.commit()

        raise


# ============================================================
# LIST USER DELETION REQUESTS
# ============================================================

def list_user_deletion_requests(user_id):
    """
    Return deletion requests belonging to workspaces
    where the user is a member.
    """

    requests = (
        DeletionRequest.query
        .join(
            Workspace,
            DeletionRequest.workspace_id
            == Workspace.id
        )
        .join(
            WorkspaceMember,
            WorkspaceMember.workspace_id
            == Workspace.id
        )
        .filter(
            WorkspaceMember.user_id == user_id
        )
        .order_by(
            DeletionRequest.requested_at.desc()
        )
        .all()
    )

    # --------------------------------------------------------
    # Remove duplicates caused by membership join.
    # --------------------------------------------------------

    unique_requests = {}

    for request in requests:

        unique_requests[request.id] = request

    return list(
        unique_requests.values()
    )


# ============================================================
# GET REQUEST DETAILS
# ============================================================

def get_deletion_request_for_user(
    request_id,
    user_id
):
    """
    Return a deletion request only if the user belongs
    to the workspace.
    """

    deletion_request = get_deletion_request(
        request_id
    )

    require_workspace_membership(
        deletion_request.workspace_id,
        user_id
    )

    return deletion_request