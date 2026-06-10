"""SQLAlchemy ORM models."""
from app.models.tag import AssetTag, Tag  # must precede asset (adds Asset.tag_assignments)
from app.models.asset import Asset, AssetGroup, asset_group_members
from app.models.audit import AuditLog
from app.models.account import (
    Account,
    AccountEntitlement,
    DiscoveryResultRaw,
)
from app.models.connector import Connector, Credential
from app.models.connector_agent import (  # must precede finding (FK: privilege_findings → connector_agent_jobs)
    ConnectorAgent,
    ConnectorEnrollmentToken,
    ConnectorAgentSettings,
    ConnectorAgentHeartbeat,
    ConnectorAgentJob,
    ConnectorAgentResult,
    ConnectorAgentResultChunk,
    ConnectorAgentLog,
)
from app.models.exception_rule import PrivilegeException
from app.models.finding import PrivilegeFinding, FindingReviewState
from app.models.job import (
    DiscoveryJob,
    DiscoveryJobTarget,
    ScanProfile,
    ScheduledScan,
    ScanBlackoutWindow,
    BulkImportJob,
)
from app.models.notification import Notification
from app.models.rule import ClassificationRule
from app.models.user import Role, User, user_roles

__all__ = [
    "Asset",
    "AssetGroup",
    "asset_group_members",
    "AuditLog",
    "Account",
    "AccountEntitlement",
    "DiscoveryResultRaw",
    "Connector",
    "Credential",
    "PrivilegeException",
    "PrivilegeFinding",
    "FindingReviewState",
    "DiscoveryJob",
    "DiscoveryJobTarget",
    "ScanProfile",
    "ScheduledScan",
    "ScanBlackoutWindow",
    "BulkImportJob",
    "Notification",
    "ClassificationRule",
    "Role",
    "User",
    "user_roles",
    "Tag",
    "AssetTag",
    "ConnectorAgent",
    "ConnectorEnrollmentToken",
    "ConnectorAgentSettings",
    "ConnectorAgentHeartbeat",
    "ConnectorAgentJob",
    "ConnectorAgentResult",
    "ConnectorAgentResultChunk",
    "ConnectorAgentLog",
]
