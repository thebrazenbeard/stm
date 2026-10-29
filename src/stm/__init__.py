"""STM: explicitly scoped, model-independent working memory."""

from .core import STM, MemorySession, AdmissionRejected, AccessDenied
from .models import MemoryRecord, PromptContext, SessionKey, VersionConflict, CapacityExceeded
from .archive import ArchiveScope, ArchiveTurn, ArchiveHit, ConversationArchive
from .archive_adapter import ArchiveHistoryReader
from .tokenizer_adapter import (
    ModelTokenizerIdentity, RuntimeTokenCounter, TokenBudgetAdapter,
)
from .retention import RetentionPolicy, RetentionAudit, RetainedConversationArchive
from .vera_bridge import VerifiedConversation, VerifiedRetentionGate, VeraConversationBridge
from .auth_broker import (
    ConversationCredentialSpec, HmacCredentialIssuer,
    HmacConversationBroker, ScopedCleanupAuthority,
)
from .retention_runner import SweepTarget, SweepReport, RetentionSweepRunner
from .storage_privacy import (
    BackupReceipt, BackupInventory, BackupRetirement,
    WalCheckpoint, ManagedArchiveBackupVault,
)
from .handoff_policy import (
    DEFAULT_REVIEW_AGE, HandoffPolicy, HandoffEligibility,
    HandoffReviewTicket, HandoffReviewQueue,
)
from .deepmemory_handoff import (
    HISTORICAL_ONLY, TargetGovernance, HistoricalHandoffRecord,
    HistoricalHandoffReceipt, HistoricalSink, HandoffUnverified,
    DeepMemoryHandoff,
)
from .windows_host_auth import WindowsPeerMemoryGateway, authenticated_windows_sid
from .android_local_auth import (
    AndroidAppIdentity, AndroidAppRegistration, AndroidAppPeerGateway,
    verify_android_binding,
)
from .retention_window_3045 import (
    REVIEW_AFTER, LOCAL_EXPIRE_AFTER, REVIEW_PERIOD, MAX_CLOCK_SKEW,
    ThirtyFortyFiveReviewPolicy, ThirtyFortyFiveRetentionGate,
    ThirtyFortyFiveWindow,
)

__all__ = [
    "STM", "MemorySession", "AdmissionRejected", "AccessDenied",
    "MemoryRecord", "PromptContext", "SessionKey", "VersionConflict", "CapacityExceeded",
    "ArchiveScope", "ArchiveTurn", "ArchiveHit", "ConversationArchive",
    "ArchiveHistoryReader", "ModelTokenizerIdentity", "RuntimeTokenCounter",
    "TokenBudgetAdapter",
    "RetentionPolicy", "RetentionAudit", "RetainedConversationArchive",
    "VerifiedConversation", "VerifiedRetentionGate", "VeraConversationBridge",
    "ConversationCredentialSpec", "HmacCredentialIssuer", "HmacConversationBroker",
    "ScopedCleanupAuthority", "SweepTarget", "SweepReport", "RetentionSweepRunner",
    "BackupReceipt", "BackupInventory", "BackupRetirement", "WalCheckpoint",
    "ManagedArchiveBackupVault",
    "DEFAULT_REVIEW_AGE", "HandoffPolicy", "HandoffEligibility",
    "HandoffReviewTicket", "HandoffReviewQueue",
    "HISTORICAL_ONLY", "TargetGovernance", "HistoricalHandoffRecord",
    "HistoricalHandoffReceipt", "HistoricalSink", "HandoffUnverified",
    "DeepMemoryHandoff", "WindowsPeerMemoryGateway",
    "authenticated_windows_sid", "AndroidAppIdentity", "AndroidAppRegistration",
    "AndroidAppPeerGateway", "verify_android_binding",
    "REVIEW_AFTER", "LOCAL_EXPIRE_AFTER", "REVIEW_PERIOD",
    "MAX_CLOCK_SKEW", "ThirtyFortyFiveReviewPolicy",
    "ThirtyFortyFiveRetentionGate", "ThirtyFortyFiveWindow",
]
