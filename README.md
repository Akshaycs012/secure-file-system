# 🔐 Secure File System

<p align="center">
  <b>A security-focused file storage system featuring authenticated encryption, integrity verification, immutable WORM storage, hash-chained audit logging, managed key lifecycles, and multi-party governed deletion.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-D97706?logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/Flask-3.x-B45309?logo=flask&logoColor=white" alt="Flask 3.x" />
  <img src="https://img.shields.io/badge/AES--256--GCM-Encryption-9A3412" alt="AES-256-GCM" />
  <img src="https://img.shields.io/badge/SQLite-Database-78350F?logo=sqlite&logoColor=white" alt="SQLite" />
  <img src="https://img.shields.io/badge/JWT-Authentication-C2410C" alt="JWT Auth" />
  <img src="https://img.shields.io/badge/Linux-WORM%20Protection-EA580C?logo=linux&logoColor=white" alt="Linux WORM" />
</p>

---

## 📌 Overview

**Secure File System** is a production-minded Python platform engineered to protect sensitive files across every phase of their lifecycle.

Rather than viewing storage security purely as a static encryption problem, this system implements an integrated, defense-in-depth model across nine critical security domains:

- 🔐 **Confidentiality:** Authenticated symmetric encryption for data at rest.
- 🛡️ **Integrity:** SHA-256 cryptographic checksums paired with GCM auth tags.
- 🔑 **Key Management:** Lifecycle state transitions, historical lookup, and rotation.
- 🔒 **Immutable Storage:** Filesystem-level WORM protection (`chattr +i`).
- 📜 **Auditability:** Cryptographically linked hash-chained transaction logs.
- ♻️ **Crash Recovery:** Atomic two-phase storage/database state resilience.
- 👥 **Access Control:** User authentication and role-based workspace authorization.
- 🏢 **Workspace Isolation:** Multi-tenant segmentation (Personal vs. Organization).
- ✅ **Governed Deletion:** Multi-user quorum approvals and delay timers before destruction.

Uploaded files are encrypted using **AES-256-GCM** via a streaming pipeline, stored with metadata blocks, locked against filesystem modification, and audited via a **tamper-evident hash chain**.

---

## 🎯 Problem Statement

Standard storage solutions treat file operations simply as read/write streams. For sensitive, compliance-critical environments, security must govern the full lifecycle—from initial upload to secure sanitization.

```text
                           Traditional File Storage
                                      │
                                      ▼
                             [ Store Raw File ]
                                      │
                                      ▼
                            [ Retrieve Raw File ]

─────────────────────────────────────────────────────────────────────────────

                             Secure File System
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
  Confidentiality                 Integrity                    Availability
        │                             │                             │
  AES-256-GCM                   SHA-256 + Audit               Crash Recovery
        │                             │                             │
  Key Lifecycle                 WORM Protection             Transaction Safety
        │                             │                             │
        └─────────────────────────────┼─────────────────────────────┘
                                      ▼
                              Governed Deletion
End-to-End File Lifecycle FlowPlaintextUpload ──► Auth Check ──► AES-256-GCM ──► SHA-256 Hash ──► WORM Lock ──► Secure Store
                                                                             │
Audit Log ◄── Permanent Purge ◄── Quorum Approval ◄── Deletion Request ◄─────┘
✨ Key Features🔐 1. AES-256-GCM File EncryptionAuthenticated Encryption: Uses AES-256-GCM to ensure confidentiality while guaranteeing authentic origin and detecting payload modification via 128-bit authentication tags.Streaming Pipeline: Files are processed in configurable chunk sizes, ensuring constant $O(1)$ memory usage even when handling gigabyte-scale uploads.Plaintext[ Original File ] ──► [ Generate Key & Nonce ] ──► [ AES-256-GCM ] ──► [ Encrypted .sfs Output ]
                                                          │
                                                  [ Auth Tag Generated ]
🔑 2. Encryption Key Lifecycle ManagementKeys are isolated from the encrypted payloads they protect. The key engine manages state transitions across seven explicit lifecycle phases:Plaintext                 ┌──────────┐
                 │ GENERATE │
                 └────┬─────┘
                      ▼
                 ┌──────────┐
                 │  ACTIVE  │
                 └────┬─────┘
                      │
           (Key Rotation Trigger)
                      │
                      ▼
                 ┌──────────┐
                 │ RETIRED  │ ──► (Retained for historical decryption)
                 └────┬─────┘
                      │
            (Security Event / Breach)
                      │
                      ▼
                 ┌──────────┐
                 │ REVOKED  │ ──► (Decryption disabled permanently)
                 └──────────┘
🛡️ 3. File Integrity Verification EngineEach stored file is tracked via cryptographic hashes and state machine evaluations. System calls evaluate files into discrete statuses:StatusDescriptionVERIFIEDFile is structurally valid, payload matches SHA-256 digest, and GCM tag verifies.TAMPEREDSignature mismatch or altered byte stream detected; decryption blocked.PROTECTEDFile is encrypted and locked with filesystem immutability.INVALIDMalformed file headers, missing key references, or corrupted structural metadata.UNVERIFIEDFile registered but cryptographic verification step is pending.NOT_FOUNDDatabase reference exists but target blob is missing from storage disk.🔒 4. Linux WORM ProtectionWrite Once Read Many (WORM) constraints are enforced directly at the OS level using Linux extended file flags (chattr +i).Bash# Example immutable file flag output from lsattr:
----i---------e------- /var/sfs/storage/payload_a8f9.sfs
Once protected, standard application processes, user accounts, and compromised runtime workers cannot alter or delete the file payload. The system interacts with chattr through isolated, privilege-restricted subprocess calls rather than running the Flask process with full root context.📜 5. Tamper-Evident Audit LoggingSecurity-relevant operations write to a cryptographically linked append-only hash chain.Plaintext  ┌───────────────────────┐      ┌───────────────────────┐      ┌───────────────────────┐
  │        Event 1        │      │        Event 2        │      │        Event 3        │
  ├───────────────────────┤      ├───────────────────────┤      ├───────────────────────┤
  │ Data: User Login      │      │ Data: File Encrypt    │      │ Data: Delete Request  │
  │ Prev Hash: 0000000000 │ ───► │ Prev Hash: Hash(E1)   │ ───► │ Prev Hash: Hash(E2)   │
  │ Curr Hash: Hash(E1)   │      │ Curr Hash: Hash(E2)   │      │ Curr Hash: Hash(E3)   │
  └───────────────────────┘      └───────────────────────┘      └───────────────────────┘
Any retrospective modification of an audit record invalidates all subsequent hash calculations in the chain, highlighting payload tampering instantly during automated verification runs.♻️ 6. Crash Recovery & Transaction SafetyStorage operations execute inside a dual-boundary transaction layer (Filesystem + Database). If an operation experiences a failure during disk writes or metadata commits, the system triggers rollback state routines to preserve storage consistency.Plaintext[ Start Transaction ] ──► [ Disk Operation ] ──► [ DB Record Update ] ──► [ Audit Write ] ──► [ Commit ]
                                 │                      │                     │
                                 └──────────────────────┼─────────────────────┘
                                                        ▼ (On Failure)
                                           [ Execution Rollback Engine ]
👥 7. Authentication & AuthorizationUses JWT tokens for stateless API authorization. Runtime secrets are dynamically loaded from environment configurations:PlaintextUser ──► POST /api/auth/login ──► Verify Credentials ──► Issue Signed JWT (JWT_SECRET_KEY)
🏢 8. Workspace IsolationStorage boundaries are strictly separated across two multi-tenant models:Personal Workspaces: Dedicated user storage with individual access controls.Organization Workspaces: Shared environments managed via Role-Based Access Controls (Owner, Admin, Member).✉️ 9. Workspace Invitation EngineAllows Organization Workspace admins to issue single-use or time-bound invitation tokens to onboard team members securely.🗑️ 10. Governed File DeletionDeletion strategy changes dynamically according to the workspace tier:Personal Workspace: Immediate file destruction upon owner confirmation.Organization Workspace: Multi-party quorum approvals with optional cool-down timers:Plaintext                                [ Delete Request ]
                                        │
                                        ▼
                            ┌───────────────────────┐
                            │ Multi-Party Approval  │
                            │   Quorum Threshold    │
                            └───────────┬───────────┘
                                        │
                       ┌────────────────┴────────────────┐
                       ▼                                 ▼
                  [ Rejected ]                      [ Approved ]
                       │                                 │
                       ▼                                 ▼
                  [ Cancelled ]                  [ Delay Timer ]
                                                         │
                                                         ▼
                                             [ Secure Erasure Engine ]
🧩 System ArchitecturePlaintext                         ┌─────────────────────────────┐
                         │      Client Interface       │
                         │     (Web Dashboard / API)   │
                         └──────────────┬──────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │       Flask REST API        │
                         └──────────────┬──────────────┘
                                        │
         ┌──────────────────────────────┼──────────────────────────────┐
         ▼                              ▼                              ▼
  Authentication                Workspace Routing                File Pipeline
  (JWT Middleware)             (RBAC / Boundaries)                     │
                                                                       │
                                        ┌──────────────────────────────┼──────────────────────────────┐
                                        ▼                              ▼                              ▼
                                [ Encryption Engine ]         [ Verification Engine ]       [ Deletion Governance ]
                                  (AES-256-GCM + Keys)             (SHA-256 Checksum)          (Quorum / Timers)
                                        │                              │                              │
                                        └──────────────────────────────┼──────────────────────────────┘
                                                                       │
                                                                       ▼
                                                       ┌──────────────────────────────┐
                                                       │    Secure Encrypted Store    │
                                                       └──────────────┬───────────────┘
                                                                      │
                                        ┌─────────────────────────────┼─────────────────────────────┐
                                        ▼                             ▼                             ▼
                                Linux WORM Control           Hash-Chained Audit          Key Registry Engine
                                 (chattr +i Flags)               (SHA-256)                 (Rotation / Rotation)
🗂️ Project StructurePlaintextsecure-file-system/
├── api/
│   ├── routes/
│   │   ├── auth.py                   # Authentication endpoints
│   │   ├── deletion_requests.py      # Governance & quorum approval endpoints
│   │   ├── files.py                  # File upload, verification, & download endpoints
│   │   ├── health.py                 # Service health monitoring
│   │   ├── pages.py                  # Dashboard & page routes
│   │   └── workspaces.py             # Workspace provisioning & member management
│   ├── services/
│   │   ├── auth_middleware.py        # Token validation & route protection
│   │   ├── auth_service.py           # Core user & session logic
│   │   ├── deletion_service.py       # Governance state machine & cleanup execution
│   │   ├── file_service.py           # File storage integration layer
│   │   ├── invitation_service.py     # Organization invite generation & verification
│   │   ├── token_service.py          # JWT creation & verification utilities
│   │   └── workspace_service.py      # Tenant isolation & membership policies
│   └── app.py                        # Flask application factory
│
├── crypto/
│   ├── audit.py                      # Hash-chained tamper-evident audit logger
│   ├── decrypt.py                    # AES-GCM streaming decryption core
│   ├── durability.py                 # Transactional commit-log helpers
│   ├── encrypt.py                    # AES-GCM streaming encryption core
│   ├── file_format.py                # Binary format specification & parsing
│   ├── file_state.py                 # File lifecycle state machine definitions
│   ├── hashing.py                    # Cryptographic hashing routines (SHA-256)
│   ├── integrity.py                  # System integrity validation routines
│   ├── key_manager.py                # Symmetric key generation & material storage
│   ├── key_registry.py               # Key state tracking & historical mapping
│   ├── key_rotation.py               # Key re-encryption & lifecycle migration
│   ├── recovery.py                   # Storage crash recovery worker
│   ├── secure_file.py                # High-level file management interface
│   ├── security_policy.py            # Password & policy enforcement engines
│   └── worm.py                       # Linux chattr/lsattr immutability interface
│
├── database/
│   ├── db.py                         # SQLAlchemy database initializers
│   └── models.py                     # Database schemas (Users, Files, Workspaces, Audit)
│
├── scripts/
│   ├── migrate_deletion_governance.py # Schema migration for governance rules
│   ├── migrate_workspace_audit.py    # Schema migration for workspace tracking
│   └── migrate_workspaces.py         # Schema migration for workspaces
│
├── static/                           # CSS stylesheets, UI assets, and client JS
├── templates/                        # Jinja2 layout templates (Dashboard, Auth, Views)
├── tests/                            # Pytest security, crypto, and unit test suite
├── .env.example                      # Template environment variable configurations
├── .gitignore                        # Git exclusion rules
├── main.py                           # Application launcher entry point
├── requirements.txt                  # Python dependencies
└── README.md                         # Documentation
🛠️ Technology StackCategoryTechnologyDescriptionLanguagePython 3.12Core programming language runtimeFrameworkFlask 3.xWeb API backend frameworkORMFlask-SQLAlchemyDatabase abstractions and relational mappingDatabaseSQLiteLocal metadata and relational database engineAuthenticationPyJWTJSON Web Token implementation for API securityCryptographyPyCryptodomeLow-level cryptographic primitives (AES-GCM, SHA-256)Storage SecurityLinux chattr / lsattrSystem file immutability flags (WORM)FrontendHTML5 / CSS3 / JavaScriptResponsive web administration client🚀 InstallationPrerequisitesPython 3.12+Linux Environment / WSL (Required for chattr WORM immutability enforcement)1. Clone RepositoryBashgit clone [https://github.com/Akshaycs012/secure-file-system.git](https://github.com/Akshaycs012/secure-file-system.git)
cd secure-file-system
2. Setup Virtual EnvironmentLinux / WSL:Bashpython3 -m venv .venv
source .venv/bin/activate
Windows (Development/Testing only):DOSpython -m venv .venv
.venv\Scripts\activate
3. Install DependenciesBashpip install -r requirements.txt
4. Configure Environment VariablesCopy the template configuration file to create your environment setup:Bashcp .env.example .env
Define a strong random key inside .env:Code snippetJWT_SECRET_KEY=e83b40f8981249ad8371c32f81a79240b9381fd56a9381c62
⚠️ Note: Never commit .env or files within keys/ to public version control repositories.▶️ Running the ApplicationLaunch the Flask development server:Bashpython main.py
The server will initialize and bind to:Plaintext[http://127.0.0.1:5000](http://127.0.0.1:5000)
Health Check EndpointConfirm operational readiness via curl or browser:Bashcurl [http://127.0.0.1:5000/api/health](http://127.0.0.1:5000/api/health)
Response:JSON{
  "service": "Secure File System API",
  "status": "ok"
}
🔌 API Reference OverviewAuthenticationHTTPPOST /api/auth/register                   # Register new user account
POST /api/auth/login                      # Authenticate & return JWT token
File OperationsHTTPPOST /api/files/upload                    # Stream-encrypt & upload new file
GET  /api/files                           # List files in accessible workspaces
GET  /api/files/<file_id>/verify          # Trigger SHA-256 integrity evaluation
GET  /api/files/<file_id>/download        # Decrypt & stream file payload
Workspaces & InvitationsHTTPGET  /api/workspaces                      # List user accessible workspaces
POST /api/workspaces/organization         # Create new Organization workspace
GET  /api/workspaces/<workspace_id>       # Fetch workspace details & members
POST /api/workspaces/<workspace_id>/invitations         # Issue member invite
POST /api/workspaces/invitations/<code_id>/accept        # Accept workspace invite
Deletion GovernanceHTTPPOST /api/deletion-requests/files/<file_id>  # Initiate governed deletion request
GET  /api/deletion-requests               # List pending approval requests
GET  /api/deletion-requests/<request_id>  # Fetch approval status details
POST /api/deletion-requests/<request_id>/approve  # Vote to approve deletion request
POST /api/deletion-requests/<request_id>/reject   # Vote to reject deletion request
POST /api/deletion-requests/<request_id>/execute  # Trigger final secure file removal
🧪 Testing SuiteThe repository includes test suites covering cryptography, recovery scenarios, security policies, and WORM mechanisms.Bash# Run all test modules
python -m pytest
Primary Coverage AreasCryptography: AES-256-GCM correctness, wrong-key failure modes, corrupted payload handling.Integrity: SHA-256 hash checks, file tampering detection, structure validation.Audit Engine: Hash-chain linkages, retrospective tampering detection.Key Manager: Lifecycle rotations, state transitions, key validation logic.Resilience: Power-loss/crash recovery simulation, transaction durability.WORM Storage: Linux immutability flag checks and permission controls.⚡ Performance BenchmarksThe system processes payload operations through a memory-bounded streaming pipeline, holding system memory overhead constant regardless of input file size.Average Local Pipeline ThroughputOperationPerformanceAES-256-GCM Encryption~255 MB/sAES-256-GCM Decryption~266 MB/sNote: Execution speed varies depending on underlying disk I/O, storage controller, hardware CPU capabilities, and current system workload.🔐 Security Design PrinciplesDefense in Depth: Security controls operate continuously across application layer, database schemas, cryptographic functions, and OS file flags.Principle of Least Privilege: System commands requiring administrative capabilities (chattr) operate via restricted helper tools; the web API process runs unprivileged.Secure Fail-Safe Defaults: Any signature failure, corrupt block, or tag mismatch during read operations forces immediate operation termination, returning failure status without releasing partial plaintext.Zero-Trust Storage: Payload files stored on disk are treated as untrusted blobs, protected entirely by key management structures and cryptographic checks.📊 Security Control MatrixSecurity GoalImplementation MechanismConfidentialityAES-256-GCM authenticated streaming encryptionAuthenticationSigned JWT bearer tokens with environment secret keysPayload IntegritySHA-256 digest + GCM 128-bit authentication tagsAudit IntegritySHA-256 cryptographically linked hash-chained log entriesImmutable StorageLinux chattr +i WORM extended filesystem protectionKey ManagementIsolated key registry supporting multi-phase lifecycle & rotationAccess ControlWorkspace-isolated authorization policies (RBAC)Deletion GovernanceMulti-party quorum approvals & execution delaysState ConsistencyCrash recovery routines with atomic transactional rollbacks🔮 Roadmap & Future Improvements[ ] Automated execution engine for scheduled deletion timers.[ ] Orphan file detection and automated storage cleanup routines.[ ] HTTPS / TLS default proxy layer integrations.[ ] Production Key Management Service (KMS/HSM) integration support.[ ] Rate limiting and request throttling middleware.[ ] CI/CD automated security pipeline integration (SAST/DAST scanning).⚠️ Production ConsiderationsThis repository is currently constructed as an academic and project-based security implementation. Before deploying into production environments:Provision dedicated production database instances (e.g., PostgreSQL).Integrate external key management infrastructure (AWS KMS, HashiCorp Vault).Enforce strict TLS/HTTPS proxy termination via Nginx or Caddy.Implement rate limiting (e.g., Redis-backed Flask-Limiter).Complete comprehensive security review and third-party penetration testing.👨‍💻 AuthorAkshayComputer Science & Engineering StudentFocused on Backend Engineering, Applied Cryptography, and Secure Distributed Systems.GitHub: @Akshaycs012
