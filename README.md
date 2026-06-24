# HAProxy OpenManager

Modern, web-based management interface for HAProxy load balancers with multi-cluster support, agent-based pull architecture, and automated deployment capabilities.

![HAProxy OpenManager Showcase](docs/screenshots/haproxy-openmanager-showcase.gif)

## Table of Contents

1. [Project Overview](#project-overview)
   - [Agent Pull Architecture](#agent-pull-architecture)
   - [Features at a Glance](#features-at-a-glance)
2. [Screenshots](#screenshots)
   - [Multi-Cluster & Agent Setup](#multi-cluster--agent-setup)
   - [Dashboard - Real-time Monitoring](#dashboard---real-time-monitoring)
   - [HAProxy Configuration](#haproxy-configuration)
   - [Configuration Import & Viewer](#configuration-import--viewer)
   - [Apply Management & Version Control](#apply-management--version-control)
   - [Security & Certificate Management](#security--certificate-management)
   - [ACME Automation](#acme-automation---automated-ssl-certificates)
   - [Site Wizard - Guided Multi-Step Host Setup](#site-wizard---guided-multi-step-host-setup)
   - [WAF Management](#waf-management)
   - [IP Inventory](#ip-inventory---cross-cluster-ip-search)
3. [Key Capabilities](#key-capabilities)
   - [Configuration & Entity Management](#configuration--entity-management)
   - [Agent & Cluster Management](#agent--cluster-management)
   - [Version Control & Change Management](#version-control--change-management)
   - [Monitoring & Security](#monitoring--security)
   - [ACME Auto SSL / Let's Encrypt](#acme-auto-ssl--lets-encrypt)
   - [Integration & API](#integration--api)
4. [Architecture](#architecture)
   - [System Architecture with Agent Pull Model](#system-architecture-with-agent-pull-model)
   - [Component Details](#component-details)
   - [Agent Pull Communication Flow](#agent-pull-communication-flow---detailed-entity-management)
5. [Features & User Interface](#features--user-interface)
   - [Pool Management](#pool-management---agent-pool-organization)
   - [Cluster Management](#cluster-management---multi-cluster-haproxy-administration)
   - [Agent Management](#agent-management---haproxy-agent-deployment--monitoring)
   - [Dashboard](#dashboard---main-overview--real-time-monitoring)
   - [Frontend Management](#frontend-management---virtual-host--routing-configuration)
   - [New Site Wizard](#new-site-wizard---guided-multi-step-host-setup)
   - [Backend Servers](#backend-servers---server-pool-management)
   - [Configuration](#configuration---haproxy-config-file-management)
   - [Apply Management](#apply-management---change-tracking--deployment)
   - [SSL Certificates](#ssl-certificates---centralized-tlsssl-certificate-management)
   - [ACME Auto SSL](#acme-auto-ssl---automated-certificate-management)
   - [WAF Management](#waf-management---web-application-firewall)
   - [IP Inventory](#ip-inventory---cross-cluster-ip-search--discovery)
   - [HA / VIP Management](#ha--vip-management---keepalived-virtual-ip-failover)
   - [User Management](#user-management---access-control--authentication)
   - [Settings](#settings---system-configuration)
6. [Getting Started - First-Time Usage](#getting-started---first-time-usage)
7. [Installation](#installation)
   - [Docker Installation](#docker-installation)
   - [Kubernetes/OpenShift Installation](#kubernetesopenshift-installation)
   - [Standalone Installation](docs/STANDALONE_INSTALL.md)
   - [Local Development](#local-development)
8. [Configuration](#configuration)
9. [API Reference](#api-reference)
10. [Development](#development)
11. [Troubleshooting](#troubleshooting)
12. [Contributing](#contributing)
13. [Use Cases](#use-cases)
14. [License](#license)
15. [Author](#author)
16. [Support](#support)

## Project Overview

HAProxy OpenManager is a comprehensive management platform designed to simplify HAProxy administration across multiple environments. It provides a unified interface for managing remote HAProxy instances through an agent-based pull architecture, supporting multi-cluster configurations with centralized control.

### Agent Pull Architecture

This project implements an **agent pull architecture** where management operations are executed through a lightweight agent service (`haproxy-agent`) installed on each target HAProxy server:

#### Conceptual Hierarchy
```
Pool (Logical Grouping)
  └── Cluster (HAProxy Cluster Definition)
       └── Agent 1 → HAProxy Server 1
       └── Agent 2 → HAProxy Server 2
       └── Agent 3 → HAProxy Server 3
```

#### Setup Flow
1. **Create Agent Pool**: First, create a pool to logically group agents (e.g., "Production Pool")
2. **Create Cluster**: Select the pool and create a cluster (e.g., "Production Cluster with 3 nodes")
3. **Deploy Agents**: Generate installation scripts for each HAProxy server, selecting the same pool
4. **Result**: Multiple agents in one pool, all managing one cluster

#### How It Works
1. **Automatic Polling**: Agents periodically poll the backend for configuration tasks (every 30 seconds)
2. **Local Execution**: Agents apply changes to local `haproxy.cfg` and reload HAProxy service
3. **No Direct Push**: Backend never directly pushes changes - agents pull on their schedule
4. **Unified Management**: All agents in a pool receive same cluster configuration

This architecture provides better security (no inbound connections to HAProxy servers), resilience (agents can retry on failure), and scalability (backend doesn't track agent state).

### Features at a Glance

✅ **Agent-Based Pull Architecture** - Secure, scalable management without inbound connections  
✅ **Multi-Cluster & Pool Management** - Organize and manage multiple HAProxy clusters from one interface  
✅ **Frontend/Backend/Server CRUD** - Complete entity management with visual UI  
✅ **New Site Wizard** - Step-by-step guided setup for a complete proxied host (frontend + backend + servers + SSL/ACME) in one consolidated atomic apply  
✅ **Bulk Config Import** - Import existing `haproxy.cfg` files with smart SSL auto-assignment  
✅ **Version Control & Rollback** - Every change versioned with one-click restore capability  
✅ **Real-Time Monitoring** - Live stats, health checks, and performance dashboards  
✅ **SSL Certificate Management** - Centralized SSL with expiration tracking  
✅ **ACME Auto SSL (Let's Encrypt)** - Automated certificate issuance, renewal, and deployment via ACME protocol  
✅ **ACME DNS-01 Challenge** *(v1.8.0)* - TXT-record validation for internal/isolated clusters (no public port 80) and wildcard certificates; pluggable DNS providers (Manual + Cloudflare), opt-in, HTTP-01 unchanged  
✅ **ACME Certificate Diagnostic Panel** - Automated preflight that checks agent readiness, DNS resolution, port 80 reachability, and ACME challenge ACL before issuing certificates  
✅ **WAF Rules** - Web Application Firewall management and deployment  
✅ **Agent Script Versioning** - Update agents via UI (Monaco editor) with auto-upgrade  
✅ **Token-Based Agent Auth** - Secure token management with revoke/renew  
✅ **IP Inventory** - Cross-cluster IP search to identify agents, VIPs, and backend servers by IP  
✅ **HA / VIP (Keepalived) Management** - Create virtual IPs from the UI; the agent installs & configures Keepalived (unicast VRRP) with a HAProxy health-check so the VIP fails over automatically; live MASTER/BACKUP detection per node  
✅ **Role-Based User Management** - Admin and user roles with granular permissions and access control  
✅ **User Activity Audit Logs** - Complete audit trail of all system events  
✅ **REST API** - Full programmatic access for automation and CI/CD integration


## Screenshots


### Multi-Cluster & Agent Setup

**Multi-Cluster Management** - Cluster selector dropdown showing multiple clusters with agent pools and online agent counts - switch between different clusters
![Multi-Cluster Management - Cluster Selector](docs/screenshots/cluster-selector.png)

**Agent Management** - Agent setup wizard with platform selection (Linux/macOS) and architecture (x86_64/ARM64)
![Agent Management - Setup Wizard](docs/screenshots/agent-setup.png)

**Agent Management** - Generated installation script ready for deployment to target servers
![Agent Management - Script Generation](docs/screenshots/agent-script.png)

### Dashboard - Real-time Monitoring

**Dashboard** - Overview tab showing system metrics, active servers, SSL certificates, and cluster agent health
![Dashboard - Overview](docs/screenshots/dashboard-overview.png)

**Dashboard** - Performance Trends with request rate and response time heatmap (24h view)
![Dashboard - Performance Trends](docs/screenshots/performance-trends.png)

**Dashboard** - Health Matrix showing backend servers with detailed health check status and response times
![Dashboard - Health Matrix](docs/screenshots/health-matrix.png)

**Dashboard** - Response Time Heatmap (24h) with color-coded latency visualization per backend
![Dashboard - Response Time Heatmap](docs/screenshots/response-time-heatmap.png)

### HAProxy Configuration

**Frontend Management** - List view with SSL/TLS bindings, sync status, and config status
![Frontend Management - List View](docs/screenshots/frontend-management.png)

**Frontend Management** - Edit modal for configuring bind address, protocol mode, default backend, SSL/TLS, ACLs, and advanced options
![Frontend Management - Edit Modal](docs/screenshots/frontend-edit.png)

**Backend Configuration** - Backend server and pool configuration page
![Backend Configuration](docs/screenshots/backend-configuration.png)

**Backend Management** - Backends & Servers tab with 165 servers across 56 backends, health status overview
![Backend Management - Backends & Servers](docs/screenshots/backends-servers.png)

### Configuration Import & Viewer

**Bulk Config Import** - Paste existing haproxy.cfg and parse configuration
![Bulk Config Import - Input](docs/screenshots/bulk-import.png)

**Bulk Config Import** - Parsed entities showing 56 frontends, 55 backends, 165 servers with SSL and configuration recommendations
![Bulk Config Import - Results](docs/screenshots/bulk-import-parsed.png)

**Configuration Viewer** - Real-time configuration viewer to pull haproxy.cfg from live agents
![Configuration Viewer](docs/screenshots/config-view.png)

### Apply Management & Version Control

**Apply Management** - Pending changes and deployment history with version tracking
![Apply Management](docs/screenshots/apply-management.png)

**Version History** - Configuration diff viewer showing added/removed lines with summary
![Version History - Diff Viewer](docs/screenshots/version-diff.png)

**Version History** - Complete version history with restore capabilities and deployment status
![Version History - Timeline](docs/screenshots/version-history.png)

### Security & Certificate Management

**Security Management** - Agent API token management with active tokens, expiration tracking, and revoke capabilities
![Security Management - API Tokens](docs/screenshots/security-token-management.png)

### ACME Automation - Automated SSL Certificates

**ACME Automation** - Setup guide with prerequisites checklist, certificate statistics, and order management
![ACME Automation - Setup Guide](docs/screenshots/acme-setup-guide.png)

**ACME Automation** - Active certificate orders with PENDING status tracking and renewal schedule
![ACME Automation - Certificate Orders](docs/screenshots/acme-certificate-orders.png)

**ACME Settings** - ACME/SSL Automation configuration with provider selection, staging mode, and auto-renewal settings
![ACME Settings](docs/screenshots/acme-settings.png)

### Site Wizard - Guided Multi-Step Host Setup

**New Site Wizard** - Multi-step guided form for creating a complete proxied host (domains + backend pool + servers + frontend + SSL/ACME) with live HAProxy config validation and atomic apply
![New Site Wizard](docs/screenshots/site-wizard.png)

### WAF Management

**WAF Management** - WAF rule configuration with request filtering, rate limiting, and advanced options
![WAF Management](docs/screenshots/waf-management.png)

### IP Inventory - Cross-Cluster IP Search

**IP Inventory** - Unified view of all IPs across clusters with search capability to identify which cluster, agent, or backend server an IP belongs to
![IP Inventory](docs/screenshots/ip-inventory.png)

## Key Capabilities

#### Configuration & Entity Management
- **Frontend Management**: Create, edit, update, and delete frontend configurations with SSL bindings, ACL rules, and routing
- **Backend Management**: Full CRUD operations for backend pools with load balancing algorithms and health checks
- **Server Management**: Add, update, remove, and configure backend servers with weights, maintenance mode, and connection limits
- **Bulk Configuration Import**: Import existing `haproxy.cfg` files to instantly manage all frontends, backends, and servers without manual recreation
  - **Smart SSL Auto-Assignment**: Automatically matches and assigns SSL certificates during bulk import if they exist in SSL Management with matching names and SYNCED status - eliminates manual SSL configuration after import
- **Configuration Synchronization**: All entities (backends, frontends, servers, SSL certificates, WAF rules) auto-sync to agents
- **Configuration Viewer**: View live HAProxy configuration pulled from agents via Configuration Management page

#### Agent & Cluster Management
- **Agent-Based Management**: Lightweight agent service for secure, pull-based HAProxy management
- **Pool Management**: Organize agents into logical pools for better cluster organization
- **Multi-Cluster Support**: Manage multiple HAProxy clusters from a single interface with cluster selector
- **Agent Token Management**: Secure token-based agent installation with token revoke and renew capabilities
- **Agent Script Editor**: Monaco code editor for updating agent scripts via UI (not binary) - create new versions, rollback, and auto-upgrade all agents
- **Platform-Specific Scripts**: Auto-generated installation scripts for Linux and macOS (x86_64/ARM64)
- **HA / VIP (Keepalived) Management**: Create a virtual IP from the UI and the agents install & configure Keepalived (VRRP) with a HAProxy health-check so the VIP fails over automatically when HAProxy drops — opt-in, with live MASTER/BACKUP per node, multi-distro install, cluster-driven config path, and Apply/Reject staging

#### Version Control & Change Management
- **Apply Management**: Centralized change tracking and deployment status monitoring across all agents
- **Version Control**: Every configuration change creates a versioned snapshot with complete history
- **Configuration Restore**: Restore any previous configuration version with one-click rollback capability
- **Diff Visualization**: See exactly what changed between versions with line-by-line comparison
- **Change Tracking**: Track who made changes, when, and what entities were affected

#### Monitoring & Security
- **Real-time Monitoring**: Live statistics, health checks, and performance metrics from HAProxy stats socket
- **SSL Management**: Centralized certificate management with expiration tracking and zero-downtime updates
- **WAF Rules**: Web Application Firewall rule management and deployment for security protection
- **User Management**: Role-based access control with admin and user roles
- **User Activity Logs**: Complete audit trail of all user actions, configuration changes, and system events

#### ACME Auto SSL / Let's Encrypt
- **Automated Certificate Issuance**: Request SSL certificates from Let's Encrypt or any ACME-compatible CA directly from the UI
- **Automatic Renewal**: Hourly background task monitors certificate expiry and creates renewal orders before expiration
- **Auto-Completion of Validated Orders** *(v1.4.0)*: Independent 60-second background task drives CA-validated orders through finalize -> download -> save without requiring user intervention; multi-replica safe via PostgreSQL `FOR UPDATE SKIP LOCKED` atomic claim, plus per-order session-level `pg_advisory_lock` to serialize concurrent completion attempts (UI "Complete" + auto-task race protection)
- **Zero-Touch Deployment**: Renewed certificates are automatically applied through the same PENDING -> APPLIED pipeline as manual SSL updates, with agent notification
- **Stuck Order Detection** *(v1.4.0)*: Setup wizard surfaces orders that the CA has validated but not yet downloaded, with one-click `Complete` action and automatic 60-second retry
- **Multi-Provider Support**: Configurable ACME directory URL supports Let's Encrypt, ZeroSSL, Google Trust Services, Buypass, and custom CAs
- **HTTP-01 Challenge**: Built-in challenge responder with automatic HAProxy routing injection; reserved backend name `_acme_challenge_backend` is auto-managed and protected from manual edits / agent sync collisions
- **DNS-01 Challenge** *(v1.8.0 — Issue #35)*: Validate via a DNS TXT record instead of HTTP on port 80, for **internal/isolated clusters with no public ingress** and for **wildcard** certificates (`*.example.com`). Pluggable per-account DNS provider (Manual + Cloudflare to start; credentials encrypted at rest and verified on save), same PENDING → APPLIED pipeline, bounded automatic retry on propagation lag, and a DNS-01 event timeline. Opt-in via a global setting; HTTP-01 behaviour is unchanged. (See the *DNS-01 Challenge* subsection under ACME Auto SSL below.)
- **ACME Account Management**: Register, view, and deactivate ACME accounts from the UI
- **Staging Mode**: Test certificate issuance with Let's Encrypt staging environment before production
- **Custom Staging Endpoint** *(v1.4.0)*: Optional `staging_url_override` setting lets you point staging mode at a private ACME test CA (e.g. Pebble) without touching the production directory URL
- **External Account Binding (EAB)**: Support for CAs that require EAB (ZeroSSL, Google Trust Services). Enter the EAB Key ID and HMAC Key globally in Settings, or per-account in the Register Account dialog (a per-account value overrides the global setting; leave it blank to use the global one)
- **Structured Error Diagnostics** *(v1.4.0)*: All ACME failures (challenge, finalize, download) persist structured JSON to `letsencrypt_orders.error_detail` for clear post-mortem analysis
- **Audit Logging** *(v1.4.0)*: Every ACME operation (request, revoke, CA-chain import, account ops) is captured in `user_activity_logs` for compliance review
- **ACME Diagnostic Panel** *(v1.5.0 — Issue #13)*: Live pre-flight + post-failure diagnostics (DNS / port-80 / routing / account / agents) and merged event timeline (`acme_order_events` + correlated `user_activity_logs`) accessible from the ACME Automation page; humanized error rendering for 11+ RFC8555 problem types with backwards-compatible fallback for legacy plain-string `error_detail`; per-user 5/min rate-limit
- **New Site Setup Wizard** *(v1.5.0 — Issue #14)*: Single guided flow that creates a Backend + Servers + HTTP Frontend (and optional HTTPS Frontend with chosen SSL mode: ACME / Upload / Existing / None) in one atomic transaction, with diff preview, draft persistence (PEM stripped), and ACME-staged order completion gated by agent confirmation. Per-mode reject path cleanly rolls back including any wizard-staged ACME orders.
- **Backward Compatible**: ACME-managed and manually uploaded certificates coexist seamlessly; existing SSL workflows are completely unaffected

#### Integration & API
- **REST API**: Complete API for programmatic access and integration with CI/CD pipelines
- **Agent Pull Architecture**: Secure polling model - no inbound connections required to HAProxy servers
- **Redis Cache**: High-performance metrics caching for dashboard with configurable retention


## Architecture

### System Architecture with Agent Pull Model

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'fontSize':'16px'}}}%%
graph TB
    subgraph UI_LAYER["🌐 User Interface Layer"]
        USER["👤 Admin/User"] --> WEB["React UI<br/>Nginx Proxy<br/>:8080"]
    end
    
    subgraph BACKEND_LAYER["⚙️ Backend Layer"]
        WEB <--> API["FastAPI<br/>Backend<br/>:8000"]
        API <--> DB[("PostgreSQL<br/>Configs & History")]
        API <--> CACHE[("Redis<br/>Metrics Cache")]
    end
    
    subgraph AGENT_LAYER["📦 Agent Pool: Production Cluster"]
        direction LR
        
        AGENT1["🤖 Agent 1<br/>10.0.1.101<br/>(Poll Every 30s)"]
        AGENT2["🤖 Agent 2<br/>10.0.1.102<br/>(Poll Every 30s)"]
        AGENT3["🤖 Agent 3<br/>10.0.1.103<br/>(Poll Every 30s)"]
        
        HAP1["⚡ HAProxy<br/>+ Stats Socket<br/>+ haproxy.cfg"]
        HAP2["⚡ HAProxy<br/>+ Stats Socket<br/>+ haproxy.cfg"]
        HAP3["⚡ HAProxy<br/>+ Stats Socket<br/>+ haproxy.cfg"]
        
        AGENT1 --> HAP1
        AGENT2 --> HAP2
        AGENT3 --> HAP3
    end
    
    API <-.->|"🔄 Pull Config<br/>📤 Push Stats<br/>⬇️ SSL/WAF"| AGENT1
    API <-.->|"🔄 Pull Config<br/>📤 Push Stats<br/>⬇️ SSL/WAF"| AGENT2
    API <-.->|"🔄 Pull Config<br/>📤 Push Stats<br/>⬇️ SSL/WAF"| AGENT3
    
    classDef uiStyle fill:#3a5a8a,stroke:#6a9eff,stroke-width:3px,color:#fff
    classDef backendStyle fill:#5a3a8a,stroke:#b39ddb,stroke-width:2px,color:#fff
    classDef dbStyle fill:#3a6a3a,stroke:#66bb6a,stroke-width:2px,color:#fff
    classDef agentStyle fill:#8a6a30,stroke:#ffb347,stroke-width:2px,color:#fff
    classDef haproxyStyle fill:#2a6a5a,stroke:#4db6ac,stroke-width:3px,color:#fff
    
    class USER,WEB uiStyle
    class API backendStyle
    class DB,CACHE dbStyle
    class AGENT1,AGENT2,AGENT3 agentStyle
    class HAP1,HAP2,HAP3 haproxyStyle
```

### Component Details

| Component | Technology | Purpose | Port |
|-----------|------------|---------|------|
| **Frontend** | React.js 18 + Ant Design | Web interface, dashboards, configuration UI | 3000 |
| **Backend** | FastAPI + Python | REST API, task queue, agent coordination | 8000 |
| **Database** | PostgreSQL 15 | Configuration storage, user management, agent tasks | 5432 |
| **Cache** | Redis 7 | Session storage, performance metrics caching | 6379 |
| **Reverse Proxy** | Nginx | Frontend/backend routing, SSL termination, ACME challenge routing | 8080 |
| **HAProxy Agent** | Bash Service | Polls backend, applies configs, manages HAProxy | N/A |
| **HAProxy Instances** | HAProxy 2.8+ | Load balancer instances being managed by agents | 8404+ |
| **ACME Service** | Built-in (Python) | ACME protocol client for automated certificate management | - |

### Agent Pull Communication Flow - Detailed Entity Management

This detailed sequence diagram shows the complete lifecycle of configuration management, including entity creation, agent polling, configuration application, SSL management, WAF rules, and agent upgrade process.

```mermaid
sequenceDiagram
    autonumber
    participant U as 👤 User Browser
    participant B as ⚙️ Backend API
    participant D as 💿 PostgreSQL DB
    participant R as 💾 Redis Cache
    participant A as 🤖 Agent
    participant CFG as 📄 haproxy.cfg
    participant H as ⚡ HAProxy Service
    participant S as 🔌 Stats Socket

    Note over U,B: ═══ PHASE 1: USER CREATES ENTITIES ═══
    
    U->>B: Create Backend "api-backend"
    B->>D: INSERT backends + servers
    B->>D: CREATE version v1.0.124
    B-->>U: ✅ Backend Created
    
    U->>B: Create Frontend "web-frontend"
    B->>D: INSERT frontend + SSL binding
    B->>D: UPDATE version v1.0.125
    B-->>U: ✅ Frontend Created
    
    U->>B: Upload SSL Certificate
    B->>D: INSERT ssl_certificates (global)
    B-->>U: ✅ SSL Ready for all clusters
    
    U->>B: Create WAF Rule
    B->>D: INSERT waf_rules (rate limit)
    B-->>U: ✅ WAF Rule Created
    
    U->>B: 🚀 Click "Apply Changes"
    B->>D: Mark tasks READY_FOR_DEPLOYMENT
    B-->>U: ✅ Queued for deployment

    Note over A,R: ═══ PHASE 2: AGENT POLLING CYCLE (30s) ═══
    
    loop Every 30 seconds
        A->>B: GET /api/agent/tasks
        B->>D: Query pending tasks
        B-->>A: Tasks + Version v1.0.125
        
        A->>S: socat show stat
        S-->>A: CSV Stats
        A->>B: POST /api/stats/upload
        B->>R: Store metrics (5min TTL)
        
        A->>B: Check agent version
        B->>D: SELECT latest_agent_version
        B-->>A: Current: 1.0.10, Latest: 1.0.11
    end

    Note over A,CFG: ═══ PHASE 3: AGENT APPLIES CONFIG ═══
    
    A->>A: Parse task bundle
    A->>A: Generate backend config
    A->>A: Generate frontend config
    
    A->>B: Download SSL certificate
    B-->>A: PEM file (encrypted)
    A->>A: Write /etc/haproxy/certs/*.pem
    A->>A: chmod 600 (secure)
    
    A->>A: Generate WAF stick-table
    
    A->>CFG: Backup haproxy.cfg
    A->>CFG: Write new configuration
    A->>H: haproxy -c -f haproxy.cfg
    
    alt Config Valid
        A->>H: systemctl reload haproxy
        H-->>A: ✅ Reload successful
        A->>CFG: Keep new config
    else Config Invalid
        A->>CFG: Restore backup
        A->>A: ❌ Rollback complete
    end

    Note over A,B: ═══ PHASE 4: AGENT REPORTS STATUS ═══
    
    A->>B: POST /api/agent/tasks/complete
    B->>D: UPDATE task status = COMPLETED
    B->>D: INSERT activity_logs (JSON)
    B-->>A: ✅ Acknowledged

    Note over U,B: ═══ PHASE 5: USER MONITORS STATUS ═══
    
    U->>B: GET /api/apply-changes/status
    B->>D: Query all agent statuses
    B-->>U: 3/3 agents ✅ v1.0.125

    Note over U,R: ═══ PHASE 6: DASHBOARD METRICS ═══
    
    U->>B: GET /api/dashboard/stats
    B->>R: GET haproxy:cluster:5:stats
    R-->>B: Latest metrics (30s fresh)
    B-->>U: Real-time dashboard data

    Note over A,B: ═══ PHASE 7: AGENT AUTO-UPGRADE ═══
    
    A->>B: Check version (in polling)
    B-->>A: New version 1.0.11 available
    
    A->>B: GET /api/agent/download/1.0.11
    B->>D: SELECT agent_script WHERE version=1.0.11
    B-->>A: Download script (bash/python)
    
    A->>A: Write new script to /tmp/agent-upgrade.sh
    A->>A: chmod +x agent-upgrade.sh
    A->>A: Execute: /tmp/agent-upgrade.sh
    
    Note over A: Agent Self-Upgrade Process
    A->>A: Stop current agent service
    A->>A: Backup old agent binary
    A->>A: Install new agent version
    A->>A: Update systemd service
    A->>A: Start agent with new version
    
    A->>B: POST /api/agent/upgrade/complete
    B->>D: UPDATE agent version = 1.0.11
    B->>D: LOG upgrade activity
    B-->>A: ✅ Upgrade confirmed
    
    A->>CFG: Read haproxy.cfg (verify integrity)
    A->>H: Check HAProxy service status
    H-->>A: Service running normally
    
    Note over A,B: Agent now running v1.0.11<br/>Continues normal polling cycle

    Note over B,D: ═══ PHASE 8: ACME AUTO-RENEWAL (Hourly) ═══

    B->>D: Query expiring ACME certs (within N days)
    D-->>B: Cert "example.com" expires in 25 days

    B->>B: Create ACME renewal order
    B->>B: Respond to HTTP-01 challenges
    
    Note over B: Next cycle: poll order status
    B->>B: Order valid - download certificate
    B->>D: Update cert content (PENDING)
    B->>D: Create config versions (PENDING)
    B->>D: Auto-apply: apply_ssl_related_configs()
    B->>D: Create consolidated version (APPLIED)
    B->>R: Notify agents via Redis
    
    A->>B: Poll detects new config version
    A->>B: Download renewed certificate
    A->>A: Write updated cert to disk
    A->>H: Reload HAProxy (zero downtime)
    A->>B: Report success
```

**Key Flow Features:**
- 🔄 **Continuous Polling**: Agents poll every 30s for tasks, stats collection, and version checks
- 📄 **Config Management**: haproxy.cfg backup → validate → apply → rollback if needed
- 🔐 **SSL Handling**: Secure download, file permissions (chmod 600), automatic frontend binding
- 🤖 **ACME Auto-Renewal**: Automatic certificate renewal via ACME protocol with same Apply pipeline as manual SSL
- 🛡️ **WAF Integration**: Stick-tables generated and integrated into config
- 📊 **Stats Collection**: Parallel stats upload using socat + stats socket
- 🔄 **Auto-Upgrade**: Agents detect new versions and self-upgrade with zero-touch deployment
- ✅ **Validation**: Every config change is validated before HAProxy reload
- 📝 **Activity Logging**: All operations logged in JSON format for audit trail


## Features & User Interface

### Pool Management - Agent Pool Organization
- **Pool Creation**: Create logical pools to group HAProxy agents
- **Pool Assignment**: Associate clusters with specific pools
- **Pool Overview**: View all agents within a pool
- **Multi-Pool Support**: Manage multiple pools for different environments (prod, staging, etc.)
- **Pool-based Filtering**: Filter agents and clusters by pool

### Cluster Management - Multi-Cluster HAProxy Administration
- **Cluster Selector**: Top navigation cluster selector for context switching
- **Cluster Creation**: Define clusters and associate with agent pools
- **Cluster Status**: Monitor cluster health and connectivity
- **Default Cluster**: Set preferred default cluster
- **Cross-Cluster View**: Compare metrics across multiple clusters
- **Cluster-Scoped Operations**: All configurations are cluster-specific

### Agent Management - HAProxy Agent Deployment & Monitoring

#### Agent Script Management
Agent scripts are **not hardcoded** in the project. They are stored in the database and can be updated via the UI:

- **Script Editor**: Edit agent installation scripts directly in the UI
- **Platform Support**: Separate scripts for Linux and macOS (x86_64/ARM64)
- **Version Control**: Create new agent versions with changelog
- **Automatic Upgrade**: Deploy new agent versions to all agents with one click
- **Upgrade Process**: Agents check backend version → Download new script → Self-upgrade → Restart

**Agent Version Update Flow:**

```mermaid
%%{init: {'theme':'base', 'themeVariables': { 'fontSize':'14px'}}}%%
graph LR
    subgraph USER["👤 User Actions"]
        A["Edit Script<br/>+ Create v1.0.5"] --> B["Mark as<br/>Latest"]
    end
    
    subgraph AUTO["🤖 Automatic Process"]
        C["Agents Poll"] --> D["Detect New<br/>Version"] --> E["Download"] --> F["Self-Upgrade"] --> G["✅ Running<br/>v1.0.5"]
    end
    
    B -.->|Trigger| C
    
    style USER fill:#2a4a6a,stroke:#4a9eff,stroke-width:2px,color:#fff
    style AUTO fill:#3a5a3a,stroke:#66bb6a,stroke-width:2px,color:#fff
    style A fill:#3a5a8a,stroke:#6a9eff,stroke-width:2px,color:#fff
    style B fill:#3a5a8a,stroke:#6a9eff,stroke-width:2px,color:#fff
    style C fill:#4a6a4a,stroke:#66bb6a,stroke-width:2px,color:#fff
    style D fill:#4a6a4a,stroke:#66bb6a,stroke-width:2px,color:#fff
    style E fill:#4a6a4a,stroke:#66bb6a,stroke-width:2px,color:#fff
    style F fill:#4a6a4a,stroke:#66bb6a,stroke-width:2px,color:#fff
    style G fill:#2a5a2a,stroke:#66bb6a,stroke-width:3px,color:#fff
```

#### Agent Operations
- **Agent Registration**: Automatic agent registration after installation
- **Installation Scripts**: Generate platform-specific scripts (Linux/macOS ARM/x86)
- **Script Download**: One-click download of customized installation scripts
- **Agent Status**: Real-time agent connectivity and health monitoring
- **Platform Detection**: Automatic detection of OS and architecture
- **Last Seen**: Track when agents last connected to backend (updated every 30s)
- **Batch Operations**: Upgrade multiple agents simultaneously

#### Agent Logs & Monitoring
- **Log Location**: `/var/log/haproxy-agent/agent.log` on each agent server
- **Log Format**: Structured JSON for easy parsing and log aggregation
- **Log Fields**: timestamp, level, message, agent_id, cluster_id, task_id
- **Activity Tracking**: All agent activities (config updates, SSL changes, task execution)
- **Log Integration**: JSON format allows easy integration with ELK, Splunk, Datadog
- **Log Rotation**: Automatic rotation with configurable retention

**Example Log Entry (JSON):**
```json
{
  "timestamp": "2025-01-15T10:30:45Z",
  "level": "INFO",
  "agent_id": "prod-haproxy-01",
  "cluster_id": 5,
  "task_id": 123,
  "message": "SSL certificate updated successfully",
  "details": {
    "cert_name": "wildcard.example.com",
    "action": "update",
    "haproxy_reload": "success"
  }
}
```

### Dashboard - Main Overview & Real-time Monitoring

The dashboard displays comprehensive real-time metrics collected by agents from HAProxy stats socket. Agents use `socat` to query the stats socket every 30 seconds and send CSV data to the backend, which parses and stores it in Redis for high-performance access.

**Tab-Based Navigation:**

1. **Overview Tab**: 
   - System-wide metrics: Total requests, active sessions, error rate
   - Frontend/Backend/Server counts
   - SSL certificate status and expiration warnings
   - Quick health status indicators

2. **Frontends Tab**:
   - Request rate per frontend with sparkline charts
   - Session distribution across frontends
   - Status (UP/DOWN) monitoring
   - Filter by specific frontends

3. **Backends Tab**:
   - Backend health matrix (all servers at a glance)
   - Request distribution percentages
   - Response time averages
   - Active/backup server status

4. **Performance Trends Tab**:
   - Response time trends (1h, 6h, 24h, 7d, 30d views)
   - Request rate trends with interactive zoom
   - Error rate analysis over time
   - Session trends and capacity planning

5. **Capacity & Load Tab**:
   - Current vs max connections
   - Queue depth monitoring
   - CPU/Memory utilization (if available)
   - Load distribution heatmaps

6. **Health Matrix Tab**:
   - Detailed server health status
   - Last status check timestamps
   - Check duration and latency
   - Failure reasons and diagnostics

**Data Collection Flow:**
- Agents → Stats Socket (`show stat`) → CSV → Backend API → Redis → Dashboard UI
- **Agent Log Path**: `/var/log/haproxy-agent/agent.log` (JSON format for easy log aggregation)
- **Update Interval**: 30 seconds (configurable)
- **Data Retention**: 30 days in Redis (configurable)

### Frontend Management - Virtual Host & Routing Configuration
- **Frontend CRUD**: Create, edit, delete, and duplicate frontend configurations
- **Protocol Support**: HTTP, TCP, and health check mode configurations
- **Binding Configuration**: IP address, port, and SSL binding options
- **Backend Assignment**: Default backend selection and routing rules
- **SSL Configuration**: Certificate assignment and SSL protocol settings
- **ACL Rules**: Access control rules with pattern matching
- **Redirect Rules**: HTTP to HTTPS redirects and custom redirections
- **Advanced Options**: Connection limits, timeouts, and performance tuning
- **Search & Filter**: Real-time search and status-based filtering

### New Site Wizard - Guided Multi-Step Host Setup

The New Site Wizard is the recommended entry point for creating a complete proxied host. It collects every piece of configuration a host needs across a five-step guided form and creates the matching frontend + backend + servers + SSL binding as a single atomic apply.

- **5-step guided flow**:
  1. **Domains** - host header / SNI / wildcard validation, IDN/Punycode normalization, port + bind-address collision check
  2. **Backend** - pool name, load-balance algorithm, health check method/URI, cookie-based persistence (RFC 6265 and HAProxy-parser-safe character validation)
  3. **Servers** - per-server address/port/weight, optional CA bundle reference (cluster-RBAC enforced), backup-server + cookie-value validators
  4. **SSL** - three modes: existing certificate (cluster-RBAC), PEM upload (chain validation + SAN/CN match), or ACME order (account binding + preflight)
  5. **Review + Dry-Run** - live `POST /api/sites/preview` runs the proposed config through `haproxy -c` and surfaces every WARNING/ERROR with a marker comment that pinpoints the offending block before anything touches the database
- **Draft persistence**: every step auto-saves to a server-side draft (30-day TTL, 50 drafts per user cap, cluster-scoped, PEM material stripped at rest)
- **Resume across sessions**: drafts can be reopened from a different browser; cluster swap mid-wizard surfaces a confirmation prompt to prevent cross-cluster contamination
- **Atomic apply**: frontend + backend + servers + SSL binding land as a single PENDING change reviewable from Apply Management - accept and apply, or reject as a whole
- **Cluster RBAC**: every step honours `user_pool_access` and cluster RBAC; SSL certificate references are validated against the target cluster at both preview AND create time
- **Hardening**: IDN/Punycode safe slug generation, cookie/header injection guards, path-traversal protection on SSL filenames, per-user-per-minute rate limit on create + preview, advisory locks against concurrent creation
- **Backwards compatible URLs**: legacy `/proxied-hosts/new` route continues to resolve to the new wizard

### Backend Servers - Server Pool Management
- **Server Management**: Add, edit, remove, and configure backend servers
- **Health Checks**: HTTP/TCP health check configuration and monitoring
- **Load Balancing**: Round-robin, least-conn, source, and URI algorithms
- **Server Weights**: Dynamic weight adjustment for load distribution
- **Maintenance Mode**: Enable/disable servers without removing configuration
- **Backup Servers**: Failover server configuration for high availability
- **Connection Limits**: Per-server connection and rate limiting
- **Monitoring Dashboard**: Real-time server status and performance metrics

### Configuration - HAProxy Config File Management
- **Syntax Editor**: Monaco editor with HAProxy syntax highlighting
- **Real-time Validation**: Configuration syntax checking and error detection
- **Configuration Templates**: Pre-built templates for common setups
- **Version Control**: Configuration versioning and rollback capabilities
- **Backup & Restore**: Automatic backups and manual restore functionality
- **Direct Editing**: Raw HAProxy configuration file editing
- **Deployment**: Apply configuration changes with validation
- **Help System**: Integrated HAProxy directive documentation
- **Real-time Config Pull**: Pull current haproxy.cfg from live HAProxy servers
  - View actual running configuration
  - Compare with managed configuration
  - Import existing configurations
  - Useful for migrating from manual to managed setup

### Apply Management - Change Tracking & Deployment

#### Change Tracking & Versioning
Every configuration change creates a new version with complete tracking:

- **Automatic Versioning**: Each apply creates a new version number (e.g., v1.0.123)
- **Version Snapshots**: Complete configuration state saved for each version
- **Diff Visualization**: See exactly what changed between versions
  - Green: Added lines
  - Red: Removed lines
  - Yellow: Modified lines
- **Change Summary**: High-level summary of changes (added frontends, modified backends, etc.)
- **Version Metadata**: Timestamp, user, cluster, affected entities

#### Deployment & Status
- **Change Tracking**: Track all pending configuration changes before apply
- **Apply Status**: Real-time deployment status per agent
- **Bulk Apply**: Deploy changes to all agents in a cluster simultaneously
- **Success/Failure Tracking**: Monitor which agents successfully applied changes
- **Retry Mechanism**: Retry failed deployments per agent
- **Apply Logs**: Detailed logs for each deployment operation with error messages

#### Version History & Restore

**Version History Viewer:**
- View all historical configuration versions
- Compare any two versions side-by-side
- See who made changes and when
- Filter by date, user, or cluster

**Configuration Restore:**
- Restore any previous configuration version
- One-click rollback to last known good configuration
- Restore process:
  1. Select previous version from history
  2. Review diff (current vs target version)
  3. Confirm restore
  4. Agents pull restored configuration
  5. HAProxy reloaded with previous config

**Use Cases:**
- Rollback after problematic deployment
- Audit configuration changes
- Compare production vs staging configurations
- Disaster recovery

### SSL Certificates - Centralized TLS/SSL Certificate Management

HAProxy OpenManager provides powerful centralized SSL/TLS certificate management with both global and cluster-specific scopes:

#### SSL Certificate Scopes

**1. Global SSL Certificates:**
- Defined once, distributed to **all clusters** and **all agents**
- Perfect for wildcard certificates or shared certificates
- When updated, all agents across all clusters automatically receive the new certificate
- Use case: `*.example.com` certificate used across all environments

**2. Cluster-Specific SSL Certificates:**
- Scoped to a specific cluster only
- Only agents in that cluster receive these certificates
- Use case: Environment-specific certificates (prod, staging, dev)

#### Certificate Operations

**Upload & Distribution:**
1. User uploads certificate via UI (PEM format: cert + private key)
2. Backend stores certificate in database
3. Agents poll backend and detect new/updated certificates
4. Agents download certificates to local disk (`/etc/haproxy/certs/`)
5. Agents update `haproxy.cfg` frontend bindings
6. HAProxy is safely reloaded with zero downtime

**Binding to Frontends:**
- SSL certificates are automatically bound to frontends based on configuration
- Frontend definition specifies which certificate to use
- Format: `bind *:443 ssl crt /etc/haproxy/certs/cert-name.pem`

**Centralized SSL Update Process:**
```
User Updates SSL in UI → All Agents Poll Backend (30s) 
  → Download New Certificate → Update Frontend Bindings 
  → Validate Config → Reload HAProxy (zero downtime)
```

#### Key Features
- **Certificate Upload**: PEM format certificate and private key upload
- **ACME Automation**: Automatic certificate issuance and renewal via Let's Encrypt / ACME protocol (see [ACME Auto SSL](#acme-auto-ssl---automated-certificate-management))
- **Certificate Store**: Centralized repository with encryption at rest
- **Expiration Monitoring**: Automatic expiration tracking with alerts (30, 15, 7 days)
- **Global Update**: Update one certificate, deploy to all clusters simultaneously
- **Domain Binding**: Associate certificates with specific domains/frontends
- **Certificate Validation**: Syntax and format validation before deployment
- **Renewal Tracking**: Certificate renewal status and history
- **Source Tracking**: Certificates display their source ("Manual" or "Auto (ACME)") for clear management
- **ACME Protection**: ACME-managed certificates are protected from manual content edits to prevent accidental overwrites
- **Security Profiles**: SSL/TLS protocol and cipher suite configuration
- **Zero Downtime**: Safe HAProxy reload ensures no dropped connections

### ACME Auto SSL - Automated Certificate Management

HAProxy OpenManager includes a built-in ACME client for automated SSL/TLS certificate management using the ACME protocol (RFC 8555). This enables zero-touch certificate issuance and renewal from Let's Encrypt and other ACME-compatible Certificate Authorities.

#### How ACME Auto SSL Works

```mermaid
sequenceDiagram
    autonumber
    participant U as Admin UI
    participant B as Backend API
    participant CA as ACME CA<br/>(Let's Encrypt)
    participant H as HAProxy<br/>(via Agent)

    Note over U,CA: === Certificate Request ===
    U->>B: Request certificate for example.com
    B->>CA: Create ACME order
    CA-->>B: Order + HTTP-01 challenge token
    B->>B: Store challenge token in DB

    Note over CA,H: === Domain Validation ===
    CA->>H: GET /.well-known/acme-challenge/{token}
    H->>B: Proxy challenge request (ACME ACL)
    B-->>H: Challenge response (key authorization)
    H-->>CA: Challenge response
    CA->>CA: Validate domain ownership

    Note over B,CA: === Certificate Issuance ===
    B->>CA: Finalize order (submit CSR)
    CA-->>B: Signed certificate
    B->>B: Store cert, status = PENDING
    B->>B: Create config version (PENDING)

    Note over U,B: === Manual Apply (New Certs) ===
    U->>B: Click "Apply Changes"
    B->>B: Mark APPLIED + consolidated config
    B->>H: Notify agents
    H->>H: Pull cert + reload HAProxy
```

#### Auto-Renewal Flow

Certificates are automatically renewed before expiration through a background task that runs hourly:

```mermaid
sequenceDiagram
    autonumber
    participant BG as Background Task<br/>(Hourly)
    participant B as Backend
    participant CA as ACME CA
    participant DB as Database
    participant H as HAProxy Agents

    BG->>DB: Find certs expiring within N days
    BG->>CA: Create renewal order
    CA-->>BG: Challenge token
    BG->>DB: Store challenge

    Note over BG,CA: Next cycle (or same)
    BG->>CA: Check order status
    CA-->>BG: Status: valid
    BG->>CA: Download renewed certificate

    Note over BG,DB: Auto-Apply (same as manual Apply)
    BG->>DB: Update cert (PENDING)
    BG->>DB: Create config versions (PENDING)
    BG->>DB: apply_ssl_related_configs()
    BG->>DB: Create consolidated version (APPLIED)
    BG->>DB: Mark cert APPLIED
    BG->>H: Notify agents via Redis
    H->>H: Pull updated cert + reload
```

**Key behavior**: Auto-renewed certificates follow the **exact same Apply pipeline** as manual SSL updates. The cert transitions `PENDING -> APPLIED` automatically, agents are notified, and cross-cluster propagation works identically to manual Apply. No separate deployment mechanism is used.

#### ACME Certificate Diagnostic Panel

Available from the ACME Automation list (`Diagnose` button on each order, or by clicking the order's status tag), the Diagnostic Panel runs a full preflight checklist before a certificate is issued or renewed and surfaces every blocker in a single operator-friendly view:

- **Agent reachability** - verifies that at least one agent in each target cluster is online and within the last-seen window
- **DNS resolution** - resolves every domain on the order (A / AAAA / CNAME) and flags wildcards and non-resolvable names with the exact upstream resolver error
- **Port 80 reachability** - checks that the HTTP-01 challenge port is reachable from the public internet via the agent's egress path
- **ACME challenge ACL preview** - renders the `acl1 !acl1` + `http-request return` block that will be injected at apply time, so the operator can see exactly what HAProxy will receive
- **HSTS / rate-limit policy collision check** - warns if existing frontend rules would short-circuit the challenge route
- **Account binding check** - confirms a valid ACME account exists for the selected provider + cluster combination
- **Event Log timeline** - merged view of typed `acme_order_events` rows and correlated `user_activity_logs` entries; auto-tails every 5s while the order is in `pending`/`processing`
- **Humanized error display** - covers 11+ RFC8555 problem types (`badNonce`, `caa`, `connection`, `rateLimited`, `unauthorized`, ...) with full backwards compatibility for legacy plain-string error details
- **Operator-friendly error envelope** - every failure returns `{ correlation_id, field, cause, remediation }` so root-causing is one API call away

#### ACME Features

| Feature | Description |
|---------|-------------|
| **Certificate Request Wizard** | Step-by-step UI wizard: select domains, account, target clusters |
| **Multi-Provider Support** | Let's Encrypt, ZeroSSL, Google Trust Services, Buypass, or custom ACME CA |
| **Staging Mode** | Test with LE staging environment (no rate limits) before production |
| **Account Management** | Register, view details, and deactivate ACME accounts |
| **Order Tracking** | View all orders with status, domains, and challenge details |
| **Auto-Renewal** | Configurable renewal window (default: 30 days before expiry) |
| **Renewal Schedule** | Dashboard showing all ACME certs with expiry dates and renewal status |
| **HTTP-01 Challenges** | Built-in challenge responder with automatic HAProxy ACL injection |
| **EAB Support** | External Account Binding for CAs that require it |
| **Certificate Protection** | ACME-managed certs are read-only in SSL Management (content cannot be manually edited) |
| **CA Chain Import** | One-click import of CA intermediate certificates |
| **Certificate Revocation** | Revoke compromised certificates through the ACME CA |

#### ACME Configuration

ACME settings are managed through **Settings > ACME / SSL Automation** tab:

| Setting | Description | Default |
|---------|-------------|---------|
| `acme.provider` | ACME CA provider selection | `letsencrypt` |
| `acme.directory_url` | ACME directory endpoint URL | LE production URL |
| `acme.staging_mode` | Use staging environment | `false` |
| `acme.auto_renew_enabled` | Enable automatic certificate renewal | `false` |
| `acme.renew_before_days` | Days before expiry to trigger renewal | `30` |
| `acme.eab_kid` | External Account Binding Key ID (if required) | - |
| `acme.eab_hmac_key` | External Account Binding HMAC Key (if required) | - |

#### Cluster ACME Setup

For HTTP-01 challenges to work, each cluster needs ACME challenge routing enabled:

1. Go to **Cluster Management** > Edit cluster
2. Enable **ACME Challenge Routing** toggle
3. Optionally set a custom ACME backend URL
4. Apply changes

When enabled, HAProxy configuration is automatically injected with:
- An ACL matching `/.well-known/acme-challenge/` requests
- A `use_backend` rule directing challenge traffic to the management backend
- A dedicated `_acme_challenge_backend` section

This injection only affects HTTP-mode frontends and is completely removed when ACME is disabled.

#### ACME Distributed Architecture

Understanding how HTTP-01 challenges work in a distributed HAProxy environment is critical for successful certificate issuance:

```
┌─────────────────┐    DNS A Record     ┌──────────────────┐
│  Let's Encrypt   │ ──────────────────► │  HAProxy Node(s) │
│  (CA Server)     │  HTTP GET :80       │  (VIP / Public)  │
└─────────────────┘  /.well-known/      └────────┬─────────┘
                      acme-challenge/             │
                      {token}                     │ ACL match →
                                                  │ use_backend
                                                  │ _acme_challenge_backend
                                                  ▼
                                         ┌──────────────────┐
                                         │  OpenManager      │
                                         │  (Backend Server) │
                                         │  Serves token     │
                                         │  response from DB │
                                         └──────────────────┘
```

**Key Points:**

1. **Let's Encrypt connects to your HAProxy**, not directly to OpenManager
2. **DNS must resolve** the requested domain to your HAProxy node's public IP (or VIP/NAT)
3. **Port 80 must be open** from the internet to HAProxy for HTTP-01 validation
4. **HAProxy routes** the `/.well-known/acme-challenge/` path to OpenManager via the injected backend
5. **OpenManager serves** the challenge token response stored in the database
6. The `MANAGEMENT_BASE_URL` or `acme.challenge_backend_url` setting tells HAProxy where to find OpenManager

**Network Scenarios:**

| Scenario | HAProxy | OpenManager | DNS Target |
|----------|---------|-------------|------------|
| Single server | localhost:80 | localhost:5000 | Server's public IP |
| Separate servers | 10.0.0.10:80 | 10.0.0.20:5000 | HAProxy's public IP |
| Behind NAT/VIP | VIP: 1.2.3.4:80 | Internal:5000 | VIP address |
| Multi-cluster | Multiple HAProxy nodes | Central OpenManager | Each domain → respective HAProxy |

#### DNS-01 Challenge — Internal/Isolated Clusters & Wildcards *(v1.8.0 — Issue #35)*

The default **HTTP-01** challenge validates over **port 80**, so the domain must resolve publicly to an HAProxy node with ACME Challenge Routing enabled. **DNS-01** validates via a **DNS TXT record** (`_acme-challenge.<domain>`) instead, so it needs **no inbound port 80 and no public ingress** to the HAProxy node. Use it for:

- **Internal / isolated clusters** (behind a VPN/firewall, no public port 80) where you still control the domain's DNS.
- **Wildcard certificates** (`*.example.com`) — which can *only* be issued via DNS-01.

DNS-01 is **opt-in** and fully backward compatible: it is disabled until an administrator enables it, and existing HTTP-01 certificates are completely unaffected.

- **Enable it**: Settings → ACME / SSL Automation → **DNS-01 Challenge (advanced)** → turn on *Enable DNS-01 Challenge* and Save. While off, DNS-01 options are hidden and no DNS-01 orders can be created.
- **Per-account provider**: in ACME Automation, create (or reconfigure) an ACME account with **Challenge Method = DNS-01** and a **DNS Provider**. Provider credentials are **verified before saving** and **encrypted at rest** (Fernet, mirroring the VRRP/MFA secret pattern); they are never returned by the API or written to logs.
- **Supported providers**: **Manual** (publish the TXT record yourself in any DNS — including fully internal DNS — then click *Verify*; works everywhere but cannot auto-renew unattended) and **Cloudflare** (API token with `Zone:DNS:Edit` + `Zone:Read`; the TXT record is created and cleaned up automatically and renews unattended). The provider interface is pluggable — more providers can be added without changing the issuance flow.
- **Same pipeline**: after validation the certificate follows the normal PENDING → APPLIED flow (assign to clusters / Apply Management) and the agent serves it — identical to HTTP-01 from finalize onward, with **zero agent or rendered-config changes** for DNS-01.
- **Manual flow**: the order detail shows the exact `_acme-challenge.<domain>` record name + TXT value (copyable); publish it and click *I've added the records — Verify*. For Cloudflare it is automatic.
- **Resilience**: a propagation-lag failure is recovered by a **bounded fresh-order retry chain** (1 original + 3 retries with increasing backoff, kept under Let's Encrypt's rate limits); any orphaned TXT record is cleaned up by a reconcile sweep. The order detail shows a DNS-01 event timeline (publish → validation → cleanup).
- **Wildcards**: `*.example.com` is validated at `_acme-challenge.example.com`; it does **not** cover the apex — add `example.com` as a separate name if you need both (the providers handle the two coexisting TXT values automatically).
- **Scope (this release)**: the Site Wizard remains HTTP-01-only; issue DNS-01 / wildcard certificates from **ACME Automation**.

#### ACME Quick Start Guide

Follow these steps to obtain your first Let's Encrypt certificate:

**Step 1: Configure ACME Settings**
- Navigate to **Settings > ACME / SSL Automation** tab
- Select your ACME provider (default: Let's Encrypt)
- For testing, enable **Staging Mode** to avoid rate limits
- Save changes

**Step 2: Register an ACME Account**
- On the **SSL Certificates > ACME Automation** page, find the ACME Account card
- Click **Register Account** and provide a valid email address
- Accept the Terms of Service

**Step 3: Enable ACME on Clusters**
- Go to **Cluster Management** > Edit your cluster
- Enable **ACME Challenge Routing** toggle
- Set the correct **ACME Backend URL** if OpenManager is on a different server
- Save the cluster configuration

**Step 4: Apply Configuration**
- Go to **Apply Management** and apply the pending HAProxy configuration changes
- This injects the ACME challenge routing rules into HAProxy

**Step 5: Verify Challenge Routing**

Test that the challenge path is reachable through HAProxy:
```bash
curl -v http://your-haproxy-ip/.well-known/acme-challenge/test
```
Expected: HTTP 404 from OpenManager (not HAProxy's default 503). This confirms routing works.

**Step 6: Ensure DNS Resolution**
- Your domain(s) must have DNS A/AAAA records pointing to your HAProxy node's public IP
- Verify: `dig +short yourdomain.com` should return the HAProxy IP

**Step 7: Request Certificate**
- Go to **SSL Certificates > ACME Automation** tab
- Click **New Certificate** and follow the wizard
- The UI will guide you through prerequisite checks before submission

#### Troubleshooting ACME

If certificate issuance fails, check the following:

| Issue | Diagnostic Step |
|-------|----------------|
| Challenge 404 | Check `ACME-CHALLENGE` log entries in OpenManager logs |
| DNS mismatch | Verify `dig +short yourdomain.com` returns HAProxy IP |
| Port 80 blocked | Test from external: `curl http://yourdomain.com/.well-known/acme-challenge/test` |
| Config not applied | Check **Apply Management** for pending changes |
| ACME not enabled | Verify cluster has **ACME Challenge Routing** enabled |
| Account issues | Check ACME account status in **ACME Automation** page |

**Diagnostic Logging:** OpenManager provides detailed ACME logging with prefixes:
- `ACME:` — Order creation, challenge responses, finalization
- `ACME-CHALLENGE:` — Incoming challenge token requests and responses

Review application logs to trace the complete ACME flow when troubleshooting issues.

### WAF Management - Web Application Firewall
- **Rate Limiting**: Request rate limiting by IP, URL, or custom patterns
- **IP Filtering**: Whitelist/blacklist IP addresses and CIDR ranges
- **Geographic Blocking**: Country-based access restrictions
- **DDoS Protection**: Automated DDoS detection and mitigation rules
- **Custom Rules**: User-defined security rules with regex patterns
- **Attack Monitoring**: Real-time attack detection and logging
- **Rule Templates**: Pre-configured security rule templates
- **Statistics Dashboard**: WAF activity analytics and blocked request metrics

### IP Inventory - Cross-Cluster IP Search & Discovery

The IP Inventory page provides a unified view of all IP addresses across every cluster, independent of the global cluster selector. It enables quick identification of which cluster, agent, or backend server a given IP belongs to.

**Key Features:**
- **Cross-Cluster Search**: Search any IP address across all clusters simultaneously
- **IP Type Identification**: Instantly determine if an IP is an agent server IP, a keepalived VIP, or a backend server address
- **Unified Results Card**: Search results show matched IP type (Server IP, VIP, Backend), agent/server name, cluster association, and status
- **Agent Tab**: Browse all agents with cluster name, hostname, agent IP, VIP (keepalive), VRRP state (MASTER/BACKUP), status, platform, and last seen time
- **Backend Servers Tab**: Browse all backend servers with cluster, backend name, server address, status, weight, and check status
- **Cluster Color Coding**: Each cluster is assigned a consistent color tag for quick visual identification
- **Auto-Refresh**: Data refreshes automatically every 30 seconds
- **Filters**: Filter by cluster and status within each tab

**Use Cases:**
- Identify which HAProxy cluster an IP belongs to during incident response
- Find which agent is running as MASTER or BACKUP in a keepalived pair
- Locate a backend server IP across multiple clusters
- Audit all IP addresses managed by the platform

### HA / VIP Management - Keepalived Virtual IP Failover

The HA / VIP page manages **highly-available virtual IPs** backed by Keepalived (VRRP) directly from the UI — no SSHing into nodes to install/configure Keepalived by hand. It builds on the agent pull-architecture: you define the VIP centrally, click Apply, and the agents converge.

**What it does:**
- **VIP dashboard**: lists each virtual IP with its pool, VRID, per-node interface, and a **live MASTER / BACKUP / FAULT** column per node (refreshed every 30s from the existing keepalive-state heartbeat pipeline).
- **Creation form**: enter the virtual IP (+ prefix), pick the pool, and select which of the pool's HAProxy nodes participate — each with a network interface (from the node's reported interfaces), a VRRP role (MASTER/BACKUP) and a priority. VRID auto-allocates per pool; an optional VRRP secret can be set.
- **Hands-off automation**: on **Apply**, each member's `keepalived.conf` is rendered and delivered; the agent installs Keepalived if missing, writes the config + a HAProxy health-check (`vrrp_script` + `track_script`), validates with `keepalived -t`, and starts the service. When HAProxy drops on the active node, the health-check lowers VRRP priority and the **VIP fails over automatically** to a backup.

**How it works (pull-based, isolated):**
- New tables `vip_instances` + `vip_members`; the agent polls `GET /api/agents/{name}/keepalived-config` (key-authenticated, agent-bound) and converges. It is fully **isolated** from the global HAProxy apply flow — VIP changes never regenerate `haproxy.cfg`.
- **Cluster-driven path**: the `keepalived.conf` location is a cluster setting (`keepalived_config_path`, default `/etc/keepalived/keepalived.conf`) delivered to the agent dynamically — just like the HAProxy paths — so non-standard installs are supported with zero per-node effort. The default is what the keepalived service loads on every distro; if you set a non-default path, ensure the keepalived unit is configured to load it.

**Apply / Reject staging:**
- VIP edits are staged as **PENDING** and only go live on **Apply**, which records an applied snapshot. **Reject** discards pending changes and **restores the previous applied state** (a never-applied VIP is discarded). Editing a live VIP never disrupts it until you re-Apply.

**Enterprise safety:**
- **Opt-in & backward compatible** — nodes/clusters without a VIP do nothing new.
- **Never clobbers a hand-managed Keepalived** — if an unmanaged `keepalived.conf` exists, the agent reports "externally managed" and leaves it untouched.
- **Multi-distro install** — Debian/Ubuntu, RHEL/CentOS/Alma/Rocky, Fedora, SUSE/openSUSE, Alpine (apt/dnf/yum/zypper/apk).
- **Reliable detection across platforms** — MASTER/BACKUP is detected via systemd journal, syslog, and a portable interface-based check (exact-match, all VIPs).
- **Secure** — the VRRP secret is encrypted at rest and never returned by the API; the delivery endpoint requires the node's own API key.
- **Scope** — VRRP targets bare-metal / VMware / on-prem L2 networks; the UI clearly notes that AWS/Azure/GCP don't honor VRRP/gratuitous-ARP. macOS agents can't run Keepalived and are excluded (the UI warns if one is selected).

**RBAC:** gated by the `vip` permission group (`vip.read/create/update/delete/apply`); admins bypass.

### User Management - Access Control & Authentication
- **User Accounts**: Create, edit, and manage user accounts
- **Role-based Access**: Admin, user, and custom role definitions
- **Permission System**: Granular permissions for different system functions
- **User Activity**: Login history and user action audit logs
- **Password Management**: Secure password policies and reset functionality
- **Session Management**: Active session monitoring and force logout
- **API Keys**: User API key generation and management
- **Role Assignment**: Dynamic role assignment and permission updates

#### Multi-Factor Authentication (MFA) — v1.6.0 (Issue #18)

MFA is **optional per account** and **default OFF**. Existing users keep their
single-factor (username/password) login unless they choose to enable it. The
feature is fully additive: nothing changes for accounts that don't opt in.

**For end-users**

- Open **Users** → find your own row → click **Enable MFA**.
- A wizard opens with three steps:
  1. **Set up** — scan the QR code with Google Authenticator / Authy /
     1Password / Microsoft Authenticator, or paste the displayed secret manually.
  2. **Verify** — enter the current 6-digit code from your app.
  3. **Backup codes** — save the 10 single-use recovery codes (format
     `XXXX-YYYY`). They are shown only once. Use the **Copy all** /
     **Download .txt** buttons.
- After enrollment your sign-in becomes two-step: username/password →
  6-digit TOTP (or a backup code).
- To turn MFA off again, open your row's **Disable MFA** action and enter a
  current TOTP or backup code.

**For admins**

- On any user with MFA enabled, the **Reset MFA** action wipes the user's
  TOTP secret, backup codes, and pending challenges. A required *reason* is
  written to the audit log. After reset the user logs in with their password
  and may re-enroll.

**Emergency: reset MFA for every user**

Use the CLI helper when an authenticator outage / mass key loss happens.
Double confirmation is required; the action is irreversible.

```bash
API_URL=https://hap.example.com ADMIN_TOKEN=eyJ... \
  ./scripts/admin-mfa-reset-all.sh
# Prompts ask for: 'yes' → 'RESET ALL MFA' → reason
# Audit log:      action='mfa.disabled.admin_bulk_reset'
```

**Configuration**

- Backend env var `MFA_ENCRYPTION_KEY` — a 44-char Fernet key used to encrypt
  TOTP secrets at rest. Generate with:
  ```bash
  python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  ```
  On Kubernetes the key lives in the `backend-secret` Secret
  (`k8s/manifests/03-secrets.yaml`). The shipped manifest uses the placeholder
  `mfa_encryption_key_replace_me`; replace it via your CI/CD pipeline (e.g.
  `sed` step) before `kubectl apply`.
- Optional `MFA_ACCOUNT_LABEL_DOMAIN` — overrides the per-user otpauth label
  domain so QR codes show e.g. `alice@hap.example.com` instead of the request
  hostname.

**API endpoints (all additive)**

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/auth/login` | Returns `mfa_required:true`+`mfa_token` for MFA users; legacy shape otherwise |
| `POST` | `/api/auth/login/mfa-verify` | Submits TOTP or backup code; returns JWT |
| `GET`  | `/api/mfa/status` | Self status (enabled / method / backup codes remaining) |
| `POST` | `/api/mfa/enroll/start` | Begin TOTP enrollment |
| `POST` | `/api/mfa/enroll/confirm` | Confirm enrollment, returns 10 backup codes once |
| `POST` | `/api/mfa/disable` | Self-disable (TOTP or backup required) |
| `POST` | `/api/mfa/backup-codes/regenerate` | Issue 10 fresh backup codes (TOTP only) |
| `GET`  | `/api/mfa/admin/status/{id}` | Admin: any user's MFA status |
| `POST` | `/api/mfa/admin-reset/{id}` | Admin: reset a single user's MFA |
| `POST` | `/api/mfa/admin-reset-all` | Admin: emergency reset for all users |

**Rate limits (per-user, ingress-aware, operationally tunable)**

MFA endpoints are rate-limited via slowapi+Redis with a **user-aware key
function** (`backend/middleware/mfa_rate_limit_key.py`):

1. If the request carries a valid Bearer JWT → bucket is `user:<id>`.
   Each operator gets an isolated bucket; an org-wide MFA rollout is no
   longer bottlenecked by the shared ingress IP.
2. Else, if the TCP peer is in `MFA_TRUSTED_PROXY_CIDRS` → bucket is the
   first `X-Forwarded-For` hop (real client IP behind the ingress).
3. Else → bucket is the TCP peer (slowapi default).

Defaults live in `backend/middleware/mfa_rate_limits.py` and are sized for
**enterprise-scale** rollouts (thousands of operators). Each one is
overridable via env var; an invalid string logs a `WARNING` and falls back
to the default without crashing.

| Endpoint | Env var | Default | Bucket |
|---|---|---|---|
| `POST /api/mfa/enroll/start` | `MFA_RATE_LIMIT_ENROLL_START` | `10/minute` | per user |
| `POST /api/mfa/enroll/confirm` | `MFA_RATE_LIMIT_ENROLL_CONFIRM` | `10/minute` | per user |
| `POST /api/mfa/disable` | `MFA_RATE_LIMIT_DISABLE` | `10/minute` | per user |
| `POST /api/mfa/backup-codes/regenerate` | `MFA_RATE_LIMIT_REGENERATE_BACKUP_CODES` | `5/hour` | per user |
| `POST /api/mfa/admin-reset/{id}` | `MFA_RATE_LIMIT_ADMIN_RESET` | `60/hour` | per admin |
| `POST /api/mfa/admin-reset-all` | `MFA_RATE_LIMIT_ADMIN_RESET_ALL` | `1/day` | per admin |

Limit string format follows slowapi: `<count>/<second|minute|hour|day>`.

**Trusted-proxy configuration**
`MFA_TRUSTED_PROXY_CIDRS` — comma-separated CIDR list, e.g.
`10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`. Empty (default) disables XFF
parsing — XFF from any peer is then ignored, which is the safe choice when
the topology is unknown. Set this when your backend sits behind a known
ingress / load balancer so anonymous flows still get per-real-IP buckets.

The pre-existing `/api/auth/login` rate-limiting policy is unchanged. On
Kubernetes, see commented overrides in
`k8s/manifests/07-configmaps.yaml::backend-config`.

### Settings - System Configuration
- **Theme Settings**: Light/dark mode toggle and UI customization
- **ACME / SSL Automation**: Configure ACME provider, directory URL, staging mode, auto-renewal, EAB credentials, and test CA connectivity
- **Notification Settings**: Alert preferences and notification channels
- **System Preferences**: Default timeouts, refresh intervals, and limits
- **Backup Settings**: Automated backup scheduling and retention policies
- **Integration Settings**: External system integrations and webhooks
- **Language Settings**: Multi-language support configuration
- **Performance Tuning**: System performance and optimization settings


## Getting Started - First-Time Usage

### Quick Start for New Users

This guide walks you through using HAProxy OpenManager for the first time, including importing your existing HAProxy configuration.

#### Setup Flow Diagram

```mermaid
graph TD
    Start([🚀 Start Setup]) --> Step1[1️⃣ Create Agent Pool<br/>HAProxy Agent Pool Management]
    Step1 --> Step2[2️⃣ Create Cluster<br/>HAProxy Cluster Management]
    Step2 --> Step3[3️⃣ Generate Agent Script<br/>Agent Management]
    Step3 --> Step4[4️⃣ Run Script on HAProxy Server<br/>SSH to server and execute]
    Step4 --> Step5[5️⃣ Copy Backup Config<br/>haproxy.cfg.initial-backup]
    Step5 --> Step6[6️⃣ Import Configuration<br/>Bulk HAProxy Config Import]
    Step6 --> Step7[7️⃣ Apply Changes<br/>Apply Management]
    Step7 --> Complete([✅ Setup Complete!])
    
    style Start fill:#2d5016,stroke:#4caf50,stroke-width:3px,color:#fff
    style Step1 fill:#7b4d1e,stroke:#ff9800,stroke-width:2px,color:#fff
    style Step2 fill:#7b4d1e,stroke:#ff9800,stroke-width:2px,color:#fff
    style Step3 fill:#1a4971,stroke:#2196f3,stroke-width:2px,color:#fff
    style Step4 fill:#4a1a4a,stroke:#9c27b0,stroke-width:2px,color:#fff
    style Step5 fill:#6b1e3f,stroke:#e91e63,stroke-width:2px,color:#fff
    style Step6 fill:#1a4d43,stroke:#009688,stroke-width:2px,color:#fff
    style Step7 fill:#6b5d1a,stroke:#fbc02d,stroke-width:2px,color:#fff
    style Complete fill:#2d5016,stroke:#4caf50,stroke-width:3px,color:#fff
```

#### Detailed Step-by-Step Instructions

##### Step 1: Create Agent Pool 📦

Navigate to **HAProxy Agent Pool Management** page.

1. Click **"Create Pool"** button
2. Fill in pool details:
   - **Pool Name**: `Production Pool` (or your preferred name)
   - **Description**: `Production environment HAProxy servers`
3. Click **Save**

**Purpose**: Pools logically group your HAProxy agents for better organization.

---

##### Step 2: Create Cluster 🎯

Navigate to **HAProxy Cluster Management** page.

1. Click **"Create Cluster"** button
2. Fill in cluster details:
   - **Cluster Name**: `Production Cluster`
   - **Description**: `Main production HAProxy cluster`
   - **Select Pool**: Choose the pool created in Step 1 (`Production Pool`)
3. Click **Save**

**Purpose**: A cluster represents a logical grouping of HAProxy configurations that will be deployed to agents.

---

##### Step 3: Generate Agent Installation Script 🤖

Navigate to **Agent Management** page.

1. Click **"Create Agent"** or **"Generate Script"** button
2. Configure agent details:
   - **Agent Name**: `haproxy-prod-01` (unique identifier)
   - **Select Pool**: Choose the same pool from Step 1 (`Production Pool`)
   - **Platform**: Select `Linux` or `macOS`
   - **Architecture**: Select `x86_64` or `ARM64`
3. Click **"Generate Install Script"**
4. Click **"Download Script"** to save the installation script

**Purpose**: This generates a customized installation script that will connect your HAProxy server to the management backend.

---

##### Step 4: Install Agent on HAProxy Server 🖥️

SSH into your HAProxy server and run the installation script.

```bash
# Copy the script to your HAProxy server
scp install-agent-haproxy-prod-01.sh root@your-haproxy-server:/tmp/

# SSH to the HAProxy server
ssh root@your-haproxy-server

# Make the script executable
chmod +x /tmp/install-agent-haproxy-prod-01.sh

# Run the installation script
sudo /tmp/install-agent-haproxy-prod-01.sh
```

**What the script does:**
- Installs required dependencies (Python, socat)
- Creates `haproxy-agent` systemd service
- Starts the agent (polls backend every 30 seconds)
- **Creates initial backup**: `/etc/haproxy/haproxy.cfg.initial-backup`
- Registers the agent with the backend

**Verify installation:**
```bash
# Check agent service status
sudo systemctl status haproxy-agent

# Check agent logs
sudo tail -f /var/log/haproxy-agent/agent.log
```

Return to the UI and verify the agent appears in **Agent Management** with status "Connected ✅".

---

##### Step 5: Copy Existing HAProxy Configuration 📄

You have **three options** to get your existing HAProxy configuration:

**Option A: Using the Initial Backup (Recommended)**

On your HAProxy server, the agent created a backup of your original configuration.

```bash
# Display the backup configuration
cat /etc/haproxy/haproxy.cfg.initial-backup
```

**Copy the entire contents** of this file to your clipboard.

---

**Option B: View Configuration via UI (Easiest)**

Navigate to **Configuration Management** page in the UI.

1. Select your agent from the **Agent Selector** dropdown
2. Click **"View Configuration"** button
3. The system will fetch the live configuration from the agent
4. **Copy the entire configuration** displayed in the viewer
5. You now have the configuration ready for import!

**Benefits**: No need to SSH to the server, get configuration directly from the UI.

---

**Option C: Current Configuration File**

If the backup doesn't exist, SSH to your server and copy the current configuration:

```bash
# Display current HAProxy configuration
cat /etc/haproxy/haproxy.cfg
```

**Copy the entire contents** to your clipboard.

---

##### Step 6: Import Configuration via Bulk Import 📥

Navigate to **Bulk HAProxy Config Import** page.

1. Select your cluster from the **Cluster Selector** dropdown (top of page)
2. **Paste** the configuration copied from Step 5 into the text area
3. Click **"Parse Configuration"** button
4. Review the parsed entities:
   - Frontends detected
   - Backends detected
   - Servers detected
   - SSL certificates (if any)
5. Click **"Import Configuration"**

**What happens:**
- The system parses your HAProxy config file
- Extracts frontends, backends, servers, and SSL bindings
- Creates database entities for each component
- Prepares configuration for deployment

**Result**: Your existing HAProxy configuration is now managed by HAProxy OpenManager! 🎉

---

##### Step 7: Apply Changes to Agent 🚀

Navigate to **Apply Management** page.

1. You'll see pending changes listed:
   - Frontends to be created
   - Backends to be created
   - Servers to be added
2. Review the changes
3. Click **"Apply Changes"** button
4. Monitor deployment status:
   ```
   Agent: haproxy-prod-01
   Status: ✅ Configuration applied successfully
   Version: v1.0.1
   ```

**What happens:**
- Backend marks configuration tasks as ready for deployment
- Agent polls and detects pending tasks (within 30 seconds)
- Agent downloads the new configuration
- Agent validates HAProxy configuration syntax
- Agent reloads HAProxy service (zero downtime)
- Agent reports success back to backend

**Verify deployment:**
- Check that agent status shows "Applied Successfully"
- Check HAProxy is running: `systemctl status haproxy`
- Check HAProxy stats: `http://your-server:8404/stats`

---

#### ✅ Setup Complete!

Your HAProxy server is now fully managed by HAProxy OpenManager. You can now:

- ✨ **Manage Frontends**: Add, edit, delete frontends via UI
- 🖥️ **Manage Backends**: Configure backend servers and health checks
- 🔒 **Upload SSL Certificates**: Centralized SSL management
- 🛡️ **Configure WAF Rules**: Add security rules
- 📊 **Monitor Performance**: View real-time statistics on dashboard
- 🔄 **Version Control**: Track all configuration changes with rollback capability

**Next Steps:**
- Add more agents to the same pool for multi-node clusters
- Configure SSL certificates in **SSL Management**
- Set up ACME Auto SSL in **SSL Management > ACME Automation** for automated Let's Encrypt certificates
- Add WAF rules in **WAF Management**
- Monitor your cluster in **Dashboard**

---


## Installation

Choose your preferred installation method:

| Method | Best For | Guide |
|--------|----------|-------|
| **Docker** | Quick setup, single-server, Docker Compose | [Docker Installation](#docker-installation) |
| **Kubernetes/OpenShift** | Production, HA, enterprise | [Kubernetes Installation](#kubernetesopenshift-installation) |
| **Standalone** | Bare-metal, VMs, LXC, no containers | [Standalone Guide](docs/STANDALONE_INSTALL.md) |

---

### Docker Installation

#### Prerequisites

- **Docker & Docker Compose** (v20.10+)
- **Git**
- **2GB+ RAM** for all services

#### Installation Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/taylanbakircioglu/haproxy-openmanager.git
   cd haproxy-openmanager
   ```

2. **Start All Services**
   ```bash
   docker-compose up -d
   ```

3. **Verify Installation**
   ```bash
   # Check all services are running
   docker-compose ps
   
   # Check API health
   curl http://localhost:8080/api/clusters
   ```

4. **Access the Application**
   - **Web Interface**: http://localhost:8080
   - **API Documentation**: http://localhost:8080/docs
   - **HAProxy Stats**: http://localhost:8404/stats

### Default Credentials

- **Admin User**: `admin` / `admin123`
- **Regular User**: `user` / `user123`

> ⚠️ **Security Note**: Change default passwords immediately in production environments.

#### Services Overview

The application consists of 8 Docker containers:

```bash
# Core Application Services
haproxy-openmanager-frontend    # React.js web interface
haproxy-openmanager-backend     # FastAPI backend
haproxy-openmanager-db          # PostgreSQL database  
haproxy-openmanager-redis       # Redis cache
haproxy-openmanager-nginx       # Nginx reverse proxy

# HAProxy Test Instances
haproxy-instance       # Local test instance
haproxy-remote1        # Remote test instance 1
haproxy-remote2        # Remote test instance 2
```

### Management Commands

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f [service_name]

# Stop all services
docker-compose down

# Rebuild and restart
docker-compose down && docker-compose up --build -d

# Database reset (⚠️ Destroys all data)
docker-compose down
docker volume rm haproxy-openmanager_postgres_data
docker-compose up -d
```

### Volume Management

```bash
# List volumes
docker volume ls | grep haproxy

# Backup database
docker exec haproxy-openmanager-db pg_dump -U haproxy_user haproxy_openmanager > backup.sql

# Restore database
docker exec -i haproxy-openmanager-db psql -U haproxy_user haproxy_openmanager < backup.sql
```

### Kubernetes/OpenShift Installation

#### Kubernetes Deployment

For Kubernetes environments, use the provided manifests:

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/manifests/

# Check deployment status
kubectl get pods -n haproxy-openmanager

# Access via port-forward
kubectl port-forward svc/nginx-service 8080:80 -n haproxy-openmanager
```

See [k8s/manifests/README.md](k8s/manifests/README.md) for detailed Kubernetes setup instructions.

### Local Development

#### Local Development Setup

1. **Backend Development**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate     # Windows
   
   pip install -r requirements.txt
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Frontend Development**
   ```bash
   cd frontend
   npm install
   npm start
   ```

3. **Database Setup**
   ```bash
   # Start only database and redis
   docker-compose up -d postgres redis
   
   # Run migrations
   python backend/migration.py
   ```


## Configuration

### Environment Variables

All configuration is managed through environment variables for maximum flexibility across different deployment environments.

**📄 Configuration Template**: `.env.template`

```bash
# 1. Copy the template
cp .env.template .env

# 2. Edit (replace placeholders with your actual values)
nano .env

# 3. Start
docker-compose up -d
```

**Important**: 
- `.env.template` is only a template (committed to git)
- `.env` is the actual configuration (NOT committed - in .gitignore)
- When making changes, edit `.env`, not `.env.template`!

#### Backend Configuration
```bash
# Database
DATABASE_URL="postgresql://haproxy_user:haproxy_pass@postgres:5432/haproxy_openmanager"
REDIS_URL="redis://redis:6379"

# Security
SECRET_KEY="your-secret-key-change-this-in-production"
DEBUG="False"  # Set to False in production

# Public URL Configuration (IMPORTANT for agent connectivity)
# This URL is embedded in agent installation scripts
PUBLIC_URL="https://your-haproxy-openmanager.example.com"
MANAGEMENT_BASE_URL="${PUBLIC_URL}"  # Optional, defaults to PUBLIC_URL

# Examples:
#   Development:  PUBLIC_URL="http://localhost:8000"
#   Production:   PUBLIC_URL="https://haproxy-openmanager.example.com"
#   Production:   PUBLIC_URL="https://haproxy-openmanager.yourdomain.com"

# Logging
LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Agent Settings
AGENT_HEARTBEAT_TIMEOUT_SECONDS=15
AGENT_CONFIG_SYNC_INTERVAL_SECONDS=30
```

#### Frontend Configuration

The frontend is a Create-React-App single-page app served as a static bundle
(`serve -s build`). It uses **same-origin** (`window.location.host`) for all
`/api/*` calls — no env vars are needed in production. Routing is handled
entirely by the nginx reverse proxy in front of the frontend pod (Kubernetes
ingress + `nginx-config` ConfigMap, or `nginx/nginx.conf` for Docker Compose).

> ⚠️ **Do NOT set `REACT_APP_API_URL` in your CI/CD pipeline.** CRA inlines
> `REACT_APP_*` values into the bundle at **build time**, so any value baked
> in there overrides the runtime same-origin detection and breaks every
> deployment whose URL does not match the inlined string. Leave the variable
> unset; the bundle will resolve to whatever host the user is browsing.

```bash
# Optional, only when you intentionally need a cross-origin API
# (then CORS_ORIGINS on the backend must include the SPA's origin):
# REACT_APP_API_URL="https://api.example.com"

# Build settings
NODE_ENV="production"
GENERATE_SOURCEMAP="false"
```

#### Configuration Priority

1. **Development**: Use `.env` file in project root
2. **Docker Compose**: Environment variables in `docker-compose.yml`
3. **Kubernetes/OpenShift**: ConfigMaps (`k8s/manifests/07-configmaps.yaml`)

#### Why Parametric URLs?

All URLs are configurable via environment variables for enterprise deployment flexibility:

- ✅ **No hardcoded URLs** in source code
- ✅ **Deploy anywhere**: Development, staging, production
- ✅ **Multi-tenant support**: Each instance can have its own URL
- ✅ **Easy migration**: Change deployment location without code changes

### HAProxy Cluster Configuration

Add new HAProxy clusters through the web interface or directly via API:

```json
{
  "name": "Production Cluster",
  "description": "Production HAProxy cluster",
  "host": "10.0.1.100",
  "port": 8404,
  "connection_type": "ssh",
  "ssh_username": "haproxy",
  "installation_type": "existing",
  "deployment_type": "cluster",
  "cluster_nodes": ["10.0.1.101", "10.0.1.102"],
  "keepalive_ip": "10.0.1.10"
}
```


## API Reference

### Authentication
```bash
# Login and get JWT token
POST /api/auth/login
Content-Type: application/json
{
  "username": "admin",
  "password": "admin123"
}

Response:
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}

# Get current user
GET /api/auth/me
Authorization: Bearer <access_token>
```

### Pool Management
```bash
# List all pools
GET /api/pools
Authorization: Bearer <token>

# Create new pool
POST /api/pools
{
  "name": "Production Pool",
  "description": "Production environment pool"
}

# Get pool details
GET /api/pools/{pool_id}
```

### Agent Management
```bash
# List all agents
GET /api/agents
Authorization: Bearer <token>

# Create agent and get installation script
POST /api/agents
{
  "name": "HAProxy-Prod-01",
  "pool_id": 1,
  "platform": "linux",  # linux or macos
  "architecture": "x86_64"  # x86_64 or arm64
}

# Agent polls for tasks (called by agent service)
GET /api/agents/{agent_id}/tasks
Authorization: Bearer <agent_token>

# Agent reports task completion
POST /api/agents/tasks/{task_id}/complete
{
  "status": "success",
  "message": "Configuration applied successfully",
  "logs": "HAProxy reloaded"
}

# Get agent status
GET /api/agents/{agent_id}/status
```

### Cluster Management
```bash
# List all clusters
GET /api/clusters
Authorization: Bearer <token>

# Create new cluster
POST /api/clusters
{
  "name": "Production Cluster",
  "description": "Production HAProxy cluster",
  "pool_id": 1
}

# Get cluster details
GET /api/clusters/{cluster_id}
```

### Statistics & Monitoring
```bash
# Get dashboard overview
GET /api/dashboard/overview

# Get HAProxy statistics
GET /api/haproxy/stats?cluster_id=1

# Get backend server status
GET /api/backends?cluster_id=1

# Get frontend configurations
GET /api/frontends?cluster_id=1
```

### ACME / Let's Encrypt API
```bash
# List ACME accounts
GET /api/letsencrypt/accounts
Authorization: Bearer <token>

# Register ACME account
POST /api/letsencrypt/accounts
{
  "email": "admin@example.com",
  "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
  "tos_agreed": true
}

# Deactivate ACME account
DELETE /api/letsencrypt/accounts/{account_id}

# Request certificate
POST /api/letsencrypt/certificates
{
  "domains": ["example.com", "www.example.com"],
  "account_id": 1,
  "cluster_ids": [1, 2]
}

# List ACME orders
GET /api/letsencrypt/orders

# Get order details
GET /api/letsencrypt/orders/{order_id}

# Retry/resume order
POST /api/letsencrypt/orders/{order_id}/retry

# Cancel order
DELETE /api/letsencrypt/orders/{order_id}

# Renew certificate (create new order)
POST /api/letsencrypt/orders/{order_id}/renew

# Revoke certificate
POST /api/letsencrypt/certificates/{cert_id}/revoke

# Import CA chain certificates
POST /api/letsencrypt/import-ca-chain

# Get renewal schedule
GET /api/letsencrypt/renewal-schedule

# Check ACME prerequisites (setup status)
GET /api/letsencrypt/prerequisites

# ACME Settings
GET /api/settings/acme
PUT /api/settings/acme
GET /api/settings/acme/test-connection?directory_url=https://...
```

### Configuration Management
```bash
# Get HAProxy configuration
GET /api/haproxy/config?cluster_id=1

# Update configuration
PUT /api/haproxy/config?cluster_id=1
Content-Type: text/plain

# Validate configuration
POST /api/haproxy/config/validate
```

## Development

### Project Structure

```
haproxy-openmanager/
├── backend/                          # FastAPI backend application
│   ├── main.py                      # Main application entry point
│   ├── config.py                    # Application configuration
│   ├── auth_middleware.py           # Authentication middleware
│   ├── agent_notifications.py       # Agent notification system
│   ├── database/                    # Database layer
│   │   ├── connection.py           # Database connection management
│   │   └── migrations.py           # Database migration scripts
│   ├── models/                      # SQLAlchemy ORM models
│   │   ├── user.py                 # User model
│   │   ├── cluster.py              # Cluster model
│   │   ├── agent.py                # Agent model
│   │   ├── frontend.py             # Frontend configuration model
│   │   ├── backend.py              # Backend configuration model
│   │   ├── ssl.py                  # SSL certificate model
│   │   └── waf.py                  # WAF rules model
│   ├── routers/                     # API route handlers
│   │   ├── auth.py                 # Authentication endpoints
│   │   ├── user.py                 # User management
│   │   ├── cluster.py              # Cluster management
│   │   ├── agent.py                # Agent management
│   │   ├── frontend.py             # Frontend configuration
│   │   ├── backend.py              # Backend configuration
│   │   ├── ssl.py                  # SSL certificate management
│   │   ├── letsencrypt.py          # ACME/Let's Encrypt endpoints
│   │   ├── settings.py             # System settings (incl. ACME config)
│   │   ├── waf.py                  # WAF rules management
│   │   ├── dashboard.py            # Dashboard statistics
│   │   ├── configuration.py        # Configuration viewer
│   │   └── security.py             # Security & token management
│   ├── services/                    # Business logic services
│   │   ├── haproxy_config.py       # HAProxy config generation
│   │   ├── acme_service.py         # ACME protocol client (RFC 8555)
│   │   └── dashboard_stats_service.py # Stats aggregation
│   ├── middleware/                  # Custom middleware
│   │   ├── activity_logger.py      # Activity logging
│   │   ├── error_handler.py        # Error handling
│   │   └── rate_limiter.py         # API rate limiting
│   ├── utils/                       # Utility functions
│   │   ├── auth.py                 # Authentication utilities
│   │   ├── haproxy_config_parser.py # Config parser
│   │   ├── haproxy_stats_parser.py  # Stats parser
│   │   ├── haproxy_validator.py     # Config validator
│   │   ├── ssl_parser.py            # SSL certificate parser
│   │   ├── activity_log.py          # Activity log utilities
│   │   ├── logging_config.py        # Logging configuration
│   │   └── agent_scripts/           # Agent installation scripts
│   │       ├── linux_install.sh     # Linux agent installer
│   │       └── macos_install.sh     # macOS agent installer
│   ├── tests/                       # Backend tests
│   │   ├── conftest.py             # Pytest configuration
│   │   └── test_*.py               # Test files
│   ├── requirements.txt             # Python dependencies
│   └── Dockerfile                   # Backend Docker image
│
├── frontend/                         # React.js frontend application
│   ├── src/
│   │   ├── components/              # React components
│   │   │   ├── Login.js            # Login page
│   │   │   ├── DashboardV2.js      # Main dashboard
│   │   │   ├── AgentManagement.js  # Agent management
│   │   │   ├── ClusterManagement.js # Cluster management
│   │   │   ├── PoolManagement.js   # Pool management
│   │   │   ├── FrontendManagement.js # Frontend config
│   │   │   ├── BackendServers.js   # Backend config
│   │   │   ├── SSLManagement.js    # SSL certificates
│   │   │   ├── ACMEAutomation.js   # ACME Auto SSL UI
│   │   │   ├── WAFManagement.js    # WAF rules
│   │   │   ├── ApplyManagement.js  # Apply changes
│   │   │   ├── Configuration.js    # Config viewer
│   │   │   ├── BulkConfigImport.js # Bulk import
│   │   │   ├── IPInventory.js     # IP inventory & search
│   │   │   ├── VersionHistory.js   # Version history
│   │   │   ├── UserManagement.js   # User management
│   │   │   ├── Security.js         # Security & tokens
│   │   │   ├── Settings.js         # Settings page
│   │   │   ├── EntitySyncStatus.js # Sync status
│   │   │   └── dashboard/          # Dashboard components
│   │   │       └── *.js            # Dashboard tabs & charts
│   │   ├── contexts/                # React contexts
│   │   │   ├── AuthContext.js      # Authentication context
│   │   │   ├── ClusterContext.js   # Cluster selection context
│   │   │   ├── ThemeContext.js     # Theme (dark/light mode)
│   │   │   └── ProgressContext.js  # Global progress indicator
│   │   ├── utils/                   # Utility functions
│   │   │   ├── api.js              # API client
│   │   │   ├── agentSync.js        # Agent sync utilities
│   │   │   ├── colors.js           # Color utilities
│   │   │   └── dashboardCache.js   # Dashboard caching
│   │   ├── App.js                   # Main app component
│   │   ├── App.css                  # Global styles
│   │   └── index.js                 # React entry point
│   ├── public/
│   │   └── index.html               # HTML template
│   ├── package.json                 # Node dependencies
│   └── Dockerfile                   # Frontend Docker image
│
├── docs/                             # Documentation
│   └── screenshots/                 # UI screenshots
│       ├── dashboard-overview.png
│       ├── frontend-management.png
│       ├── backend-configuration.png
│       ├── bulk-import.png
│       └── *.png                    # Other screenshots
│
├── k8s/                              # Kubernetes/OpenShift manifests
│   └── manifests/
│       ├── 00-namespace.yaml        # Namespace
│       ├── 01-service-accounts.yaml # Service accounts
│       ├── 02-rbac.yaml             # RBAC roles
│       ├── 03-secrets.yaml          # Secrets
│       ├── 04-storage.yaml          # Persistent volumes
│       ├── 05-postgres.yaml         # PostgreSQL deployment
│       ├── 06-redis.yaml            # Redis deployment
│       ├── 07-configmaps.yaml       # ConfigMaps
│       ├── 08-backend.yaml          # Backend deployment
│       ├── 09-frontend.yaml         # Frontend deployment
│       ├── 10-nginx.yaml            # Nginx deployment
│       ├── 11-routes.yaml           # OpenShift routes
│       ├── 12-ingress.yaml          # Kubernetes ingress
│       ├── 13-hpa.yaml              # Horizontal Pod Autoscaler
│       ├── deploy.sh                # Deployment script
│       └── cleanup.sh               # Cleanup script
│
├── nginx/                            # Nginx reverse proxy
│   └── nginx.conf                   # Nginx configuration
│
├── haproxy/                          # Sample HAProxy configs
│   ├── haproxy.cfg                  # Sample configuration
│   ├── haproxy-simple.cfg           # Simple example
│   ├── haproxy-remote1.cfg          # Remote example 1
│   └── haproxy-remote2.cfg          # Remote example 2
│
├── scripts/                          # Utility scripts
│   ├── check-agent-logs.sh          # Check agent logs
│   ├── check-agent-stats.sh         # Check agent stats
│   ├── check-haproxy-stats-socket.sh # Check stats socket
│   ├── cleanup-cluster-entities.sh  # Cleanup entities
│   ├── cleanup-soft-deleted.sh      # Cleanup soft deletes
│   ├── update-agent-version.sh      # Update agent version
│   └── test-stats-parser.py         # Test stats parser
│
├── utils/                            # Uninstall utilities
│   ├── uninstall-agent-linux.sh     # Linux uninstaller
│   └── uninstall-agent-macos.sh     # macOS uninstaller
│
├── docker-compose.yml                # Docker Compose configuration
├── docker-compose.localtest.yml      # Local development/testing overrides
├── docker-compose.test.yml           # Test environment
├── version.json                      # Application version metadata
├── build-images.sh                   # Build Docker images
├── pytest.ini                        # Pytest configuration
├── README.md                         # This file
├── CONFIG.md                         # Configuration documentation
├── TESTING.md                        # Testing documentation
├── UPGRADE_GUIDE.md                  # Upgrade guide
└── LICENSE                           # MIT License
```

### Adding New Features

1. **Backend API Endpoints**: Add to `backend/main.py`
2. **Frontend Components**: Add to `frontend/src/components/`
3. **Database Changes**: Update `backend/init.sql` and create migration
4. **HAProxy Features**: Extend `backend/haproxy_client.py`


## Troubleshooting

### Common Issues

#### 1. Connection Refused to HAProxy
```bash
# Check if HAProxy is running
curl http://localhost:8404/stats

# Check HAProxy configuration
docker exec haproxy-instance haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg

# View HAProxy logs
docker logs haproxy-instance
```

#### 2. Database Connection Issues
```bash
# Check database status
docker exec haproxy-openmanager-db pg_isready -U haproxy_user

# Check database logs
docker logs haproxy-openmanager-db

# Reset database
docker-compose down
docker volume rm haproxy-openmanager_postgres_data
docker-compose up -d
```

#### 3. SSH Connection Issues
```bash
# Test SSH connectivity
ssh -i ~/.ssh/id_rsa user@remote-server

# Check SSH key permissions
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub

# Verify SSH service
systemctl status ssh  # on remote server
```

#### 4. Frontend Build Issues
```bash
# Clear node modules and reinstall
cd frontend
rm -rf node_modules package-lock.json
npm install

# Check for port conflicts
lsof -i :3000
```

#### 5. Phantom Pending Changes / Orphan Config Versions

**Symptom:** Apply Management shows pending changes that can't be applied or rejected, or shows entities from wrong cluster.

**Root Cause:** Orphan config versions - versions that reference entities from different clusters or deleted entities (entity ID reuse bug).

**Solution (Automatic):** 
- **Modern versions (v1.1.0+):** Orphan versions are automatically detected and cleaned when you:
  - Open Apply Management page (orphans filtered out from display)
  - Click "Apply Changes" (orphans deleted before apply)
  - Click "Reject All" (orphans deleted before reject)

**Manual Cleanup (if needed):**
```sql
-- Connect to database
kubectl exec -it <postgres-pod> -- psql -U haproxy_user -d haproxy_openmanager

-- Find orphan versions (example for cluster_id=2)
SELECT cv.id, cv.version_name, cv.cluster_id,
       CASE 
         WHEN cv.version_name ~ 'backend-[0-9]+-' 
         THEN (SELECT cluster_id FROM backends WHERE id = SUBSTRING(cv.version_name FROM 'backend-([0-9]+)-')::int)
         ELSE NULL
       END as entity_cluster
FROM config_versions cv
WHERE cv.cluster_id = 2 AND cv.status = 'PENDING';

-- Delete orphan versions (where entity_cluster != 2 or NULL)
DELETE FROM config_versions 
WHERE id IN (SELECT id FROM ...);
```

**Prevention:**
- Always delete backends/frontends in the correct cluster
- Use Apply Changes workflow (don't skip)
- Keep backend/frontend names unique across clusters

#### 6. Apply Changes Stuck - HAProxy Configuration Validation Errors

**Symptom:** Pending changes in Apply Management remain stuck and are not applied by agents, or agents report configuration failures.

**Root Cause:** The generated HAProxy configuration has syntax errors or validation issues that prevent HAProxy from accepting the new config.

**Diagnosis - Check HAProxy Validation on Agent Server:**

```bash
# SSH to the agent server where changes are stuck
ssh user@agent-server

# Check agent logs for validation errors
sudo tail -f /var/log/haproxy-agent/agent.log

# The agent writes the new config to /tmp/haproxy-new-config.cfg before applying
# Manually validate the configuration file
sudo /usr/sbin/haproxy -c -f /tmp/haproxy-new-config.cfg

# If validation fails, you'll see detailed error messages like:
# [ALERT] parsing [/tmp/haproxy-new-config.cfg:45] : 'bind' : missing address, port or path
# [ALERT] parsing [/tmp/haproxy-new-config.cfg:78] : unknown keyword 'ssl-certificate'
```

**Common Validation Issues:**

1. **Invalid SSL Certificate Reference:**
   ```
   [ALERT] 'bind' : unable to load SSL certificate '/etc/haproxy/certs/missing-cert.pem'
   ```
   - Solution: Ensure SSL certificate was uploaded and synced to the agent
   - Check: `ls -la /etc/haproxy/certs/`

2. **Backend Server Not Defined:**
   ```
   [ALERT] 'use_backend' : unable to find required use_backend: 'backend-name'
   ```
   - Solution: Ensure backend exists and is defined before the frontend that uses it

3. **Invalid ACL Syntax:**
   ```
   [ALERT] parsing [config:42] : error detected while parsing ACL 'acl-name'
   ```
   - Solution: Fix ACL syntax in Frontend Management

4. **Port Already in Use:**
   ```
   [ALERT] Starting frontend GLOBAL: cannot bind socket
   ```
   - Solution: Check if another service is using the same port

**Recovery Steps:**

1. **View Generated Config:**
   ```bash
   # On agent server - view the new config that failed validation
   sudo cat /tmp/haproxy-new-config.cfg
   
   # Compare with current working config
   sudo cat /etc/haproxy/haproxy.cfg
   ```

2. **Check Agent Logs:**
   ```bash
   # See full error context and rollback messages
   sudo tail -100 /var/log/haproxy-agent/agent.log | grep -A 10 "validation failed"
   ```

3. **Fix Issues in UI:**
   - Go to Apply Management → View pending changes
   - Identify the problematic entity (frontend, backend, SSL certificate)
   - Edit or delete the problematic entity
   - Reject current pending changes
   - Re-apply after fixing

4. **Emergency Rollback:**
   ```bash
   # On agent server - agent automatically keeps backup
   sudo ls -la /etc/haproxy/haproxy.cfg.backup*
   
   # Manually restore if needed (agent usually does this automatically on validation failure)
   sudo cp /etc/haproxy/haproxy.cfg.backup.TIMESTAMP /etc/haproxy/haproxy.cfg
   sudo systemctl reload haproxy
   ```

**Prevention:**
- Always test configurations incrementally (don't make too many changes at once)
- Use Configuration Viewer to preview generated HAProxy config before applying
- Ensure SSL certificates are uploaded before creating frontends that use them
- Keep backend names unique and descriptive
- Test ACL syntax before saving

#### 7. ACME Certificate Issues

**Symptom:** ACME certificate request stuck in "pending" or challenge validation fails.

**Diagnosis:**
```bash
# Check backend logs for ACME errors
kubectl logs deployment/backend -n haproxy-openmanager | grep "ACME"

# Verify ACME challenge endpoint is accessible through the managed HAProxy instance
curl http://your-domain/.well-known/acme-challenge/test

# Check if ACME is enabled on the cluster
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/clusters | jq '.[].acme_enabled'
```

**Common Issues:**

1. **Challenge validation failed**: Ensure HAProxy cluster has `acme_enabled=true` and HTTP-mode frontends are configured
2. **DNS not pointing correctly**: The domain must resolve to the IP of the HAProxy instance(s) managed by the cluster's agents
3. **Rate limited**: Let's Encrypt has rate limits; use staging mode (`acme.staging_mode=true`) for testing
4. **Stuck orders**: Orders stuck > 24h are logged as warnings; check backend logs
5. **Firewall blocking**: Port 80 must be open for HTTP-01 challenges from the CA

**ACME Auto-Renewal Not Working:**
```bash
# Check if auto-renewal is enabled
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/settings/acme

# Verify background task is running (check backend logs)
kubectl logs deployment/backend -n haproxy-openmanager | grep "ACME RENEWAL"
```

Settings to verify:
- `acme.auto_renew_enabled` must be `true`
- `acme.renew_before_days` controls when renewal triggers (default: 30 days)
- Certificate must have `auto_renew=true` and `source=letsencrypt`

### Debug Mode

Enable debug logging:

```bash
# Backend debug mode
export DEBUG=True
export LOG_LEVEL=DEBUG

# Frontend development mode
export NODE_ENV=development
export REACT_APP_DEBUG=true
```

### Log Locations

```bash
# Application logs
docker logs haproxy-openmanager-backend
docker logs haproxy-openmanager-frontend

# HAProxy logs
docker logs haproxy-instance

# Database logs
docker logs haproxy-openmanager-db

# System logs (on remote servers)
journalctl -u haproxy
journalctl -u keepalived
```


## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### How to Contribute

1. **Report Bugs**: Open an issue with detailed reproduction steps
2. **Suggest Features**: Share your ideas for new features or improvements
3. **Submit PRs**: Fix bugs, add features, or improve documentation
4. **Improve Docs**: Help make the documentation clearer and more comprehensive
5. **Share**: Star the project and share it with others

### Development Guidelines

- Follow PEP 8 for Python code
- Use ESLint/Prettier for JavaScript code
- Add tests for new features
- Update documentation for API changes
- Ensure Docker builds work correctly
- Follow existing code style and conventions
- Write clear commit messages
- Keep PRs focused on a single change

## Use Cases

1. **Enterprise HAProxy Management**: Manage multiple HAProxy clusters across different environments
2. **DevOps Automation**: Automated configuration deployment with version control
3. **Multi-Tenant Setups**: Separate pools and clusters for different teams/projects
4. **Monitoring & Analytics**: Real-time metrics and performance tracking
5. **Security Management**: Centralized SSL certificate and WAF rule management


## License

This project is licensed under the **GNU Affero General Public License v3.0 (or later)** — see the [LICENSE](LICENSE) file for the full text.

A short summary:

- You are free to use, modify, and distribute this software.
- If you run a modified version as a network service (e.g., SaaS), you must make the modified source available to its users (AGPL §13).
- Any redistribution or derivative work must remain under AGPL-3.0-or-later.


## Author

**Taylan Bakırcıoğlu**  
Burgan Bank - DevOps / Product Group Manager  
LinkedIn: [linkedin.com/in/taylanbakircioglu](https://www.linkedin.com/in/taylanbakircioglu/)

Developed with ❤️ for the HAProxy community


## Support

- **Documentation**: This README and inline code documentation
- **Issues**: [GitHub Issues](https://github.com/taylanbakircioglu/haproxy-openmanager/issues)
- **Pull Requests**: Contributions are welcome!


## Related Projects

- [HAProxy](https://www.haproxy.org/) - The load balancer being managed
- [FastAPI](https://fastapi.tiangolo.com/) - Backend framework
- [React.js](https://reactjs.org/) - Frontend framework
- [Ant Design](https://ant.design/) - UI component library

---

## Release Notes

- **v1.8.2** (2026-06-25) — **ACME nonce fix** (Issue #35 follow-up): the ACME client now scopes the anti-replay nonce **per certificate authority** so a nonce issued by one CA is never sent to another. This fixes ZeroSSL/Google account registration failing with `malformed: The Replay Nonce could not be base64url-decoded` (the client previously shared one nonce across CAs and only auto-retried on `badNonce`). Account registration now always uses a fresh nonce from the target CA, and the retry covers this case too. Backend-only; HTTP-01 and Let's Encrypt are unaffected.
- **v1.8.1** (2026-06-24) — **ACME DNS-01 fixes** (Issue #35 follow-up): Cloudflare API tokens are now sanitized so a pasted token with quotes/spaces no longer fails with "Invalid request headers"; ZeroSSL/Google **External Account Binding (EAB)** can be entered per-account in the register dialog and EAB-required failures show a clear message; and **Apply Management** now categorizes cluster ACME enable/disable changes under their own "ACME Challenge Routing" section and **Apply/Reject All** correctly process them (previously "Rejected 0 HA/VIP change(s)"), consistent with every other entity. Fully backward compatible.
- **v1.8.0** (2026-06-23) — **ACME DNS-01 challenge support** (Issue #35): Auto SSL can now validate via a **DNS TXT record** (`_acme-challenge.<domain>`) instead of HTTP-01 on port 80, enabling certificates for **internal/isolated clusters with no public ingress** and **wildcard** certificates (`*.example.com`). Pluggable **per-account DNS provider** (Manual + Cloudflare to start; credentials verified on save and **encrypted at rest**, never returned by the API or logged), the same **PENDING → APPLIED** pipeline, a **bounded automatic retry** on propagation lag, and a **DNS-01 event timeline** in the order detail. **Opt-in** via Settings → ACME (global switch, default off); **HTTP-01 is byte-for-byte unchanged**, with **zero agent or rendered-config changes**. Manual DNS-01 certificates cannot auto-renew unattended; the UI states this and disables auto-renew for them.
- **v1.7.8** (2026-06-07) — HA / VIP apply progress now shows **per-node** convergence: a multi-node VIP's apply popup reads "Syncing HA/VIP… 1/2 node(s) converged" (matching the HA/VIP table) instead of a coarse per-change count. Frontend-only.
- **v1.7.7** (2026-06-07) — HA / VIP apply-progress consistency: applying a VIP change (or approving a delete) used to flash the progress popup green instantly while the HA/VIP page still showed `SYNCING (0/1)` for a couple of minutes. The popup now **keeps showing "Syncing HA/VIP… X/Y node(s) converged"** until each member node reports the VIP `ACTIVE` (create/edit) or fully torn down (delete) — exactly like the HAProxy agent-sync widget — then completes green. It's a fire-and-forget background poll (the Apply button is released immediately), bounded at ~5 min so an offline node can't spin forever (then it completes with an informational "still converging — track on the HA/VIP page"). Frontend-only; no backend/agent/schema change.
- **v1.7.6** (2026-06-07) — HA / VIP UX + accuracy polish: (1) the on-prem/L2 cloud caveat is now a **subtle, collapsed-by-default "Network requirements" info link** instead of a prominent yellow warning. (2) The delete dialog is simplified — deletion is **always a graceful teardown** (stop & disable keepalived, remove our config, release the VIP, keep the package); the confusing "also uninstall the package" checkbox was removed (it was a no-op on any node whose keepalived predates the install marker, and package removal is better handled as a deliberate node-decommission step — the `purge_package` API remains for that). (3) The agent now reports keepalived **FAULT** state (e.g. when the chosen interface has no usable IPv4) instead of misreporting it as BACKUP, so a misconfigured VIP shows red/FAULT in the UI. (1)+(2) are frontend-only; (3) is an additive agent-script change — push it via **Agent Script Management → Reset to Defaults**, then **Upgrade**.
- **v1.7.5** (2026-06-07) — HA / VIP "View Change" fix: editing a VIP (e.g. priority + virtual IP) now shows a **real line diff — only the lines that actually changed** — in Apply Management's View Change, instead of rendering the whole `keepalived.conf` as "added". Also fixes a doubled `+ +` prefix (the VIP diff now stores lines without a +/- prefix, matching the standard config diff). View-only; no schema, agent, apply, or render change.
- **v1.7.4** (2026-06-06) — HAProxy config-generator robustness fix: a frontend that uses a stick counter (`track-sc<N>` or an `sc_*_rate(...)` fetch, e.g. a rate-limit `http-request deny if { sc_http_req_rate(0) gt N }`) but declares **no `stick-table`** caused HAProxy to fatally reject the whole cluster config with *"table '&lt;frontend&gt;' used but not configured"*. This happened where rate-limit directives had been baked into a frontend's stored `request_headers`/`options` (by an older version or a config import). The generator now **auto-injects a default `stick-table`** in that case. Purely additive — it only fires when a counter is used and no table exists (a config that was already invalid), so frontends that already declare a stick-table or don't rate-limit are byte-unchanged.
- **v1.7.3** (2026-06-06) — HA / VIP backward-compat fix: the v1.7.2 deletion-tracking list now only resurfaces VIPs deleted through the **new approval flow** (gated on `last_config_status='APPLIED'`), so a VIP soft-deleted under an earlier version's immediate-delete is no longer shown as `DELETING`. Display-only; no schema or agent change.
- **v1.7.2** (2026-06-06) — HA / VIP safety & visibility follow-up:
  - **Approval-gated deletion (safety).** Deleting a *running* VIP from the UI no longer takes effect immediately — it is **staged for Apply Management** and the VIP **keeps running, untouched**, until you **Approve** it (Reject keeps it). The agent is told to tear keepalived down **only after approval**, so a misclick can never tear down a production VIP — an agent never deletes without an explicit human approval. The deletion is trackable through the standard Apply popup and a **DELETING** status on the HA/VIP tab. (A VIP that was never applied is removed at once — nothing is running to tear down.)
  - **Diagnostics view** — a per-VIP search-icon modal showing each node's keepalived deploy state, the message it reported, last-ack time and live VRRP state (handy while a fresh install is SYNCING, ~30s), plus the exact node-side log commands.
  - **Opt-in package uninstall** — the safe default keeps the keepalived package (stop & disable, remove our config, release the VIP); a default-off checkbox additionally uninstalls the package **only on nodes where OpenManager installed it** (an admin's pre-existing keepalived is never removed, tracked via an install marker).
  - Adds additive `purge_on_teardown` + `pending_delete` columns; `SCHEMA_VERSION` 5 → 7 (idempotent; existing data/passwords unaffected). Agent script updated — push it via **Agent Script Management → Reset to Defaults**, then **Upgrade** agents.
- **v1.7.1** (2026-06-06) — HA / VIP follow-up: a VIP can now be created on a **single node** — a Keepalived-managed floating IP **without** failover (e.g. a one-box HAProxy that wants a stable address, or before a second node is added). Add a second node anytime for real VRRP failover. A single-node VIP renders a clean **multicast** config (no bare `unicast_src_ip`, which `keepalived -t` rejects); multi-node behaviour is unchanged. The Create-VIP form now auto-selects the first chosen node as **MASTER** and shows an in-UI notice that, on Apply, Keepalived is **installed automatically from the node's OS package repositories** (apt/dnf/yum/zypper/apk — the node must reach its repos / an internal mirror), while a hand-managed Keepalived is still left untouched. No schema change.
- **v1.7.0** (2026-06-05) — Feature (Issue #27): **HA / VIP (Keepalived) management** from the UI. A new "HA / VIP" tab lets you create a virtual IP, pick a per-node interface, and select which pool nodes participate (with MASTER/BACKUP roles + priorities); on Apply, the agent installs & configures Keepalived (unicast VRRP, cloud-safe default) with a HAProxy health-check so the VIP fails over automatically when HAProxy drops, and the tab shows live MASTER/BACKUP per node. Fully **opt-in and backward compatible** — nodes/clusters without a VIP are untouched, and a node already running a hand-managed Keepalived is detected and never overwritten (reported as "externally managed"). Pending VIP changes can be **Rejected** to fully restore the last applied state. Keepalived is installed across the major distros (Debian/Ubuntu, RHEL/CentOS/Alma/Rocky, Fedora, SUSE/openSUSE, Alpine), and live MASTER/BACKUP detection works across distros/init systems (journald + log files + portable interface-based detection). On-prem/L2 scope (VRRP); a clear in-UI notice covers the cloud caveat. Adds two new tables (`vip_instances`, `vip_members`) — `SCHEMA_VERSION` bumps to 3 (idempotent re-run; existing data and passwords unaffected). A new "HA / VIP" tab lets you create a virtual IP, pick a per-node interface, and select which pool nodes participate (with MASTER/BACKUP roles + priorities); on Apply, the agent installs & configures Keepalived (unicast VRRP, cloud-safe default) with a HAProxy health-check so the VIP fails over automatically when HAProxy drops, and the tab shows live MASTER/BACKUP per node. Fully **opt-in and backward compatible** — nodes/clusters without a VIP are untouched, and a node already running a hand-managed Keepalived is detected and never overwritten (reported as "externally managed"). Pending VIP changes can be **Rejected** to fully restore the last applied state. Keepalived is installed across the major distros (Debian/Ubuntu, RHEL/CentOS/Alma/Rocky, Fedora, SUSE/openSUSE, Alpine), and live MASTER/BACKUP detection works across distros/init systems (journald + log files + portable interface-based detection). On-prem/L2 scope (VRRP); a clear in-UI notice covers the cloud caveat. Adds two new tables (`vip_instances`, `vip_members`) — `SCHEMA_VERSION` bumps to 3 (idempotent re-run; existing data and passwords unaffected).
- **v1.6.5** (2026-06-02) — Security: re-pinned the bundled nginx reverse-proxy image to `nginx:1.31.1-alpine` (mainline patched release) for the nginx "poolslip" advisory (fixed in mainline 1.31.1+ / stable 1.30.2+). Supersedes the v1.6.4 stable pin. No config, schema, or behavior changes.
- **v1.6.4** (2026-06-02) — Security: pinned the bundled nginx reverse-proxy image to a patched stable release (`nginx:1.30.2-alpine`) for the nginx "poolslip" advisory (mainline ≤ 1.31.0 affected; fixed in stable 1.30.2+). The product's nginx config uses no `rewrite` capture groups, so the config-level mitigation did not apply — the fix is the version pin. No config, schema, or behavior changes.
- **v1.6.3** (2026-06-01) — Bugfix: a backend **server** toggled OFF (`is_active=false`) disappeared from the UI with no way to reactivate it. `GET /api/backends` now honors `include_inactive` for servers (previously only backends), so disabled servers stay visible with an OFF switch + "Inactive" tag and can be re-enabled; soft-deleted (pending-delete) servers stay hidden. A Reject of a server toggle now correctly rolls back `is_active` (entity snapshot). Startup migrations are hardened for multiple replicas / rolling deploys (advisory lock + schema-version gate, so an already-current schema isn't re-migrated under a serving peer's load). Version is reported consistently across all layers. No schema changes; config generation unchanged (disabled servers stay commented out).
- **v1.6.2** (2026-05-30) — Bugfixes: (1) agents (which authenticate with their `X-API-Key` token) could not reach `GET /api/clusters` / `/api/clusters/{id}` after the v1.5.x cluster-read hardening, breaking agent assignment ("401: Authorization header missing"); these endpoints now accept either a user JWT or an agent token (anonymous access is still rejected). (2) The uninstall-script generator returned 400 for macOS agents (which report platform `darwin`); it now normalizes the platform the same way the install generator does. No UI or schema changes.
- **v1.6.1** (2026-05-21) — Security patch: bump `axios` to 1.16.x (prototype-pollution hardening, header-injection fix, keep-alive memory leak fix) and `fast-uri` to 3.1.2 (GHSA-v39h-62p7-jpjc). No functional changes.

For full release notes and the list of features delivered in each version (v1.5.x Site Wizard + ACME Diagnostic Panel, v1.4.0 ACME stability + enterprise audit, v1.3.0, ...) see the [GitHub Releases](https://github.com/taylanbakircioglu/haproxy-openmanager/releases) page.

---

**Made with ❤️ for the HAProxy community**
