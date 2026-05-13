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
   - [Backend Servers](#backend-servers---server-pool-management)
   - [Configuration](#configuration---haproxy-config-file-management)
   - [Apply Management](#apply-management---change-tracking--deployment)
   - [SSL Certificates](#ssl-certificates---centralized-tlsssl-certificate-management)
   - [ACME Auto SSL](#acme-auto-ssl---automated-certificate-management)
   - [WAF Management](#waf-management---web-application-firewall)
   - [IP Inventory](#ip-inventory---cross-cluster-ip-search--discovery)
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
✅ **Bulk Config Import** - Import existing `haproxy.cfg` files with smart SSL auto-assignment  
✅ **Version Control & Rollback** - Every change versioned with one-click restore capability  
✅ **Real-Time Monitoring** - Live stats, health checks, and performance dashboards  
✅ **SSL Certificate Management** - Centralized SSL with expiration tracking  
✅ **ACME Auto SSL (Let's Encrypt)** - Automated certificate issuance, renewal, and deployment via ACME protocol  
✅ **WAF Rules** - Web Application Firewall management and deployment  
✅ **Agent Script Versioning** - Update agents via UI (Monaco editor) with auto-upgrade  
✅ **Token-Based Agent Auth** - Secure token management with revoke/renew  
✅ **IP Inventory** - Cross-cluster IP search to identify agents, VIPs, and backend servers by IP  
✅ **Keepalived VRRP Detection** - Automatic MASTER/BACKUP state and VIP detection from keepalived  
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
- **ACME Account Management**: Register, view, and deactivate ACME accounts from the UI
- **Staging Mode**: Test certificate issuance with Let's Encrypt staging environment before production
- **Custom Staging Endpoint** *(v1.4.0)*: Optional `staging_url_override` setting lets you point staging mode at a private ACME test CA (e.g. Pebble) without touching the production directory URL
- **External Account Binding (EAB)**: Support for CAs that require EAB (ZeroSSL, Google Trust Services)
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

### User Management - Access Control & Authentication
- **User Accounts**: Create, edit, and manage user accounts
- **Role-based Access**: Admin, user, and custom role definitions
- **Permission System**: Granular permissions for different system functions
- **User Activity**: Login history and user action audit logs
- **Password Management**: Secure password policies and reset functionality
- **Session Management**: Active session monitoring and force logout
- **API Keys**: User API key generation and management
- **Role Assignment**: Dynamic role assignment and permission updates

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
```bash
# API Endpoint (auto-detected if empty)
# Leave empty in production to use same-origin (window.location)
REACT_APP_API_URL=""  # For development: "http://localhost:8000"

# Environment
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

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


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

### v1.5.0 — ACME Diagnostics & Site Wizard

#### Highlights

- **Issue #13: ACME Diagnostic Panel.** From the ACME Automation list, click the new `Diagnose` button (or the order's status tag) to launch a Modal with three Tabs:
  1. **Pre-flight Checks** — DNS resolution, port-80 reachability, HAProxy routing, ACME account status, agent health. Each check has its own `Re-run` button.
  2. **Event Log** — Merged timeline of typed `acme_order_events` rows (added in v1.5.0) and correlated `user_activity_logs` entries; auto-tails every 5s while the order is in `pending`/`processing`.
  3. **Raw Error** — Humanized error display covering 11+ RFC8555 problem types (`badNonce`, `caa`, `connection`, `rateLimited`, `unauthorized`, ...) with full backwards compatibility for legacy plain-string `error_detail`.
- **Issue #14: New Site Setup Wizard.** A single guided flow (`/sites/new`) that creates a Backend + Servers + HTTP Frontend (and optional HTTPS Frontend) in one atomic transaction. SSL choice supports four modes:
  - `acme` — defers HTTPS frontend creation to a deferred `post_completion_actions` block on a wizard-staged ACME order; the order is promoted to a real LE call only after the agent confirms the gating `bulk-site-create-{ts}` config version (legacy `bulk-proxied-host-create-{ts}` is still recognised by the reject path for historical APPLIED versions).
  - `upload` — uploads PEM cert+key in the same transaction.
  - `existing` — reuses an admin-uploaded cert and ensures the cluster junction is set.
  - `none` — HTTP-only host.
  The wizard ships with the same visual ACL rule builder used by the standalone Frontend Management page (Routing & ACLs section on the Frontend step) so operators define `acl` / `use_backend` / `redirect` rules from cluster-scoped backend dropdowns instead of free-text HAProxy directives. Drafts persist for 30 days with PEM material stripped at rest. Reject of the wizard's PENDING version cleanly rolls back ALL wizard entities (backends, servers, frontend(s), SSL row if any, AND the wizard-staged `letsencrypt_orders` row).

#### Migration Release Notes

This release adds **idempotent** migrations only — no destructive schema changes:

- New columns on `letsencrypt_orders`:
  - `post_completion_actions JSONB` (deferred actions for wizard ACME mode)
  - `wizard_staged_until TIMESTAMPTZ` (24h timeout for wizard-staged orders)
  - `pending_apply_version_name VARCHAR(255)` + partial index `WHERE status='wizard_staged'`
  - `created_by INTEGER REFERENCES users(id) ON DELETE SET NULL`
- New tables: `acme_order_events` (typed event log, 90d retention), `wizard_drafts` (30d retention).
- New composite index `idx_user_activity_logs_user_action_time` for the per-user-per-minute rate-limit COUNT(*) used by both new features.

The `letsencrypt_orders.status` column has no CHECK constraint; the new `wizard_staged` value coexists with all existing statuses (`pending`, `ready`, `processing`, `valid`, `invalid`, ...).

The reject path's force-delete fallback now also covers `entity_type='letsencrypt_order'` snapshots so wizard-staged ACME orders are removed when their parent PENDING version is rejected.

#### Rollback Considerations

- **Forward compatibility (v1.5.0 → future).** All new columns/tables are additive; older code paths that do not know about them are unaffected.
- **Backward rollback (v1.5.0 → v1.4.0).** The new columns/tables remain in the database harmlessly; v1.4.0 simply ignores them. Wizard-staged ACME orders that were never promoted to `pending` will not progress on v1.4.0 (the v1.4.0 background task does not select `status='wizard_staged'`); admins can either:
  1. Wait for the 24h `wizard_staged_until` timeout to fire (v1.5.0 only) — only relevant if rolling back temporarily, OR
  2. Manually `DELETE FROM letsencrypt_orders WHERE status='wizard_staged'` and re-run the wizard once you re-deploy v1.5.0.
- **Wizard ACME failure scenarios.** If the agent never confirms the gating config version (e.g. agent down), the wizard-staged ACME order will time out and transition to `status='invalid'` after 24h with `error_detail='wizard staged timeout (>24h with no agent confirm)'` — surfaced in the new Diagnostic Panel.
- **Drafts.** PEM material is server-side stripped from `wizard_drafts.payload`; rolling back will not leak keys at rest.

#### v1.5.x — Site Wizard module rename + ACL UX parity

A non-breaking follow-up to v1.5.0 that retires the internal "Proxied Host" namespace in favour of "Site" everywhere it used to leak into operators' workflow:

- **Module file rename.** `backend/routers/proxied_host.py` and `backend/models/proxied_host.py` are now `site_wizard.py`. The Pydantic class `ProxiedHostCreate` (and its sibling `ProxiedHostPreflightAcme` / `ProxiedHostDraftCreate`) was renamed to `SiteCreate` etc. with a module-level alias `ProxiedHostCreate = SiteCreate` so existing imports keep working.
- **API URL prefix rename.** The wizard now mounts at `/api/sites/*` (canonical). The legacy `/api/proxied-hosts/*` slug is preserved as a hidden `308 Permanent Redirect` alias on `main.py`, so external integrators keep working through the redirect during the transition window. The frontend axios calls all target `/api/sites/*` directly.
- **Audit-log version-name rename.** Wizard-applied versions now carry the prefix `bulk-site-create-{ts}`. The cluster reject path on `cluster.py` recognises BOTH the new prefix and the legacy `bulk-proxied-host-create-{ts}` so historical APPLIED versions still clean up.
- **Activity-log action + resource_type.** The wizard's explicit `log_user_activity` call now writes `action='wizard_create_site'` and `resource_type='site'` (was `wizard_create_proxied_host` / `proxied_host`). Older audit rows already in the database keep their pre-rename strings.
- **Rate-limit dual-name aliasing.** The wizard's per-user-per-minute rate-limit (`COUNT(*)` over `user_activity_logs`) now passes `ANY($::text[])` so it counts BOTH the canonical `site_*` action_name and its legacy `proxied_host_*` companion. A deploy that lands mid-minute cannot reset the quota, and the limit cannot be bypassed by an attacker who picks the legacy name.
- **DB schema rebrand (Phase I).** The `wizard_drafts.wizard_type` column's schema-level `DEFAULT` flipped from `'proxied_host'` to `'site'`. New rows land with the canonical value via an explicit `INSERT … VALUES ($1, 'site', …)`. The list / cap / cluster-delete-purge queries all filter on `wizard_type IN ('site', 'proxied_host')` so pre-rebrand drafts owned by the same user remain visible and remain rejectable. **Existing rows are NOT row-rewritten** — the migration is a metadata-only `ALTER TABLE … SET DEFAULT 'site'` that takes a non-blocking lock and is idempotent.
- **Wizard ACL UX parity.** The Frontend step now embeds the same `ACLRuleBuilder` component used by the Frontend Management page, with cluster-scoped existing backends populated automatically and the wizard's brand-new backend surfaced as a virtual entry in the use_backend dropdown. Drafts persist the three rule arrays so a resumed draft hydrates with the same routing config.

Backward compatibility is preserved at every layer: the DB-level `wizard_drafts.wizard_type='proxied_host'` enum value (still valid for pre-rebrand rows), the `LEGACY_WIZARD_DRAFT_SESSION_KEY` browser sessionStorage key, frontend route aliases (`/proxied-hosts/new`, `/proxied-hosts/drafts`), and the legacy `/api/proxied-hosts/*` URL all keep working.

##### Phase J — UI mount-time race fix ("clusters don't appear after deploy")

**Reported symptom.** After every rolling deploy, operators saw the cluster
selector empty for "a long time" — closing and re-opening the browser did
not help, but waiting ~30s did. The user diagnosed it as a UI problem.

**Root cause.** A React mount-time race between `<AuthProvider>` (parent)
and `<ClusterProvider>` (child). React's useEffect commit phase fires
CHILD effects before PARENT effects, so `ClusterProvider.useEffect` —
which dispatches the very first `axios.get('/api/clusters')` — ran BEFORE
`AuthProvider.useEffect` set `axios.defaults.headers.common['Authorization']`.
The first request went out un-authenticated → backend returned 401 →
ClusterContext's `catch` block silently committed `clusters=[]`. The
operator-visible UI rendered "no clusters" until the 30-second
auto-refresh interval re-fired the request, by which point auth had
hydrated and the call succeeded. Restarting the browser kept hitting the
same race because localStorage carried the token but the useEffect
ordering was identical.

**Fix (3 layers of defence).**

1. **`src/index.js` module-level axios bootstrap.** Runs before
   `<App />` is rendered, so no React tree (and therefore no useEffect)
   can fire before it. Synchronously seeds
   `axios.defaults.headers.common['Authorization']` from localStorage
   AND installs an `axios.interceptors.request` that re-reads the token
   on every outbound request. The interceptor is the belt-and-suspenders
   defence — it cannot be raced by mount ordering and survives any
   future code path that mutates `axios.defaults`.
2. **`AuthContext` synchronous useState lazy initialisers.** The
   `_hydrateAuthSync` helper runs during the AuthProvider RENDER phase,
   which precedes ANY child useEffect. It reads localStorage and seeds
   `loading=false`, `isAuthenticated=true`, and the user object —
   eliminating the post-mount async hydration that produced the race.
3. **`ClusterContext` auth-gate + exponential-backoff retry.** The
   first fetch is gated on `isAuthenticated && !authLoading`, and a
   transient 5xx / network failure now triggers up to 4 fast retries
   (1s, 2s, 4s, 8s — total ~15s) instead of immediately blanking the
   cluster list and depending on the 30s auto-refresh interval. 401/403
   intentionally do NOT retry (re-auth is the user's job). The previous
   cluster list is preserved on transient hiccups so periodic refreshes
   no longer flash an "empty state".

**Verification.** 22 static-source pin tests in
`backend/tests/test_frontend_auth_bootstrap_phase_j.py` cover all three
layers (bootstrap order, AuthContext lazy init, ClusterContext retry +
auth-gate) plus the six audit-loop hotfixes below. 590 backend tests
pass; frontend `npm run build` clean.

**Operator-visible outcome.** After deploy, the cluster selector
populates on the FIRST fetch — no 30-second wait. A transient kube-proxy
convergence window collapses to a few seconds (covered by retries) instead
of being masked by the 30-second interval.

##### Phase J audit hotfixes (audit fix #2 → #6)

Successive audit loops surfaced six follow-on issues that each
reproduced one or more of the original symptoms in narrower windows.
Each fix is pinned in the same Phase J pin-test file:

- **Audit fix #2 — stale closure in `fetchClusters`.** Wrapping
  `fetchClusters` in `useCallback(…, [])` froze `selectedCluster` at
  its mount-time value (`null`), so the 30-second auto-refresh
  reported stale agent-health data forever. Bridged via
  `selectedClusterRef`, updated in a passive effect, and read inside
  the callback.
- **Audit fix #3 — missing `setLoading(true)` on the auth-gated
  first fetch.** During the login flow, the ClusterContext effect
  fired with `loading=false` (the initial value), so the cluster
  selector briefly rendered "No Cluster Selected" before the spinner
  came back. Now the effect explicitly seeds `setLoading(true)` when
  the auth gate flips open.
- **Audit fix #4 — `loading=false` between retry waves.** The
  `finally` clause unconditionally released the loading flag, so the
  spinner blinked off between each backoff attempt and the UI
  flashed "No Cluster Selected" for up to ~15 seconds — the very
  symptom Phase J was meant to eliminate. The release is now gated
  on `retryTimerRef.current === null` so the spinner stays on across
  the entire retry budget.
- **Audit fix #5 — exhausted retry budget left counter at 4.**
  `retryAttemptRef` was reset only on a successful fetch and on the
  auth-gate transition. After 4 transient failures in a row the
  counter stayed at 4 for the rest of the session, so any subsequent
  invocation (the 30s background refresh, an explicit refetch from a
  mutator like `deleteCluster`) skipped the retry pattern entirely
  on the first transient failure. The settle-into-empty-state branch
  now resets the counter so each fresh invocation gets a full retry
  budget.
- **Audit fix #6 — page-content "No Cluster Selected" during the
  fetch window.** The cluster selector itself already showed a
  spinner via `loading`, but page-level components
  (`SSLManagement`, `Configuration`, `DashboardV2`,
  `BulkConfigImport`, `BulkVersionHistory`) checked
  `!selectedCluster` directly and rendered a permanent warning
  affordance. During the 15-second retry budget the page therefore
  read as "you forgot to pick a cluster" even though the cluster
  list was simply still being fetched. Each page now also consumes
  `loading: clustersLoading` from `useCluster()` and shows a neutral
  "Loading clusters…" affordance until the fetch settles, only then
  flipping to the warning. This is the fix that fully closes the
  user-visible loop on the original "clusters don't appear after
  deploy" report.

##### Phase K — Site Wizard validation hardening + UX simplification

Operators reported that completing the wizard and clicking **Create &
Apply** repeatedly surfaced opaque 422 errors at the final step:

```
HTTP→HTTPS redirect cannot be combined with custom redirect rules.
body -> frontend -> acl_rules -> 0: Input should be a valid dictionary
body -> frontend -> use_backend_rules -> 0: Input should be a valid dictionary
```

Root causes (each fixed by Phase K):

1. **Contract mismatch on rule fields.** `ACLRuleBuilder.js`
   serialised ACL / use_backend / redirect rules as `string[]` while
   `FrontendStep` typed them as `List[dict]`. Every wizard POST
   carrying a single ACL rule failed Pydantic validation. The
   downstream renderer in `services/haproxy_config.py` had always
   expected strings, so the schema mismatch was the stale side.
2. **Step 2 mutex was advisory only.** The
   `https_redirect ⊕ redirect_rules` validator existed at the model
   level but the wizard let the operator advance through Step 2 → 3 →
   4 with the conflict in place, only to be punted back at Create.
3. **No HAProxy validation before Create.** `/api/sites/preview`
   only checked collisions; the real validator ran inside the
   `create_site` transaction *after* entity inserts. Operators
   discovered errors at apply time.
4. **HTTPS step overcrowded.** 11 SSL bind-line knobs flat on Step 3
   without a defaults summary or any visible grouping.

**What changed**

- **Phase A — Backend contract + safety validators**
  (`backend/models/site_wizard.py`).
  - `acl_rules`, `use_backend_rules` are now `List[str]`.
    `redirect_rules` stays `List[Union[str, dict]]` to preserve the
    structured-redirect path used by the renderer's
    `_format_redirect_rule`.
  - Per-element safety validators reject embedded newlines (HAProxy
    directive injection prevention), shell-substitution patterns
    (`system`, `exec`, `eval`, `$(`, backtick — same set the
    manual frontend API has been blocking since pre-R14), 4 KB
    string limit, and empty / whitespace-only strings.
  - Two new cross-field model validators close silent-bug gaps:
    `FrontendStep.reject_tcp_mode_with_https_redirect` (the renderer
    used to emit an HTTP-only directive into a TCP frontend) and
    `SSLChoice.reject_inverted_tls_versions` (when both `ssl_min_ver`
    and `ssl_max_ver` are set, reject `min > max`).
- **Phase B — Step 2 hard-block + TCP-mode guard**
  (`SiteWizard.js`, `ACLRuleBuilder.js`).
  - The Step 2 Next handler now hard-blocks the
    `https_redirect ⊕ redirect_rules` and `mode='tcp' ⊕
    https_redirect` combinations with one-click resolve buttons
    ("Disable HTTP→HTTPS switch" / "Remove redirect rules").
  - Switching the frontend to TCP mode auto-clears `https_redirect`;
    the Switch is also `disabled` while `mode==='tcp'` with an
    explanatory tooltip.
  - `ACLRuleBuilder` accepts a new `disableRedirectRules` prop that
    visually disables the Redirect Rules section (`aria-disabled`,
    greyed-out cards, tooltip) when the parent passes
    `https_redirect=true`. The rules data stays in component state
    so toggling the switch off restores them.
- **Phase C — Real HAProxy dry-run gate before Create**
  (`backend/routers/site_wizard.py`, `SiteWizard.js`).
  - New shared helper `_synthesize_candidate_haproxy_config(body,
    conn, *, entities_already_inserted)` is used by both
    `create_site` (post-insert validation gate) and a new dry-run
    path on `POST /api/sites/preview`. Two callsites pinned by
    `test_phase_k_create_site_and_preview_use_same_synthesis_helper`
    so the apply gate and the dry-run gate cannot silently desync.
  - `POST /api/sites/preview` now accepts an optional
    `validate_haproxy_config=true` query param. When set, the
    endpoint runs `HAProxyConfigValidator` against the synthesised
    candidate config and returns a `validation: {is_valid,
    error_count, warning_count, errors, warnings, infos}` block in
    the same 200 OK envelope. Validator crashes return
    `is_valid: null` + `validator_error` (matches `create_site`'s
    non-fatal posture). The dry-run path is rate-limited at 5/min
    via `_enforce_rate_limit` and emits structured ENTER/EXIT
    `logger.info` lines for telemetry. Legacy preview callers
    (`SiteDrafts.handlePreview`) are unaffected — they pass no flag.
  - The wizard auto-fires the dry-run on Step 4 entry with an
    `AbortController` so rapid Step 4 → Step 2 → Step 4 navigation
    cancels the in-flight request. A six-state validation card
    renders inline: idle / loading / clean (green) /
    `warnings_only` (yellow) / `errors` (red, blocks Create) /
    `pydantic_error` (red, body-parse failures from Phase A's new
    validators or PEM-stripped resume drafts) / `unavailable`
    (orange, advisory — Create stays enabled to mirror the
    validator-crash-is-non-fatal contract). Each error /
    `pydantic_error` row gets an `Edit Step N` jumpback button via
    a static directive→step + loc→step mapping table.
  - Audit-fix #1 (post-implementation review): the wizard also
    resets `dryRunResult.status` to `idle` whenever the operator
    leaves Step 4. The ACL builder lives outside the antd Form
    so its mutations don't fire `Form.onValuesChange`; without
    this reset a stale `clean`/`errors`/`warnings_only` status
    survives Step 4 → Step 2 (ACL edit) → Step 4 round-trips
    and the auto-fire branch suppresses the next fetch. With
    the reset every Step 4 entry triggers a fresh dry-run
    (rate-limit-safe — entry is operator-initiated, not
    programmatic).
  - Audit-fix #2 (post-implementation review): the
    `Edit Step N` jumpback now also resolves the target step
    from the error **message text** when `loc` cannot pinpoint
    it. Pydantic v2 raises `model_validator(mode="after")`
    errors with `loc=()`; FastAPI prepends `'body'` so the
    operator-visible envelope is `loc=['body']` (length 1).
    The legacy `_locPathToStep` early-returned null for this
    case, dropping the jumpback for PEM-stripped resume
    ("ssl.mode='upload' requires a non-empty PEM-encoded
    certificate_content …") and every
    `enforce_acme_apply_and_http` cross-field rejection. A
    small ordered pattern table recovers the step from the
    failure message text so operators always get a working
    "fix-from-here" button.
  - Audit-fix #2 round 3 (post-implementation review): the
    pattern table is ordered so cross-field ACME messages
    route to the step the operator must EDIT to fix the
    error, not the step that "feels related". A naive ordering
    ("SSL first because every cross-field message starts with
    `ssl.mode='acme'`") would route every cross-field hit to
    Step 3, defeating the jumpback. Order is now:
    `apply_immediately` (Step 4) → `wildcard`/`domains` (Step
    0) → `frontend.*`/`bind_port` (Step 2) → `backend.*` (Step
    1) → SSL catch-all (Step 3, LAST). With this ordering,
    "ssl.mode='acme' requires apply_immediately=true" routes
    to Step 4 (toggle the switch), "ssl.mode='acme' requires
    frontend.bind_port=80" routes to Step 2 (edit FE port),
    and "(HTTP-01) cannot issue wildcard certs" routes to
    Step 0 (remove wildcard). PEM-stripped and other SSL-only
    errors still hit Step 3 via the final catch-all.
  - Audit-fix #2 round 4 (post-implementation review): the
    pydantic_error renderer no longer emits a stray
    `<strong>: </strong>` orphan-colon prefix when the failing
    error has no field path. SiteCreate-level model_validator
    errors land with `loc=['body']` (length 1); after dropping
    the leading `'body'` marker the joined path is empty.
    Pre-fix the renderer wrapped that empty string in
    `<strong>...: </strong>`, producing a visually broken " : "
    prefix in front of every PEM-stripped resume message and
    every `enforce_acme_apply_and_http` cross-field rejection.
    Post-fix the strong/colon prefix renders only when a real
    field path exists.
- **Phase D — HTTPS step simplification + UI parity**
  (`SiteWizard.js`).
  - TLS bounds (`ssl_min_ver`, `ssl_max_ver`) and the HSTS quartet
    stay first-class on the SSL step; rarely-used knobs
    (`https_bind_port`, `https_frontend_name_suffix`, `ssl_alpn`,
    `ssl_ciphers`, `ssl_ciphersuites`, `ssl_strict_sni`,
    `ssl_verify`) move into a nested **Advanced TLS settings
    (rarely needed)** Collapse that defaults to closed. A read-only
    summary line ("Port 443, ALPN h2,http/1.1, …") shows the safe
    defaults that apply unless overridden.
  - The Advanced Collapse auto-opens (`defaultActiveKey`) when a
    saved draft has any non-default value, so resumed drafts
    surface their custom tuning instead of silently hiding it.
  - HSTS UI parity for the Phase A
    `reject_hsts_preload_without_hsts` validator: the
    `hsts_preload` Switch is `disabled` until HSTS is enabled,
    `max-age ≥ 31536000`, AND `includeSubDomains=true`.
    `hsts_max_age` and `hsts_include_subdomains` are also disabled
    while `hsts_enabled=false`.
  - TLS min/max ordering UI parity: the `ssl_min_ver` /
    `ssl_max_ver` Selects use Antd `dependencies` + a custom
    validator that rejects min > max client-side with the same
    wording the Phase A model validator uses.

**Backward compatibility**

- The existing `/api/sites` POST envelope is unchanged.
- The existing `/api/sites/preview` POST envelope gains an optional
  `validation` field that legacy callers can ignore. The
  `validate_haproxy_config` flag defaults to `false`, so
  `SiteDrafts.handlePreview` and any external integrators keep
  their pre-Phase K behaviour.
- `redirect_rules` retains its `List[Union[str, dict]]` shape, so
  any historical caller (or saved draft) that used the structured
  dict form continues to work.
- The Pydantic safety validators (`system`, `exec`, `eval`, `$(`,
  backtick) match the manual frontend API's existing
  `validate_acl_rules` posture, which has been in production
  blocking the same substrings since pre-R14 with no operator
  complaint. No existing wizard payload that previously round-
  tripped through `services/haproxy_config.py` can be rejected by
  these new validators.
- The `_synthesize_candidate_haproxy_config` helper in
  `entities_already_inserted=True` mode is functionally identical
  to the previous inline `generate_haproxy_config_for_cluster`
  call inside `create_site`. The refactor is pure DRY plumbing.

##### Rollback considerations (Phase K)

If you must roll back to a pre-Phase-K v1.5.x build:

- **Saved drafts** with the new `acl_rules: List[str]` shape are
  forward- and backward-compatible: the legacy build also expected
  string elements at the renderer level, the rejection only ever
  happened at the wizard model boundary. Operators on the legacy
  build hit the same 422 the new build is fixing — no DB rewrite
  needed.
- **`/api/sites/preview` `validation` block** is a new optional
  field; legacy frontend callers ignore unknown fields. The
  `validate_haproxy_config` query param default is `false`, so
  legacy callers do not exercise the dry-run branch.
- **No DB migrations** are introduced by Phase K. The
  `frontends.acl_rules` / `redirect_rules` / `use_backend_rules`
  JSONB columns remain unchanged.

##### Phase K Phase D — Operator-feedback follow-ups (Bulgu #1–#6)

Operator review of the Phase A–C release surfaced six additional
issues. Each is rooted in a UX inconsistency or a residual stuck
state, and the fixes converge on a "single source of truth + ref-
based dry-run lifecycle" architecture:

- **Bulgu #1 — Cluster scope.** Pre-fix Step 0 had its own cluster
  Select dropdown decoupled from the header. Operators routinely
  picked cluster A in the header and cluster B in the wizard with
  zero visual signal that the wizard would target a different
  cluster than every other tool. Phase D pipes the wizard through
  the SAME `ClusterContext` that FrontendManagement / BackendServers
  / SSLManagement consume, hides Step 0's `cluster_id` `Form.Item`,
  and replaces the picker with a read-only `<Tag>` display + hint
  to change cluster via the header. A `useEffect` keeps
  `form.cluster_id` synchronised with `selectedCluster.id` so mid-
  wizard header changes propagate; the existing cluster-transition
  cleanup effect handles cert-id orphan reconciliation. Resume from
  a draft that targets a different cluster now auto-swaps the
  header cluster (best-effort `selectCluster()` call) so post-
  resume edits stay cluster-consistent.

- **Bulgu #2 — SSL CA bundle dropdown filter.** Backend's
  `BackendServers.js` filters the CA-bundle Select with
  `?usage_type=server`, so operators only see certs imported with
  the right purpose. The wizard pre-fix surfaced EVERY cert in the
  cluster regardless of usage, letting an operator submit a payload
  that apply-time HAProxy would parse-error on (`unable to load
  SSL private key`). Phase D filters explicitly:
    * Per-server CA bundle Select → `usage_type === 'server'`.
    * SSL & ACME step's "Existing certificate" Select →
      `usage_type === 'frontend'`.
  The empty-state Alert was also updated to reason about only the
  filtered list so a cluster with N server-side certs but zero
  frontend certs renders the "no certs imported" hint correctly.

- **Bulgu #3 — Stuck "Validating against HAProxy…".** The root
  cause was a self-cancel race in the auto-fire `useEffect`. The
  effect deps array included `dryRunResult.status`, and the effect
  body called `setDryRunResult({status: 'loading'})` at the top.
  The status change re-triggered the effect; React's cleanup of the
  previous run fired BEFORE the new body, aborting the in-flight
  controller; the new body returned early because `status !==
  'idle'`; the aborted fetch's `.catch` block detected
  `signal.aborted` and returned without setting state. Status
  stayed `'loading'` forever. Audit-fix #1 (round 1) had addressed
  the leave-Step-4 cleanup branch but the enter-Step-4 self-abort
  was a separate failure mode that only surfaced on a real backend.
  Phase D switches the lifecycle to a ref-driven model:
    * `dryRunStatusRef` shadows the latest status (synced via a
      passive `useEffect`).
    * `dryRunInvalidationTick` is the external re-trigger channel;
      `onValuesChange` bumps it when the operator edits a Step-4-
      visible field (e.g. the Apply Immediately switch).
    * The main effect's deps array drops `dryRunResult.status` and
      becomes `[step, form, aclBuilderData, dryRunInvalidationTick]`
      — none of these change on a self-issued setDryRunResult, so
      the self-cancel race is structurally impossible.
    * Cleanup nulls the abort ref only if it still points to the
      torn-down controller, so a fresh fetch's ref is never
      accidentally cleared.

- **Bulgu #4 — Preview missing fields.** The /api/sites/preview
  response previously echoed only a sparse subset of fields, so the
  SiteDrafts Preview modal could not show whether per-server
  timings, backend cookie persistence, frontend maxconn, HSTS, or
  ciphersuites would actually land on disk. Phase D enriches both
  the backend response (additive — all existing keys preserved)
  AND the SiteDrafts UI:
    * Backend: emits the full operator-settable surface area on
      `would_create` (backend cookie/timeouts/options, per-server
      timings + SSL+CA-bundle details, frontend maxconn/timeouts/
      compression/ACL counts, HTTPS ciphersuites, etc.).
    * Frontend: replaces the four flat Descriptions blocks with a
      typed renderer that only surfaces NON-DEFAULT values
      (`isMeaningful` predicate) so the modal stays scannable. A
      dedicated per-server card surfaces every per-server field
      the operator customised. HSTS gets its own section when
      enabled.

- **Bulgu #5 — Resume hydration regressions.** Two issues:
    1. Existing certificate was wiped on resume. Root cause was
       the orphan-detect effect running on the SAME render that
       the resume effect committed the new cluster_id. existingCerts
       was still `[]` (fetch in flight), so `certIds = new Set()`
       and the freshly-resumed `ssl.ssl_certificate_id` looked like
       an orphan and got cleared. Phase D fix: short-circuit the
       orphan-detect when `existingCertsLoading=true` and add the
       loading flag to the effect deps so the check re-runs after
       the fetch settles. ALSO: pin `prevClusterRef.current` to
       `merged.cluster_id` BEFORE `form.setFieldsValue(merged)` so
       the cluster-transition cleanup effect does not misread the
       hydration as a user-driven cluster switch.
    2. The same stuck "Validating against HAProxy…" — resolved by
       the Bulgu #3 self-cancel-race fix above.

- **Bulgu #6 — Create as PENDING button removed.** Pre-fix the
  wizard had TWO submit buttons. The "Create as PENDING" button
  bypassed the standard manual-flow convention (entity Create →
  PENDING version → Apply Management review → operator Apply). The
  "Create & Apply" button bypassed Apply Management entirely.
  Operators were trained to "always Create & Apply", defeating the
  change-review benefit of Apply Management. Phase D consolidates:
    * Single button: "Create Site" (or "Create & Apply (ACME)" when
      sslMode='acme', because ACME forces the immediate apply for
      the HTTP-01 challenge).
    * `handleSubmit` derives `effectiveApply` from `sslModeAtSubmit
      === 'acme'` — no button-driven branching.
    * Non-ACME flow: `apply_immediately=false` → backend returns
      `created_pending` → operator is navigated to /apply-management
      where they review the bulk version and click Apply (same
      Agent-pull cadence as manual entity creation).
    * ACME flow: `apply_immediately=true` (M22 model_validator
      enforces this) → standard `created_applied` response.
    * The `acmeBlocksDraft` derivation that gated the (now-removed)
      PENDING button is retired — handleSubmit's `effectiveApply`
      replaces the gate.

##### Phase K Phase D — Backward compatibility / rollback

- **Cluster picker change.** Operators who relied on the wizard-
  internal cluster Select must switch via the header instead. No
  data-layer change. Drafts saved on a different cluster
  auto-swap the header on resume.
- **`/api/sites/preview` response shape.** Additive only — every
  pre-existing key keeps the same shape; new keys are
  `cluster_id`, `domains`, additive fields on `backend` / `servers`
  / `frontend_http` / `frontend_https`. Legacy frontend callers
  ignore unknown fields.
- **`/api/sites` request shape.** Unchanged.
- **No DB migrations** are introduced by Phase K Phase D.

##### Phase K Phase D — Follow-up audit findings (Bulgu #7–#8)

A deeper post-implementation audit surfaced two additional
race conditions that were not visible in the first pass. Both
are now resolved on the same `pilot` branch:

- **Bulgu #7 — Resume cluster swap race on cold mount.** On a
  browser refresh of `/sites/new` while a Resume click had
  already pre-populated sessionStorage, the wizard mount races
  against `ClusterContext`'s `fetchClusters()`. The resume
  effect ran with `clustersFromContext=[]`, so
  `selectCluster(draftCluster)` was silently skipped. Then
  `ClusterContext` finished loading and `selectedCluster`
  became the user's `defaultCluster` (NOT the draft's
  cluster). The naive header sync then overwrote
  `form.cluster_id` with the default cluster, and the
  cluster-transition cleanup effect read that overwrite as a
  user-driven switch and wiped the draft's cert selections —
  the Bulgu #5 second-order failure that survived the
  short-circuit fix on a cold mount path.

  Fix: header sync effect grew a one-shot post-resume swap
  branch keyed on `resumedFromDraft && !resumeClusterSynced`.
  When the draft's `cluster_id` is in the freshly-loaded
  `clustersFromContext`, the swap pushes the HEADER to the
  draft cluster instead of forcing the form to follow the
  header. The `resumeClusterSynced` state gates this to
  exactly ONE attempt so a later operator-driven header
  cluster change is honoured normally. `selectClusterRef`
  (a `useRef(selectCluster)` updated by a tiny sync effect)
  keeps the dep set small so the header sync effect does not
  re-run on every `ClusterProvider` render.

  Pin: `tests/test_frontend_auth_bootstrap_phase_j.py::
  test_phase_k_phase_d_resume_cluster_swap_race_fix`.

- **Bulgu #8 — Mid-wizard cluster change leaves stale dry-run.**
  When an operator on Step 4 changes the header cluster, the
  wizard's cluster_id transitions through `form.setFieldsValue`
  (the header sync effect's standard force path). Antd's
  `setFieldsValue` is a SILENT update that does NOT fire
  `onValuesChange`, so the dry-run invalidation tied to
  `onValuesChange` never ran. Result: the Step 4 validation
  card kept displaying the PREVIOUS cluster's "clean" verdict
  even though the wizard payload now targeted a different
  cluster.

  Fix: the cluster-transition cleanup effect (which already
  detected the change to wipe stale cert ids) now also resets
  `dryRunResult` to idle and bumps `dryRunInvalidationTick`
  whenever `dryRunStatusRef.current !== 'idle'`. The dry-run
  effect's dep list picks up the tick bump and re-fires
  against the new cluster as soon as the operator reaches
  Step 4.

  Pin: `tests/test_frontend_auth_bootstrap_phase_j.py::
  test_phase_k_phase_d_cluster_change_invalidates_dry_run`.

Both fixes are additive (no API or DB changes) and rollback
without leaving residual state — disabling the new effects
simply restores the previous (racy) behaviour.

##### Phase K Phase D — Operator-feedback round 2 (Bulgu #9–#11)

A second operator-feedback round surfaced one parity gap and two
follow-ups on the wizard's HAProxy validation experience:

- **Bulgu #9 — Wizard PEM upload parity with SSL Management page.**
  Pre-fix `services.ssl_service.create_cert_row` (the helper the
  wizard calls when `ssl.mode='upload'`) was a thin INSERT that
  never parsed the PEM. It stored `primary_domain` / `all_domains`
  from the operator-entered FRONTEND domains (not the cert SAN),
  left `expiry_date` / `issuer` / `fingerprint` NULL, hard-coded
  `status='valid'` and `days_until_expiry=0`, never validated the
  private key or chain, never checked name uniqueness (so a
  duplicate name would 500 at the DB unique constraint), and could
  not reactivate a soft-deleted row of the same name. The
  resulting cert showed up on the SSL Management page with empty
  expiry/issuer columns and a permanent "valid" status — confusing
  UX and clearly inconsistent with the dedicated SSL Management
  upload flow (`POST /api/ssl/certificates`).

  Fix: `create_cert_row` now mirrors `routers/ssl.py::
  create_ssl_certificate`:
  - parses the PEM via `utils.ssl_parser.parse_ssl_certificate`
    (raises HTTPException 400 on parse failure),
  - validates private_key + chain via `validate_private_key`
    / `validate_certificate_chain`,
  - computes status / days_until_expiry from the normalised
    timezone-naive UTC `expiry_date`,
  - enforces name uniqueness within the target cluster (returns
    400 instead of a DB-level 500),
  - reactivates soft-deleted rows of the same name (preserves
    the row id for downstream references).

  Pin: `tests/test_ssl_service_extraction.py` — 11 tests cover
  the happy path, all 6 negative paths (parse fail, empty content,
  bad private key, bad chain, duplicate active name, soft-delete
  reactivation), and the "metadata comes from PEM, not payload"
  contract.

- **Bulgu #10 — Heuristic validator rejected wizard's own default
  timeouts.** The wizard's config synthesis emits `timeout connect
  10000ms` / `timeout server 60000ms` / `timeout client 100ms`
  (millisecond suffix is canonical HAProxy syntax). The pre-fix
  heuristic regex was `^\d+[smhd]?$`, which only allowed the
  single-character suffixes `s`/`m`/`h`/`d` — `ms` was rejected
  outright even though the same validator's own suggestion text
  said "Use format like '5s', '30000ms', '1m'". Operators saw
  10+ FALSE-POSITIVE "Invalid timeout value '10000ms'" errors on
  the wizard's defaults at Step 4 and could not click Create.

  Fix: `utils/haproxy_validator.py::_validate_timeout_directive`
  regex relaxed to `^\d+(us|ms|s|m|h|d)?$` — accepting the full
  set of HAProxy time-format suffixes (per the HAProxy docs Time
  format chapter) while still rejecting malformed values like
  `10000xx`, `abc`, `-100ms`, `1.5s`, and bare `ms`.

  Pin: `tests/test_haproxy_validator_timeout_units.py` — 17
  parametrised cases (11 valid formats, 5 invalid formats, plus
  the exact operator-reported failure mode).

- **Bulgu #11 — Operator reported "Previous loses values".**
  Architectural review confirmed the wizard's contract is sound:
  every step is rendered into a long-lived `<div>` whose only
  step-driven prop is the CSS `display` toggle (`block` vs
  `none`). React does NOT unmount the children, Antd's Form.Item
  registrations stay intact, and the Antd default `preserve=true`
  keeps values in form state even for the inner Form.Items that
  conditional-render inside `<Form.Item shouldUpdate>` (SSL mode
  branches, TCP/http frontend mode toggle). All wizard
  `setFieldsValue` call-sites are guarded by domain triggers
  (cluster change, sslMode change, TCP-mode-clears-https_redirect,
  resume hydration) — none fire on a Previous/Next click alone.

  No code regression was identified. Most likely operator
  perception driver: with Bulgu #10 fixed, the `timeout
  connect=10000` / `timeout server=60000` values the operator
  saw in the "Advanced backend settings" Collapse after coming
  back from Step 4 are simply the wizard's pre-existing defaults
  (`backend.timeout_connect=10000`, `backend.timeout_server=
  60000`, `backend.timeout_queue=60000`), not regressed values
  — these were never operator-entered, just defaults the
  operator did not notice in the collapsed Advanced section on
  the forward pass.

  Defensive measure: a static-source pin test asserts the
  architectural contract so a future refactor cannot regress
  to per-step conditional rendering or sneak a
  `preserve={false}` in:
  `tests/test_frontend_auth_bootstrap_phase_j.py::
  test_phase_k_phase_d_wizard_preserves_form_state_across_step_navigation`.

  If the operator can reproduce specific field-level state loss
  on a Previous click after the Bulgu #10 fix, please file the
  repro steps so we can target the actual scenario.

##### Rollback considerations (Phase I)

If you must roll back to a pre-rebrand v1.5.x build after operators have already saved drafts on the new build:

- New rows on `wizard_drafts` with `wizard_type='site'` will be invisible to the legacy code path that filters on `wizard_type='proxied_host'` only. Operators will see those new drafts disappear from the listing AND will not be counted against the 50-draft cap. The rows themselves are not deleted — they expire via the standard 30-day TTL prune.
- Pre-rebrand rows with `wizard_type='proxied_host'` continue to work on the legacy build because their value never changed.
- The schema-level `DEFAULT` is not rolled back automatically. Operators rolling back can either (a) leave it at `'site'` (harmless — the legacy build hard-codes `'proxied_host'` in every INSERT, so the default is never consulted) or (b) re-run an `ALTER TABLE wizard_drafts ALTER COLUMN wizard_type SET DEFAULT 'proxied_host'` to restore the original schema.

##### Phase K Phase D — Operator-feedback round 3 (Bulgu #12)

**Operator-reported failure flow** (May 11, 2026):

The wizard's Step 4 dry-run showed 8 WARNINGs but no ERRORs, so Create proceeded; the operator then applied via Apply Management and the real `haproxy -c` parse rejected the config:

```
[ALERT] parsing [/tmp/haproxy-new-config.cfg:79] : error detected while parsing ACL 'acl1' : failed to open pattern file </path>.
[ALERT] parsing [/tmp/haproxy-new-config.cfg:87] : error detected while parsing switching rule : no such ACL : 'acl1'.
[ALERT] Fatal errors found in configuration.
```

The 8 WARNINGs were ALSO operator-confusing false positives:

```
[frontend] Directive 'stick-table' may not be valid in 'frontend' section
[frontend] Directive 'tcp-request' may not be valid in 'frontend' section  (×2)
[backend] Directive 'cookie' may not be valid in 'backend' section  (×2)
[backend] Missing 'global' section - recommended for production
```

**Two root causes:**

1. **Heuristic validator `valid_directives` was incomplete** — `stick-table`, `tcp-request`, `tcp-response`, `cookie`, `http-after-response`, `errorfile`, `description`, `id`, `filter`, etc. are perfectly valid in their respective sections but the validator's small hand-picked sets did not list them. Every wizard / manual page that emitted them flagged a spurious "may not be valid" WARNING. The wizard's pre-persist apply-time gate uses the same validator; even though it only blocks on ERROR-level findings, the noise polluted the operator-visible response trail and the version-history page.

2. **ACL `-f <file>` pattern-file references** — the visual ACL builder offered `-f (from file)` as a selectable flag, and neither the manual Frontend API's Pydantic validator (`models/frontend.py::validate_acl_rules`) nor the wizard's Pydantic validator (`models/site_wizard.py::_validate_haproxy_directive_string`) rejected `-f`. HAProxy OpenManager is a fully-managed product: it does NOT provision pattern files onto the HAProxy node's filesystem, so any operator-typed `-f /path/...` ALWAYS resolves to "file not found" at HAProxy reload time. The UI made it trivial to author an unsupported state.

**Three-layer fix:**

**Layer A — Heuristic validator** (`backend/utils/haproxy_validator.py`):

- Expanded `valid_directives['frontend']` to include `stick-table`, `stick`, `tcp-request`, `tcp-response`, `http-after-response`, `errorfile`, `errorloc`, `errorloc302`, `errorloc303`, `http-error`, `description`, `id`, `filter`, `monitor`, `unique-id-format`, `unique-id-header`, `declare`, `http-buffer-request`, plus a long-tail of less-common-but-valid directives.
- Expanded `valid_directives['backend']` to include `cookie`, `appsession`, `tcp-request`, `tcp-response`, `tcp-check`, `retries`, `fullconn`, `dispatch`, `redirect`, `use-server`, `acl`, `capture`, `errorfile`, `description`, `id`, `filter`, `rate-limit`, `email-alert`, `force-persist`, `transparent`, `source`, plus a long-tail.
- Added `partial_fragment: bool = False` parameter to `HAProxyConfigValidator.validate_config()` and the module-level `validate_haproxy_config()`. When True (or auto-detected via the wizard's marker comment), the validator suppresses the "Missing 'global' section" / "Consider adding 'defaults' section" diagnostics — the wizard / cluster synthesis intentionally OMITS those blocks because the agent merges them with its local copy on disk.
- Both the wizard's `/preview` dry-run AND the apply-time pre-persist gate now pass `partial_fragment=True` (`backend/routers/site_wizard.py`).

**Layer B — ACL `-f` rejection in Pydantic** (server-side gate):

- `backend/models/site_wizard.py`: Added `_ACL_FILE_FLAG_PATTERN = re.compile(r"(^|\s)-f(\s|$)")` and rejected the pattern inside `_validate_haproxy_directive_string` with an operator-friendly message explaining why the product cannot support pattern files. This covers `acl_rules`, `use_backend_rules`, and string-shaped `redirect_rules`.
- `backend/models/frontend.py::validate_acl_rules`: Mirrored the same rejection on the manual Frontend API so both create paths return the identical 400/422 envelope.

**Layer C — ACL `-f` removal from the visual builder + UI gates** (client-side authoring guardrail):

- `frontend/src/components/ACLRuleBuilder.js`: Removed `-f` from the selectable `FLAGS` list. Updated `FLAG_HINTS` to drop the `-f` mention. Existing rules that already carry `-f` (loaded from saved drafts pre-fix) keep the tag visible as `-f (deprecated — remove)` so operators can SEE and REMOVE the flag, but cannot re-add it once removed. Added a section-level red `Alert` that counts every rule carrying `-f` and explains the failure mode + remediation. Inline rule-card error decoration (`status='error'` + red border + inline description) surfaces the same message at the per-rule level. Mirrored the regex client-side so raw-mode typed `-f` immediately flags inline.
- `frontend/src/components/SiteWizard.js`: Added a Step 2 → Step 3 hard-gate on the Next button — if ANY rule still carries `-f`, the click surfaces the same operator-friendly error and refuses to advance.
- `frontend/src/components/FrontendManagement.js::handleSubmit`: Mirrored the same gate so the manual Frontend page rejects submit identically.

**Backward compatibility:**

- Existing drafts that contain `-f`-flagged rules still load — the ACLRuleBuilder displays them visibly so operators can remove them. Submit is blocked until they do.
- Existing PERSISTED frontend rows in the DB that already carry `-f` (created before this fix) continue to work at the agent level — the validator changes do NOT retroactively reject them. They can still be EDITED through the UI (which will block save until `-f` is removed) or read via the API for visibility / audit.
- The expanded `valid_directives` sets only ADD entries; nothing previously accepted is now flagged. Pre-existing tests that asserted "Directive X is valid" continue to pass.

**Tests added:**

- `backend/tests/test_haproxy_validator_bulgu12.py` (27 new tests):
  - Per-directive false-positive regression pins for both frontend and backend sections.
  - `partial_fragment=True` suppression + marker-comment auto-detect.
  - Wizard Pydantic `-f` rejection across spacing/position variants.
  - Anchor-correctness pin: regex must NOT match `-foo` / `-file` substrings inside other tokens.
  - Manual Frontend API parity pin.
  - End-to-end pin replaying the user's actual config (minus `-f`) with zero spurious WARNINGs.

- `backend/tests/test_site_wizard_phase2_validator_gate.py`: Widened the pre-window lookback from 400 to 1500 chars to accommodate the partial-fragment forwarding comment block.

**Rollback considerations:**

- Reverting the `valid_directives` expansion brings back operator-visible WARNING noise but does NOT break apply (which only gates on ERROR). Safe to roll back if a regression is discovered.
- Reverting the `-f` Pydantic rejection ALLOWS operators to author the failure mode again, but does not break anything that worked before. Roll back ONLY if a customer has pre-provisioned pattern files and a tightly-controlled need to reference them.
- Reverting the ACLRuleBuilder UI changes is a pure visual revert; the Pydantic gate keeps the safety net.

### Earlier Releases

For earlier release notes (v1.4.0 ACME stability + enterprise audit, v1.3.0, ...) see the [GitHub Releases](https://github.com/taylanbakircioglu/haproxy-openmanager/releases) page.

---

**Made with ❤️ for the HAProxy community**
