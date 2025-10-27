# HAProxy OpenManager

Modern, web-based management interface for HAProxy load balancers with multi-cluster support, agent-based pull architecture, and automated deployment capabilities.

## 🎯 Project Overview

HAProxy OpenManager is a comprehensive management platform designed to simplify HAProxy administration across multiple environments. It provides a unified interface for managing remote HAProxy instances through an agent-based pull architecture, supporting multi-cluster configurations with centralized control.

### 🏗️ Agent Pull Architecture

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

### Key Capabilities

- **Agent-Based Management**: Lightweight agent service for secure, pull-based HAProxy management
- **Pool Management**: Organize agents into logical pools for better cluster organization
- **Multi-Cluster Support**: Manage multiple HAProxy clusters from a single interface with cluster selector
- **Agent Installation Scripts**: Auto-generated platform-specific installation scripts (Linux/macOS)
- **Configuration Synchronization**: Backends, frontends, SSL certificates, and WAF rules auto-sync to agents
- **Apply Management**: Centralized change tracking and deployment status monitoring
- **Real-time Monitoring**: Live statistics, health checks, and performance metrics
- **Configuration Management**: Visual configuration editor with syntax highlighting and version history
- **SSL Management**: Centralized certificate management with expiration tracking
- **WAF Rules**: Web Application Firewall rule management and deployment
- **User Management**: Role-based access control with admin and user roles
- **REST API**: Complete API for programmatic access and integration

## 📸 Screenshots

### Dashboard - Real-time Monitoring
![Dashboard Overview](docs/screenshots/dashboard-overview.png)
*Overview tab showing system metrics, active servers, SSL certificates, and cluster agent health*

![Performance Trends](docs/screenshots/performance-trends.png)
*Performance Trends with request rate and response time heatmap (24h view)*

![Health Matrix](docs/screenshots/health-matrix.png)
*Health Matrix showing backend servers with detailed health check status and response times*

![Backends & Servers](docs/screenshots/backends-servers.png)
*Backends & Servers tab with 165 servers across 56 backends, health status overview*

### Configuration Management

![Cluster Selector](docs/screenshots/cluster-selector.png)
*Cluster selector showing multiple clusters with agent pools and online agent counts*

![Frontend Management](docs/screenshots/frontend-management.png)
*Frontend Management with SSL/TLS bindings, sync status, and config status*

![Backend Configuration](docs/screenshots/backend-configuration.png)
*Backend configuration with TCP mode, health checks, and server management*

![Configuration View](docs/screenshots/config-view.png)
*Real-time configuration viewer - pull haproxy.cfg from live agents*

### Apply Management & Version Control

![Apply Management](docs/screenshots/apply-management.png)
*Apply Management showing pending changes and deployment history with version tracking*

![Version Diff](docs/screenshots/version-diff.png)
*Configuration diff viewer showing added/removed lines with summary*

![Version History](docs/screenshots/version-history.png)
*Complete version history with restore capabilities and deployment status*

### Agent & Security Management

![Agent Setup](docs/screenshots/agent-setup.png)
*Agent setup wizard - platform selection (Linux/macOS) and architecture (x86_64/ARM64)*

![Agent Script](docs/screenshots/agent-script.png)
*Generated installation script ready for deployment to target servers*

![WAF Management](docs/screenshots/waf-management.png)
*WAF rule configuration with request filtering, rate limiting, and advanced options*

> 📝 **Note**: Screenshots show the actual production interface. Replace GitHub asset URLs with your own after uploading images to your repository's releases or issues.

## 🏗️ Architecture

### System Architecture with Agent Pull Model

```mermaid
graph TB
    subgraph USERS[" "]
        USER["👤 HAProxy Manager<br/>(Admin/User)"]
    end
    
    subgraph MGMT["🖥️ Management Layer"]
        UI["React Frontend<br/>Port: 3000"]
        NGINX["Nginx Proxy<br/>Port: 8080"]
    end
    
    subgraph BACKEND["⚙️ Backend Services"]
        API["FastAPI Backend<br/>Port: 8000<br/>📋 Configuration Store<br/>🔐 SSL Management<br/>🛡️ WAF Rules"]
        REDIS[("💾 Redis Cache<br/>Port: 6379<br/>📊 Metrics Storage")]
        DB[("💿 PostgreSQL<br/>Port: 5432<br/>🗂️ Clusters, Agents<br/>📝 Version History")]
    end
    
    subgraph POOL["📦 Agent Pool: Production"]
        CLUSTER["🎯 Cluster: Production<br/>(Logical Grouping)"]
        
        subgraph HAP1_BOX["🖥️ HAProxy Server 1 (10.0.1.101)"]
            AGENT1["🤖 Agent<br/>Poll Every 30s"]
            CFG1["📄 haproxy.cfg"]
            SOCK1["🔌 Stats Socket"]
            SRV1["⚡ HAProxy Service"]
            
            AGENT1 -->|Manages| CFG1
            AGENT1 -->|Reads Stats| SOCK1
            AGENT1 -->|Reload| SRV1
            CFG1 -->|Used by| SRV1
            SRV1 -->|Provides| SOCK1
        end
        
        subgraph HAP2_BOX["🖥️ HAProxy Server 2 (10.0.1.102)"]
            AGENT2["🤖 Agent<br/>Poll Every 30s"]
            CFG2["📄 haproxy.cfg"]
            SOCK2["🔌 Stats Socket"]
            SRV2["⚡ HAProxy Service"]
            
            AGENT2 -->|Manages| CFG2
            AGENT2 -->|Reads Stats| SOCK2
            AGENT2 -->|Reload| SRV2
            CFG2 -->|Used by| SRV2
            SRV2 -->|Provides| SOCK2
        end
        
        subgraph HAP3_BOX["🖥️ HAProxy Server 3 (10.0.1.103)"]
            AGENT3["🤖 Agent<br/>Poll Every 30s"]
            CFG3["📄 haproxy.cfg"]
            SOCK3["🔌 Stats Socket"]
            SRV3["⚡ HAProxy Service"]
            
            AGENT3 -->|Manages| CFG3
            AGENT3 -->|Reads Stats| SOCK3
            AGENT3 -->|Reload| SRV3
            CFG3 -->|Used by| SRV3
            SRV3 -->|Provides| SOCK3
        end
    end
    
    USER -->|Access UI| UI
    UI <-->|HTTP| NGINX
    NGINX <-->|Proxy| API
    NGINX <-->|Serve| UI
    
    API -->|Store Config| DB
    API -->|Cache Metrics| REDIS
    API <-.->|Version Control| DB
    
    CLUSTER -.->|Contains| AGENT1
    CLUSTER -.->|Contains| AGENT2
    CLUSTER -.->|Contains| AGENT3
    
    AGENT1 <-.->|"🔄 Pull Tasks<br/>📤 Upload Stats<br/>⬇️ Download SSL"| API
    AGENT2 <-.->|"🔄 Pull Tasks<br/>📤 Upload Stats<br/>⬇️ Download SSL"| API
    AGENT3 <-.->|"🔄 Pull Tasks<br/>📤 Upload Stats<br/>⬇️ Download SSL"| API
    
    classDef userStyle fill:#bbdefb,stroke:#1565c0,stroke-width:3px,color:#000
    classDef frontendStyle fill:#ce93d8,stroke:#6a1b9a,stroke-width:2px,color:#000
    classDef backendStyle fill:#ffcc80,stroke:#e65100,stroke-width:2px,color:#000
    classDef dbStyle fill:#a5d6a7,stroke:#2e7d32,stroke-width:2px,color:#000
    classDef poolStyle fill:#f8bbd0,stroke:#ad1457,stroke-width:3px,color:#000
    classDef clusterStyle fill:#fff59d,stroke:#f57f17,stroke-width:2px,color:#000
    classDef haproxyStyle fill:#80cbc4,stroke:#00695c,stroke-width:2px,color:#000
    classDef agentStyle fill:#b39ddb,stroke:#4527a0,stroke-width:2px,color:#000
    
    class USER userStyle
    class UI,NGINX frontendStyle
    class API backendStyle
    class DB,REDIS dbStyle
    class CLUSTER clusterStyle
    class HAP1_BOX,HAP2_BOX,HAP3_BOX haproxyStyle
    class AGENT1,AGENT2,AGENT3 agentStyle
```

### Component Details

| Component | Technology | Purpose | Port |
|-----------|------------|---------|------|
| **Frontend** | React.js 18 + Ant Design | Web interface, dashboards, configuration UI | 3000 |
| **Backend** | FastAPI + Python | REST API, task queue, agent coordination | 8000 |
| **Database** | PostgreSQL 15 | Configuration storage, user management, agent tasks | 5432 |
| **Cache** | Redis 7 | Session storage, performance metrics caching | 6379 |
| **Reverse Proxy** | Nginx | Frontend/backend routing, SSL termination | 8080 |
| **HAProxy Agent** | Bash Service | Polls backend, applies configs, manages HAProxy | N/A |
| **HAProxy Instances** | HAProxy 2.8+ | Load balancer instances being managed by agents | 8404+ |

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
```

**Key Flow Features:**
- 🔄 **Continuous Polling**: Agents poll every 30s for tasks, stats collection, and version checks
- 📄 **Config Management**: haproxy.cfg backup → validate → apply → rollback if needed
- 🔐 **SSL Handling**: Secure download, file permissions (chmod 600), automatic frontend binding
- 🛡️ **WAF Integration**: Stick-tables generated and integrated into config
- 📊 **Stats Collection**: Parallel stats upload using socat + stats socket
- 🔄 **Auto-Upgrade**: Agents detect new versions and self-upgrade with zero-touch deployment
- ✅ **Validation**: Every config change is validated before HAProxy reload
- 📝 **Activity Logging**: All operations logged in JSON format for audit trail

## ✨ Features & User Interface

### 🏊 **Pool Management** - *Agent Pool Organization*
- **Pool Creation**: Create logical pools to group HAProxy agents
- **Pool Assignment**: Associate clusters with specific pools
- **Pool Overview**: View all agents within a pool
- **Multi-Pool Support**: Manage multiple pools for different environments (prod, staging, etc.)
- **Pool-based Filtering**: Filter agents and clusters by pool

### 🤖 **Agent Management** - *HAProxy Agent Deployment & Monitoring*

#### Agent Script Management
Agent scripts are **not hardcoded** in the project. They are stored in the database and can be updated via the UI:

- **Script Editor**: Edit agent installation scripts directly in the UI
- **Platform Support**: Separate scripts for Linux and macOS (x86_64/ARM64)
- **Version Control**: Create new agent versions with changelog
- **Automatic Upgrade**: Deploy new agent versions to all agents with one click
- **Upgrade Process**: Agents check backend version → Download new script → Self-upgrade → Restart

**Agent Version Update Flow:**
```
UI: Edit Script → Create Version 1.0.5 → Mark as Latest 
  → Agents Poll → Detect New Version → Self-Download 
  → Self-Upgrade → Restart Service
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
    "cert_name": "wildcard.company.com",
    "action": "update",
    "haproxy_reload": "success"
  }
}
```

### 🌐 **Cluster Management** - *Multi-Cluster HAProxy Administration*
- **Cluster Selector**: Top navigation cluster selector for context switching
- **Cluster Creation**: Define clusters and associate with agent pools
- **Cluster Status**: Monitor cluster health and connectivity
- **Default Cluster**: Set preferred default cluster
- **Cross-Cluster View**: Compare metrics across multiple clusters
- **Cluster-Scoped Operations**: All configurations are cluster-specific

### 🔄 **Apply Management** - *Change Tracking & Deployment*

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

### 🎯 **Dashboard** - *Main Overview & Real-time Monitoring*

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

### 🌐 **Frontend Management** - *Virtual Host & Routing Configuration*
- **Frontend CRUD**: Create, edit, delete, and duplicate frontend configurations
- **Protocol Support**: HTTP, TCP, and health check mode configurations
- **Binding Configuration**: IP address, port, and SSL binding options
- **Backend Assignment**: Default backend selection and routing rules
- **SSL Configuration**: Certificate assignment and SSL protocol settings
- **ACL Rules**: Access control rules with pattern matching
- **Redirect Rules**: HTTP to HTTPS redirects and custom redirections
- **Advanced Options**: Connection limits, timeouts, and performance tuning
- **Search & Filter**: Real-time search and status-based filtering

### 🖥️ **Backend Servers** - *Server Pool Management*
- **Server Management**: Add, edit, remove, and configure backend servers
- **Health Checks**: HTTP/TCP health check configuration and monitoring
- **Load Balancing**: Round-robin, least-conn, source, and URI algorithms
- **Server Weights**: Dynamic weight adjustment for load distribution
- **Maintenance Mode**: Enable/disable servers without removing configuration
- **Backup Servers**: Failover server configuration for high availability
- **Connection Limits**: Per-server connection and rate limiting
- **Monitoring Dashboard**: Real-time server status and performance metrics

### 🔒 **SSL Certificates** - *Centralized TLS/SSL Certificate Management*

HAProxy OpenManager provides powerful centralized SSL/TLS certificate management with both global and cluster-specific scopes:

#### SSL Certificate Scopes

**1. Global SSL Certificates:**
- Defined once, distributed to **all clusters** and **all agents**
- Perfect for wildcard certificates or shared certificates
- When updated, all agents across all clusters automatically receive the new certificate
- Use case: `*.company.com` certificate used across all environments

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
- **Certificate Store**: Centralized repository with encryption at rest
- **Expiration Monitoring**: Automatic expiration tracking with alerts (30, 15, 7 days)
- **Global Update**: Update one certificate, deploy to all clusters simultaneously
- **Domain Binding**: Associate certificates with specific domains/frontends
- **Certificate Validation**: Syntax and format validation before deployment
- **Renewal Tracking**: Certificate renewal status and history
- **Security Profiles**: SSL/TLS protocol and cipher suite configuration
- **Zero Downtime**: Safe HAProxy reload ensures no dropped connections

### 🛡️ **WAF Management** - *Web Application Firewall*
- **Rate Limiting**: Request rate limiting by IP, URL, or custom patterns
- **IP Filtering**: Whitelist/blacklist IP addresses and CIDR ranges
- **Geographic Blocking**: Country-based access restrictions
- **DDoS Protection**: Automated DDoS detection and mitigation rules
- **Custom Rules**: User-defined security rules with regex patterns
- **Attack Monitoring**: Real-time attack detection and logging
- **Rule Templates**: Pre-configured security rule templates
- **Statistics Dashboard**: WAF activity analytics and blocked request metrics

### 📊 **Statistics** - *Advanced Analytics & Reporting*
- **Time-series Charts**: Response time, traffic volume, and error rate trends
- **Performance Metrics**: Detailed frontend/backend performance analysis
- **Traffic Analysis**: Request distribution and peak usage patterns
- **Error Analytics**: HTTP status code distribution and error tracking
- **Session Monitoring**: Active sessions and connection statistics
- **Historical Data**: 1 hour to 30-day historical performance data
- **Custom Filtering**: Frontend/backend specific statistics filtering
- **Export Functionality**: CSV/JSON data export for external analysis

### ⚙️ **Configuration** - *HAProxy Config File Management*
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

### 👥 **User Management** - *Access Control & Authentication*
- **User Accounts**: Create, edit, and manage user accounts
- **Role-based Access**: Admin, user, and custom role definitions
- **Permission System**: Granular permissions for different system functions
- **User Activity**: Login history and user action audit logs
- **Password Management**: Secure password policies and reset functionality
- **Session Management**: Active session monitoring and force logout
- **API Keys**: User API key generation and management
- **Role Assignment**: Dynamic role assignment and permission updates

### 🔧 **Settings** - *System Configuration*
- **Theme Settings**: Light/dark mode toggle and UI customization
- **Notification Settings**: Alert preferences and notification channels
- **System Preferences**: Default timeouts, refresh intervals, and limits
- **Backup Settings**: Automated backup scheduling and retention policies
- **Integration Settings**: External system integrations and webhooks
- **Language Settings**: Multi-language support configuration
- **Performance Tuning**: System performance and optimization settings

## 🚀 Quick Start - Agent-Based Setup

### Complete Setup Process

#### Example Scenario: 3-Node HAProxy Cluster

Let's set up a production HAProxy cluster with 3 servers (10.0.1.101, 10.0.1.102, 10.0.1.103):

#### Step 1: Create an Agent Pool
1. Navigate to **Pool Management**
2. Click **Create Pool**
3. Fill in details:
   - Name: "Production Pool"
   - Description: "Production environment HAProxy instances"
4. Save the pool

#### Step 2: Create a Cluster
1. Go to **Cluster Management**
2. Click **Create Cluster**
3. Provide cluster details:
   - Name: "Production Cluster"
   - Description: "3-node production HAProxy cluster"
   - **Select Pool**: "Production Pool" (created in Step 1)
4. Save the cluster
5. **Important**: This associates the cluster with the pool

#### Step 3: Create Agents (Repeat for each HAProxy server)

**For HAProxy Server 1 (10.0.1.101):**
1. Navigate to **Agent Management**
2. Click **Create Agent**
3. Fill in agent details:
   - Agent Name: "prod-haproxy-01"
   - Platform: Linux
   - Architecture: x86_64
   - **Select Pool**: "Production Pool" (same pool as cluster!)
4. Click **Generate Install Script**
5. Download the script

**Repeat for Server 2 (10.0.1.102):**
   - Agent Name: "prod-haproxy-02"
   - Same Pool: "Production Pool"

**Repeat for Server 3 (10.0.1.103):**
   - Agent Name: "prod-haproxy-03"
   - Same Pool: "Production Pool"

**Result**: You now have 3 agents in "Production Pool", all managing "Production Cluster"

#### Step 4: Install Agents on HAProxy Servers

**On each HAProxy server (10.0.1.101, 102, 103):**
```bash
# Copy the downloaded script to the server
scp install-agent-prod-haproxy-01.sh root@10.0.1.101:/tmp/

# SSH to the server
ssh root@10.0.1.101

# Make executable and run
chmod +x /tmp/install-agent-prod-haproxy-01.sh
sudo /tmp/install-agent-prod-haproxy-01.sh
```

The agent will:
- Install required dependencies (Python, socat)
- Create `haproxy-agent` systemd service
- Start polling the backend every 30 seconds
- Register itself with the backend
- Begin managing `/etc/haproxy/haproxy.cfg`

#### Step 5: Verify All Agents are Connected
1. Return to **Agent Management** in the UI
2. You should see all 3 agents:
   - ✅ prod-haproxy-01 - Connected - Last seen: 5 seconds ago
   - ✅ prod-haproxy-02 - Connected - Last seen: 3 seconds ago
   - ✅ prod-haproxy-03 - Connected - Last seen: 8 seconds ago
3. All agents are now ready to receive configurations

#### Step 6: Configure HAProxy for the Cluster
1. Select **"Production Cluster"** from the cluster selector at the top
2. Create **Backends**:
   ```
   Backend: web-backend
   Servers: 
     - web01: 192.168.1.10:80
     - web02: 192.168.1.11:80
     - web03: 192.168.1.12:80
   Load Balancing: roundrobin
   ```
3. Create **Frontends**:
   ```
   Frontend: web-frontend
   Bind: 0.0.0.0:80
   Default Backend: web-backend
   ```
4. Upload **SSL Certificates** (if needed)
5. Add **WAF Rules** (if needed)

#### Step 7: Apply Changes to All Agents
1. Navigate to **Apply Management**
2. You'll see pending changes for "Production Cluster"
3. Click **Apply Changes**
4. Watch the deployment status:
   ```
   ✅ prod-haproxy-01: Configuration applied successfully
   ✅ prod-haproxy-02: Configuration applied successfully
   ✅ prod-haproxy-03: Configuration applied successfully
   ```
5. All 3 HAProxy servers now have identical configurations!

#### Result
- **1 Pool** ("Production Pool")
- **1 Cluster** ("Production Cluster")
- **3 Agents** (prod-haproxy-01, 02, 03)
- **3 HAProxy Servers** with synchronized configurations

### 🎯 Traditional Quick Start (for local development/testing)

For local development without agents:

## 🚀 Traditional Quick Start

### Prerequisites

- **Docker & Docker Compose** (v20.10+)
- **Git**
- **2GB+ RAM** for all services
- **SSH access** to remote HAProxy servers (for remote management)

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/haproxy-openmanager.git
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

## 📋 Configuration

### Environment Variables

All configuration is managed through environment variables for maximum flexibility across different deployment environments.

**📄 Configuration Template**: `.env.template`

```bash
# 1. Kopyalayın (template → gerçek config)
cp .env.template .env

# 2. Düzenleyin (YOUR-DOMAIN yerine gerçek domain)
nano .env

# 3. Başlatın
docker-compose up -d
```

**⚠️ ÖNEMLİ**: 
- `.env.template` sadece bir şablondur (git'e commit edilir)
- `.env` gerçek yapılandırmadır (git'e commit EDİLMEZ - .gitignore'da)
- Değiştirdiğinizde `.env` dosyasını düzenleyin, `.env.template` değil!

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
#   Production:   PUBLIC_URL="https://haproxy-openmanager.company.com"
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

## 🔌 API Reference

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

## 🐳 Docker Deployment

### Services Overview

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

## ☸️ Kubernetes/OpenShift Deployment

### Kubernetes Deployment

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

## 🛠️ Development

### Local Development Setup

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

### Project Structure

```
haproxy-openmanager/
├── backend/                 # FastAPI backend
│   ├── main.py             # Main application entry
│   ├── haproxy_client.py   # HAProxy management client
│   ├── haproxy_installer.py # Automated installation
│   ├── init.sql            # Database initialization
│   └── requirements.txt    # Python dependencies
├── frontend/               # React.js frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── contexts/       # React contexts
│   │   └── App.js         # Main app component
│   └── package.json       # Node dependencies
├── haproxy/               # HAProxy configurations
├── k8s/                   # Kubernetes manifests
├── nginx/                 # Nginx configuration
└── docker-compose.yml     # Docker services
```

### Adding New Features

1. **Backend API Endpoints**: Add to `backend/main.py`
2. **Frontend Components**: Add to `frontend/src/components/`
3. **Database Changes**: Update `backend/init.sql` and create migration
4. **HAProxy Features**: Extend `backend/haproxy_client.py`

## 🐛 Troubleshooting

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

## 📝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 for Python code
- Use ESLint/Prettier for JavaScript code
- Add tests for new features
- Update documentation for API changes
- Ensure Docker builds work correctly

## 🎨 Screenshots

> 📸 **Note**: Screenshots will be added soon. In the meantime, check the feature descriptions above for detailed functionality overview.

### Main Dashboard
Coming soon - Real-time metrics, charts, and cluster overview

### Agent Management
Coming soon - Agent deployment, monitoring, and script generation

### Configuration Management
Coming soon - HAProxy configuration editor with syntax highlighting

## 📊 Project Statistics

- **Languages**: Python (Backend), JavaScript/React (Frontend)
- **Architecture**: Microservices with Agent Pull Model
- **Database**: PostgreSQL with async operations
- **Cache**: Redis for high-performance metrics
- **Deployment**: Docker Compose & Kubernetes/OpenShift ready

## 🎯 Use Cases

1. **Enterprise HAProxy Management**: Manage multiple HAProxy clusters across different environments
2. **DevOps Automation**: Automated configuration deployment with version control
3. **Multi-Tenant Setups**: Separate pools and clusters for different teams/projects
4. **Monitoring & Analytics**: Real-time metrics and performance tracking
5. **Security Management**: Centralized SSL certificate and WAF rule management

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Taylan Bakırcıoğlu**  
Burgan Bank - DevOps / Product Line Manager  
LinkedIn: [linkedin.com/in/taylanbakircioglu](https://www.linkedin.com/in/taylanbakircioglu/)

Developed with ❤️ for the HAProxy community

## 🌟 Star History

If you find this project useful, please consider giving it a star on GitHub!

## 🤝 Support

- **Documentation**: This README and inline code documentation
- **Issues**: [GitHub Issues](https://github.com/hub-burgan-com-tr/haproxy-openmanager/issues)
- **Pull Requests**: Contributions are welcome!

## ⭐ Contributing

We welcome contributions! Here's how you can help:

1. **Report Bugs**: Open an issue with detailed reproduction steps
2. **Suggest Features**: Share your ideas for new features or improvements
3. **Submit PRs**: Fix bugs, add features, or improve documentation
4. **Improve Docs**: Help make the documentation clearer and more comprehensive
5. **Share**: Star the project and share it with others

### Contribution Guidelines

- Follow existing code style and conventions
- Write clear commit messages
- Add tests for new features
- Update documentation as needed
- Keep PRs focused on a single change

## 🔗 Related Projects

- [HAProxy](https://www.haproxy.org/) - The load balancer being managed
- [FastAPI](https://fastapi.tiangolo.com/) - Backend framework
- [React.js](https://reactjs.org/) - Frontend framework
- [Ant Design](https://ant.design/) - UI component library

---

**Made with ❤️ for the HAProxy community**
