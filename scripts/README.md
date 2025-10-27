# HAProxy OpenManager - Utility Scripts

This directory contains utility scripts for managing, monitoring, and troubleshooting HAProxy OpenManager.

## 🧹 Cleanup Scripts

### cleanup-cluster-entities.sh
**Purpose:** Clean all frontends and backends from a specific cluster

**Usage:**
```bash
# Interactive mode (prompts for cluster)
./scripts/cleanup-cluster-entities.sh

# Direct cluster specification
./scripts/cleanup-cluster-entities.sh "demo-cluster"
./scripts/cleanup-cluster-entities.sh 1
```

**Features:**
- Interactive cluster selection (by name or ID)
- Safety confirmation prompts  
- Automatic HAProxy config apply
- Comprehensive status reporting
- Preserves cluster (only deletes entities)

### cleanup-soft-deleted.sh
**Purpose:** Permanently delete soft-deleted entities from database

**Usage:**
```bash
./scripts/cleanup-soft-deleted.sh
```

**Features:**
- Database health check
- Dry run preview
- Double confirmation (yes + CONFIRM)
- Verification after cleanup
- Detailed entity deletion report

## 🔧 Agent Scripts

### fix-agent-status.sh
Fix agents stuck in 'upgrading' status

### update-agent-version.sh  
Update agent script versions

## 🔍 Monitoring & Debugging Scripts

### check-agent-logs.sh
Check agent log files for errors

### check-agent-stats.sh
Verify agent statistics collection  

### check-haproxy-stats-socket.sh
Test HAProxy stats socket connectivity

### debug-agent-stats-function.sh
Debug agent stats collection functions

### test-agent-stats-sending.sh
Test agent stats sending functionality

### test-real-heartbeat.sh
Test agent heartbeat functionality

### test-stats-parser.py
Test HAProxy stats parsing

## 🏗️ Build & Test Scripts

### test-build.sh
Run build tests for the project

## 🚨 Emergency Use Cases

**1. Cluster Migration/Cleanup:**
```bash
# Clean old cluster completely
./scripts/cleanup-cluster-entities.sh "old-cluster"

# Clean soft-deleted entities
./scripts/cleanup-soft-deleted.sh
```

**2. Database Maintenance:**
```bash
# Regular cleanup of soft-deleted entities
./scripts/cleanup-soft-deleted.sh
```

**3. Agent Issues:**
```bash
# Fix stuck agents
./scripts/fix-agent-status.sh

# Debug stats problems
./scripts/debug-agent-stats-function.sh
```

## ⚠️ Safety Notes

- All cleanup scripts require admin authentication
- Cluster entity cleanup preserves the cluster itself
- Soft-delete cleanup is permanent and cannot be undone
- Always use dry-run features when available
- Test in development environment first

## 🔗 Related Documentation

- [Testing Guide](../TESTING.md)
- [Impact Analysis](../IMPACT_ANALYSIS.md)
- [Configuration Guide](../CONFIG.md)
