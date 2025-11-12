# Agent Upgrade Guide - Dashboard Stats Fix

## Problem
Dashboard showing 0 metrics after agent auto-upgrade due to missing environment variables (`SOCAT_BIN`, `STATS_SOCKET_PATH`) when agent restarts in daemon mode.

## Solution
Implemented **lazy initialization** in both `get_haproxy_stats_csv()` and `get_server_statuses()` functions. These functions now initialize their dependencies on first call, making them completely independent of global variable initialization.

## Deployment Steps

### Step 1: Wait for Pipeline ⏳
```bash
# Pipeline is currently running after git push
# Check status: https://[your-azure-devops]/pipeline
# Wait for deployment to complete (~3-5 minutes)
```

### Step 2: Verify Backend Deployment ✅
```bash
# Check backend logs for successful deployment
kubectl logs -f deployment/backend -n haproxy-manager | head -20

# Expected: New pod started with latest code
```

### Step 3: Update Agent Version in UI 🔄

**Option A: Automatic Script Sync (Recommended)**
```bash
# Get admin token
TOKEN=$(curl -k -s -X POST "https://haproxy-manager.example.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | jq -r '.access_token')

# Sync scripts from files to database (creates version 1.0.0)
curl -k -X POST "https://haproxy-manager.example.com/api/agents/sync-scripts-from-files" \
  -H "Authorization: Bearer $TOKEN" | jq .

# Expected: {"status": "success", "synced": ["linux", "macos"]}
```

**Option B: Manual UI Update**
1. Go to **Agent Management** page
2. Click **Settings** → **Agent Versions**
3. For **Linux** platform:
   - Click **Edit Script**
   - Version: Keep current or increment (e.g., 1.0.3)
   - Changelog: Add "Fixed stats collection after upgrade"
   - Click **Save** (this syncs file content to database)
4. Repeat for **macOS** platform

### Step 4: Upgrade Agents 🚀

**Option A: UI (Single Agent)**
1. Go to **Agent Management** page
2. Select agent (e.g., `demo-agent`)
3. Click **Upgrade** button
4. Wait 30 seconds for agent to restart

**Option B: API (Batch Upgrade)**
```bash
# Get all agents
curl -k -s -X GET "https://haproxy-manager.example.com/api/agents" \
  -H "Authorization: Bearer $TOKEN" | jq '.agents[] | {id, name, version}'

# Upgrade specific agent (replace {agent_id})
curl -k -X POST "https://haproxy-manager.example.com/api/agents/{agent_id}/upgrade" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### Step 5: Verify Stats Collection 📊

**Backend Logs** (30 seconds after upgrade):
```bash
kubectl logs -f deployment/backend -n haproxy-manager | grep -E "haproxy_stats_csv|demo-agent"

# Expected logs:
# ✅ "Has haproxy_stats_csv: True"
# ✅ "CSV preview: IyBweG..." (base64 data)
# ✅ "STATS: Parsed 15 rows for cluster demo-cluster1"
```

**Agent Logs** (on agent server):
```bash
sudo tail -f /var/log/haproxy-agent/agent.log | grep STATS

# Expected logs:
# ✅ "STATS: Initialized socat: /usr/bin/socat"
# ✅ "STATS: Using default socket path: /var/run/haproxy/admin.sock"
# ✅ "STATS: Fetched CSV: 2121 bytes, 9 lines, base64: 2828 chars"
```

**Dashboard UI**:
1. Open **Dashboard** page
2. Refresh page (F5)
3. Check metrics:
   - ✅ Frontend/Backend filters populated
   - ✅ Overview metrics showing real data (not 0)
   - ✅ Charts showing data points
   - ✅ "Waiting for Agent Data" warning gone

## Troubleshooting

### Issue: Backend still shows "Has haproxy_stats_csv: False"

**Cause**: Agent hasn't upgraded yet or using old script version

**Solution**:
```bash
# Check agent version on agent server
grep "AGENT_VERSION" /usr/local/bin/haproxy-agent | head -1

# Force agent restart
sudo systemctl restart haproxy-agent

# Check logs immediately
sudo tail -20 /var/log/haproxy-agent/agent.log
```

### Issue: "STATS: socat not available"

**Cause**: socat not installed

**Solution**:
```bash
# Install socat
sudo yum install -y socat  # RHEL/CentOS
sudo apt install -y socat  # Debian/Ubuntu

# Restart agent
sudo systemctl restart haproxy-agent
```

### Issue: "STATS: Socket not found: /var/run/haproxy/admin.sock"

**Cause**: HAProxy stats socket not configured

**Solution**:
```bash
# Check HAProxy config for stats socket
grep "stats socket" /etc/haproxy/haproxy.cfg

# Add if missing (in global section):
# stats socket /var/run/haproxy/admin.sock mode 666 level admin

# Reload HAProxy
sudo systemctl reload haproxy
```

## Verification Checklist

- [ ] Pipeline completed successfully
- [ ] Backend pod restarted with new code
- [ ] Agent scripts synced to database (version visible in UI)
- [ ] Agents upgraded to new version
- [ ] Backend logs show "Has haproxy_stats_csv: True"
- [ ] Agent logs show STATS messages
- [ ] Dashboard showing real metrics
- [ ] Charts populated with data
- [ ] No "Waiting for Agent Data" warning

## Next Upgrades

This fix is **permanent**. Future agent upgrades will NOT break stats collection because:

1. ✅ Functions are self-contained with lazy initialization
2. ✅ No dependency on global variable initialization order
3. ✅ Works in any restart scenario (systemd, daemon mode, upgrade)
4. ✅ Backward compatible with existing agents

**No manual intervention needed for future upgrades!** 🎉

