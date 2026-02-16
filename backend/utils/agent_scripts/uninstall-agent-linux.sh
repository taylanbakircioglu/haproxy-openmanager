#!/bin/bash
# HAProxy Agent Uninstaller for Linux
# Run with: sudo ./uninstall-agent-linux.sh
# Removes agent service, binary, config, logs. HAProxy untouched.

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run as root: sudo $0"
    exit 1
fi

echo "=========================================="
echo "HAProxy Agent Uninstaller for Linux"
echo "=========================================="
echo ""

SELF_PID=$$

# ===========================================
# SAFETY: Define protected HAProxy paths
# These must NEVER be touched by this script
# ===========================================
PROTECTED_PATHS=(
    "/etc/haproxy"
    "/etc/haproxy/haproxy.cfg"
    "/usr/sbin/haproxy"
    "/usr/local/sbin/haproxy"
    "/var/log/haproxy"
    "/var/run/haproxy"
    "/run/haproxy"
    "/etc/systemd/system/haproxy.service"
    "/lib/systemd/system/haproxy.service"
    "/usr/lib/systemd/system/haproxy.service"
)

# Safety helper: refuse to remove anything that is a protected HAProxy path
safe_rm() {
    local target="$1"
    for protected in "${PROTECTED_PATHS[@]}"; do
        if [[ "$target" == "$protected" || "$target" == "$protected/" ]]; then
            echo "  BLOCKED: Refusing to remove protected HAProxy path: $target"
            return 1
        fi
    done
    # Extra guard: path must contain "haproxy-agent" or be in /tmp
    if [[ "$target" != *"haproxy-agent"* && "$target" != /tmp/* ]]; then
        echo "  BLOCKED: Path does not contain 'haproxy-agent': $target"
        return 1
    fi
    rm -rf "$target" 2>/dev/null && echo "  Removed $target"
    return 0
}

# --- Pre-flight: verify HAProxy is safe ---
echo "[0/5] Safety check..."
if [[ -f /etc/haproxy/haproxy.cfg ]]; then
    echo "  HAProxy config found at /etc/haproxy/haproxy.cfg - will be preserved"
fi
if systemctl is-active haproxy.service &>/dev/null; then
    echo "  HAProxy service is running - will NOT be touched"
fi
echo "  Protected paths: haproxy.service, /etc/haproxy/, /usr/sbin/haproxy, /var/log/haproxy"
echo ""

# --- 1. Stop and remove systemd service ---
echo "[1/5] Stopping agent systemd service..."
# SAFETY: Only touch services with "agent" in the name
for svc in haproxy-agent.service haproxy.agent.service; do
    systemctl stop "$svc" 2>/dev/null
    systemctl disable "$svc" 2>/dev/null
    systemctl unmask "$svc" 2>/dev/null
done
# SAFETY: Only remove unit files that contain "agent" in filename
for f in \
    /etc/systemd/system/haproxy-agent.service \
    /etc/systemd/system/haproxy.agent.service \
    /lib/systemd/system/haproxy-agent.service \
    /usr/lib/systemd/system/haproxy-agent.service \
    /etc/systemd/user/haproxy-agent.service; do
    rm -f "$f" 2>/dev/null && echo "  Removed $f"
done
systemctl daemon-reload 2>/dev/null
systemctl reset-failed 2>/dev/null
echo "  Done"
echo ""

# --- 2. Kill agent processes (exclude self and haproxy) ---
echo "[2/5] Killing agent processes..."
agent_pids=$(pgrep -f "haproxy-agent" 2>/dev/null || true)
# SAFETY: Get HAProxy master PID to never kill it
haproxy_master_pid=$(pgrep -x "haproxy" 2>/dev/null || true)
if [[ -n "$agent_pids" ]]; then
    for p in $agent_pids; do
        # Skip self, parent, and HAProxy master process
        if [[ "$p" == "$SELF_PID" || "$p" == "$PPID" ]]; then
            continue
        fi
        # SAFETY: Double-check this is not a haproxy process
        proc_cmd=$(ps -p "$p" -o args= 2>/dev/null || true)
        if [[ -n "$proc_cmd" && "$proc_cmd" != *"haproxy-agent"* ]]; then
            echo "  SKIPPED PID $p: not an agent process ($proc_cmd)"
            continue
        fi
        if [[ -n "$haproxy_master_pid" ]] && echo "$haproxy_master_pid" | grep -q "^${p}$"; then
            echo "  SKIPPED PID $p: HAProxy master process - protected"
            continue
        fi
        kill -9 "$p" 2>/dev/null && echo "  Killed PID $p"
    done
    sleep 1
else
    echo "  No agent processes found"
fi
echo ""

# --- 3. Remove agent binary ---
echo "[3/5] Removing agent binary..."
# SAFETY: Only files named exactly "haproxy-agent", never "haproxy"
for f in \
    /usr/local/bin/haproxy-agent \
    /usr/bin/haproxy-agent \
    /usr/sbin/haproxy-agent \
    /sbin/haproxy-agent \
    /opt/bin/haproxy-agent; do
    if [[ -f "$f" ]]; then
        # Final guard: verify filename is haproxy-agent, not haproxy
        basename_f=$(basename "$f")
        if [[ "$basename_f" == "haproxy-agent" ]]; then
            rm -f "$f" 2>/dev/null && echo "  Removed $f"
        else
            echo "  BLOCKED: Unexpected filename: $f"
        fi
    fi
done
echo "  Done"
echo ""

# --- 4. Remove config, logs, PID files, temp files ---
echo "[4/5] Removing agent config, logs, and temp files..."

# Config and data directories - all contain "haproxy-agent" in path
for d in \
    /etc/haproxy-agent \
    /var/log/haproxy-agent \
    /var/lib/haproxy-agent \
    /usr/local/etc/haproxy-agent \
    /usr/local/share/haproxy-agent \
    /usr/local/share/haproxy-agent-backups \
    /opt/haproxy-agent; do
    safe_rm "$d"
done

# PID files
for f in \
    /var/run/haproxy-agent.pid \
    /run/haproxy-agent.pid \
    /tmp/haproxy-agent.pid; do
    safe_rm "$f"
done

# Clean up agent temp files in /tmp
find /tmp -maxdepth 1 -name "haproxy-agent*" -exec rm -rf {} \; 2>/dev/null
find /tmp -maxdepth 1 -name "heartbeat_payload_*" -exec rm -f {} \; 2>/dev/null
find /tmp -maxdepth 1 -name "heartbeat_response_*" -exec rm -f {} \; 2>/dev/null
find /tmp -maxdepth 1 -name "haproxy-failed-*" -exec rm -f {} \; 2>/dev/null
find /tmp -maxdepth 1 -name "haproxy_new_*" -exec rm -f {} \; 2>/dev/null
find /tmp -maxdepth 1 -name "haproxy-merged*" -exec rm -f {} \; 2>/dev/null
find /tmp -maxdepth 1 -name "ssl_cert_*" -exec rm -f {} \; 2>/dev/null
rm -f /tmp/agent_debug.log /tmp/debug_agent.log /tmp/haproxy-new-config.cfg 2>/dev/null

# Clean agent-related cron entries
if grep -q "haproxy-agent" /etc/cron.d/haproxy-agent 2>/dev/null; then
    rm -f /etc/cron.d/haproxy-agent 2>/dev/null && echo "  Removed cron job"
fi
for cf in /etc/crontab /var/spool/cron/root /var/spool/cron/crontabs/root; do
    if [[ -f "$cf" ]] && grep -q "haproxy-agent" "$cf" 2>/dev/null; then
        sed -i '/haproxy-agent/d' "$cf" 2>/dev/null && echo "  Cleaned $cf"
    fi
done
echo "  Done"
echo ""

# --- 5. Verify ---
echo "[5/5] Verifying..."
ok=true
if pgrep -f "haproxy-agent" 2>/dev/null | grep -v "^${SELF_PID}$" | grep -v "^${PPID}$" | grep -q .; then
    echo "  WARNING: Agent processes still running"
    ok=false
fi
if [[ -d /etc/haproxy-agent ]]; then
    echo "  WARNING: /etc/haproxy-agent still exists"
    ok=false
fi
if [[ -f /usr/local/bin/haproxy-agent ]]; then
    echo "  WARNING: /usr/local/bin/haproxy-agent still exists"
    ok=false
fi
if $ok; then
    echo "  Agent completely removed."
fi

echo ""
echo "--- HAProxy integrity check ---"
if [[ -f /etc/haproxy/haproxy.cfg ]]; then
    echo "  /etc/haproxy/haproxy.cfg    : OK (untouched)"
else
    echo "  /etc/haproxy/haproxy.cfg    : not found (was not present before)"
fi
if systemctl is-active haproxy.service &>/dev/null; then
    echo "  haproxy.service             : running"
elif systemctl is-enabled haproxy.service &>/dev/null; then
    echo "  haproxy.service             : stopped (was not running before)"
else
    echo "  haproxy.service             : not installed"
fi
if [[ -f /usr/sbin/haproxy ]]; then
    echo "  /usr/sbin/haproxy           : OK (untouched)"
fi

echo ""
echo "=========================================="
echo "Done. HAProxy itself was not touched."
echo "=========================================="
