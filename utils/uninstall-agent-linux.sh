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

# Safety: only remove paths containing "haproxy-agent" or under /tmp
safe_rm() {
    local target="$1"
    if [[ "$target" != *"haproxy-agent"* && "$target" != /tmp/* ]]; then
        echo "  BLOCKED: '$target' does not contain 'haproxy-agent' - skipping"
        return 1
    fi
    if [[ -e "$target" ]]; then
        rm -rf "$target" 2>/dev/null && echo "  Removed $target" || echo "  FAILED to remove $target"
    fi
    return 0
}

# Snapshot HAProxy state before we start
echo "[pre] HAProxy status before uninstall:"
haproxy_was_active=$(systemctl is-active haproxy.service 2>/dev/null || echo "unknown")
haproxy_cfg_hash=""
if [[ -f /etc/haproxy/haproxy.cfg ]]; then
    haproxy_cfg_hash=$(md5sum /etc/haproxy/haproxy.cfg 2>/dev/null | awk '{print $1}')
    echo "  Config : /etc/haproxy/haproxy.cfg (md5: $haproxy_cfg_hash)"
fi
echo "  Service: haproxy.service ($haproxy_was_active)"
echo ""

# --- 1. Stop and remove agent systemd service ---
echo "[1/5] Stopping agent systemd service..."
for svc in haproxy-agent.service haproxy.agent.service; do
    systemctl stop "$svc" 2>/dev/null
    systemctl disable "$svc" 2>/dev/null
    systemctl unmask "$svc" 2>/dev/null
done
for f in \
    /etc/systemd/system/haproxy-agent.service \
    /etc/systemd/system/haproxy.agent.service \
    /lib/systemd/system/haproxy-agent.service \
    /usr/lib/systemd/system/haproxy-agent.service \
    /etc/systemd/user/haproxy-agent.service; do
    safe_rm "$f"
done
systemctl daemon-reload 2>/dev/null
systemctl reset-failed 2>/dev/null
echo "  Done"
echo ""

# --- 2. Kill agent processes ---
echo "[2/5] Killing agent processes..."
found=0
for p in $(pgrep -f "haproxy-agent" 2>/dev/null || true); do
    [[ "$p" == "$SELF_PID" || "$p" == "$PPID" ]] && continue
    # Verify process command actually contains "haproxy-agent"
    cmd=$(ps -p "$p" -o args= 2>/dev/null || true)
    if [[ "$cmd" == *"haproxy-agent"* ]]; then
        kill -9 "$p" 2>/dev/null && echo "  Killed PID $p ($cmd)" && found=$((found + 1))
    fi
done
[[ $found -eq 0 ]] && echo "  No agent processes found"
echo ""

# --- 3. Remove agent binary ---
echo "[3/5] Removing agent binary..."
for f in \
    /usr/local/bin/haproxy-agent \
    /usr/bin/haproxy-agent \
    /usr/sbin/haproxy-agent \
    /sbin/haproxy-agent \
    /opt/bin/haproxy-agent; do
    safe_rm "$f"
done
echo "  Done"
echo ""

# --- 4. Remove config, logs, PID, temp files ---
echo "[4/5] Removing agent config, logs, and temp files..."
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
for f in \
    /var/run/haproxy-agent.pid \
    /run/haproxy-agent.pid \
    /tmp/haproxy-agent.pid; do
    safe_rm "$f"
done
# Agent temp files
find /tmp -maxdepth 1 \( \
    -name "haproxy-agent*" -o \
    -name "heartbeat_payload_*" -o \
    -name "heartbeat_response_*" -o \
    -name "haproxy-failed-*" -o \
    -name "haproxy_new_*" -o \
    -name "haproxy-merged*" -o \
    -name "ssl_cert_*" \
    \) -exec rm -rf {} \; 2>/dev/null
rm -f /tmp/agent_debug.log /tmp/debug_agent.log /tmp/haproxy-new-config.cfg 2>/dev/null
# Cron
if [[ -f /etc/cron.d/haproxy-agent ]]; then
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
$ok && echo "  Agent completely removed."

# Verify HAProxy was not affected
echo ""
echo "[post] HAProxy integrity after uninstall:"
haproxy_now_active=$(systemctl is-active haproxy.service 2>/dev/null || echo "unknown")
echo "  Service: haproxy.service ($haproxy_now_active)"
if [[ "$haproxy_was_active" == "active" && "$haproxy_now_active" != "active" ]]; then
    echo "  ERROR: HAProxy was running but is now stopped!"
fi
if [[ -f /etc/haproxy/haproxy.cfg ]]; then
    haproxy_cfg_hash_after=$(md5sum /etc/haproxy/haproxy.cfg 2>/dev/null | awk '{print $1}')
    if [[ "$haproxy_cfg_hash" == "$haproxy_cfg_hash_after" ]]; then
        echo "  Config : unchanged (md5: $haproxy_cfg_hash_after)"
    else
        echo "  ERROR: HAProxy config was modified!"
    fi
fi

echo ""
echo "=========================================="
echo "Done. HAProxy itself was not touched."
echo "=========================================="
