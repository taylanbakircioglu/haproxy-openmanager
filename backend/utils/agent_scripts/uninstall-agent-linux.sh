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

# --- 1. Stop and remove systemd service ---
echo "[1/5] Stopping systemd service..."
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
    rm -f "$f" 2>/dev/null && echo "  Removed $f"
done
systemctl daemon-reload 2>/dev/null
systemctl reset-failed 2>/dev/null
echo "  Done"
echo ""

# --- 2. Kill agent processes (exclude self) ---
echo "[2/5] Killing agent processes..."
agent_pids=$(pgrep -f "haproxy-agent" 2>/dev/null || true)
if [[ -n "$agent_pids" ]]; then
    for p in $agent_pids; do
        if [[ "$p" != "$SELF_PID" && "$p" != "$PPID" ]]; then
            kill -9 "$p" 2>/dev/null && echo "  Killed PID $p"
        fi
    done
    sleep 1
else
    echo "  No agent processes found"
fi
echo ""

# --- 3. Remove binary ---
echo "[3/5] Removing agent binary..."
for f in \
    /usr/local/bin/haproxy-agent \
    /usr/bin/haproxy-agent \
    /usr/sbin/haproxy-agent \
    /sbin/haproxy-agent \
    /opt/bin/haproxy-agent; do
    rm -f "$f" 2>/dev/null && echo "  Removed $f"
done
echo "  Done"
echo ""

# --- 4. Remove config, logs, PID files, temp files ---
echo "[4/5] Removing config, logs, and temp files..."
for d in \
    /etc/haproxy-agent \
    /var/log/haproxy-agent \
    /var/lib/haproxy-agent \
    /usr/local/etc/haproxy-agent \
    /usr/local/share/haproxy-agent \
    /usr/local/share/haproxy-agent-backups \
    /opt/haproxy-agent; do
    rm -rf "$d" 2>/dev/null && echo "  Removed $d"
done
for f in \
    /var/run/haproxy-agent.pid \
    /run/haproxy-agent.pid \
    /tmp/haproxy-agent.pid; do
    rm -f "$f" 2>/dev/null && echo "  Removed $f"
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
# Clean cron
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
echo "=========================================="
echo "Done. HAProxy itself was not touched."
echo "=========================================="
