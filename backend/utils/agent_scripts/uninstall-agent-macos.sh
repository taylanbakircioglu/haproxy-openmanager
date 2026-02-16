#!/bin/bash
# HAProxy Agent Uninstaller for macOS
# Run with: sudo ./uninstall-agent-macos.sh
# Removes agent service, binary, config, logs. HAProxy untouched.

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run as root: sudo $0"
    exit 1
fi

echo "=========================================="
echo "HAProxy Agent Uninstaller for macOS"
echo "=========================================="
echo ""

SELF_PID=$$

# --- 1. Stop and remove launchd service ---
echo "[1/5] Stopping launchd service..."
for svc in com.haproxy.agent haproxy.agent haproxy-agent com.haproxy-agent; do
    launchctl stop "$svc" 2>/dev/null
    launchctl unload "/Library/LaunchDaemons/$svc.plist" 2>/dev/null
    launchctl unload "/Library/LaunchAgents/$svc.plist" 2>/dev/null
    launchctl remove "$svc" 2>/dev/null
done
for svc in com.haproxy.agent haproxy.agent haproxy-agent com.haproxy-agent; do
    for f in \
        "/Library/LaunchDaemons/$svc.plist" \
        "/Library/LaunchAgents/$svc.plist" \
        "$HOME/Library/LaunchAgents/$svc.plist"; do
        rm -f "$f" 2>/dev/null && echo "  Removed $f"
    done
done
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
    /opt/homebrew/bin/haproxy-agent \
    /usr/bin/haproxy-agent \
    /opt/homebrew/sbin/haproxy-agent \
    /usr/sbin/haproxy-agent; do
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
    /opt/homebrew/etc/haproxy-agent \
    /usr/local/var/log/haproxy-agent \
    /opt/homebrew/var/log/haproxy-agent \
    /usr/local/share/haproxy-agent \
    /usr/local/share/haproxy-agent-backups \
    /opt/homebrew/share/haproxy-agent \
    /opt/homebrew/share/haproxy-agent-backups; do
    rm -rf "$d" 2>/dev/null && echo "  Removed $d"
done
for f in \
    /var/run/haproxy-agent.pid \
    /tmp/haproxy-agent.pid \
    /usr/local/var/run/haproxy-agent.pid \
    /opt/homebrew/var/run/haproxy-agent.pid; do
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
