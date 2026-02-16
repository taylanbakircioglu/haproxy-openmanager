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

# ===========================================
# SAFETY: Define protected HAProxy paths
# These must NEVER be touched by this script
# ===========================================
PROTECTED_PATHS=(
    "/etc/haproxy"
    "/etc/haproxy/haproxy.cfg"
    "/usr/local/sbin/haproxy"
    "/opt/homebrew/sbin/haproxy"
    "/usr/local/bin/haproxy"
    "/opt/homebrew/bin/haproxy"
    "/usr/local/etc/haproxy"
    "/opt/homebrew/etc/haproxy"
    "/var/log/haproxy"
    "/usr/local/var/log/haproxy"
    "/opt/homebrew/var/log/haproxy"
    "/Library/LaunchDaemons/com.haproxy.plist"
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
haproxy_bin=$(which haproxy 2>/dev/null || true)
if [[ -n "$haproxy_bin" ]]; then
    echo "  HAProxy binary found at $haproxy_bin - will be preserved"
fi
haproxy_cfg=""
for cfg in /etc/haproxy/haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg /opt/homebrew/etc/haproxy/haproxy.cfg; do
    if [[ -f "$cfg" ]]; then
        haproxy_cfg="$cfg"
        echo "  HAProxy config found at $cfg - will be preserved"
        break
    fi
done
echo "  Protected: haproxy binary, haproxy config, haproxy logs, haproxy LaunchDaemon"
echo ""

# --- 1. Stop and remove launchd service ---
echo "[1/5] Stopping agent launchd service..."
# SAFETY: Only touch services with "agent" in the name
for svc in com.haproxy.agent haproxy.agent haproxy-agent com.haproxy-agent; do
    launchctl stop "$svc" 2>/dev/null
    launchctl unload "/Library/LaunchDaemons/$svc.plist" 2>/dev/null
    launchctl unload "/Library/LaunchAgents/$svc.plist" 2>/dev/null
    launchctl remove "$svc" 2>/dev/null
done
# SAFETY: Only remove plist files that contain "agent" in filename
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
    /opt/homebrew/bin/haproxy-agent \
    /usr/bin/haproxy-agent \
    /opt/homebrew/sbin/haproxy-agent \
    /usr/sbin/haproxy-agent; do
    if [[ -f "$f" ]]; then
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
    safe_rm "$d"
done

for f in \
    /var/run/haproxy-agent.pid \
    /tmp/haproxy-agent.pid \
    /usr/local/var/run/haproxy-agent.pid \
    /opt/homebrew/var/run/haproxy-agent.pid; do
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
if [[ -f /usr/local/bin/haproxy-agent ]] || [[ -f /opt/homebrew/bin/haproxy-agent ]]; then
    echo "  WARNING: agent binary still exists"
    ok=false
fi
if $ok; then
    echo "  Agent completely removed."
fi

echo ""
echo "--- HAProxy integrity check ---"
if [[ -n "$haproxy_cfg" && -f "$haproxy_cfg" ]]; then
    echo "  $haproxy_cfg    : OK (untouched)"
fi
if [[ -n "$haproxy_bin" && -f "$haproxy_bin" ]]; then
    echo "  $haproxy_bin              : OK (untouched)"
fi
if launchctl list 2>/dev/null | grep -q "haproxy" | grep -v "agent"; then
    echo "  HAProxy LaunchDaemon       : running"
fi

echo ""
echo "=========================================="
echo "Done. HAProxy itself was not touched."
echo "=========================================="
