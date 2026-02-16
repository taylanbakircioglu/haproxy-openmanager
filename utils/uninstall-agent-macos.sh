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
haproxy_bin=$(which haproxy 2>/dev/null || true)
haproxy_cfg=""
haproxy_cfg_hash=""
for cfg in /etc/haproxy/haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg /opt/homebrew/etc/haproxy/haproxy.cfg; do
    if [[ -f "$cfg" ]]; then
        haproxy_cfg="$cfg"
        haproxy_cfg_hash=$(md5 -q "$cfg" 2>/dev/null || true)
        echo "  Config : $cfg (md5: $haproxy_cfg_hash)"
        break
    fi
done
[[ -n "$haproxy_bin" ]] && echo "  Binary : $haproxy_bin"
echo ""

# --- 1. Stop and remove agent launchd service ---
echo "[1/5] Stopping agent launchd service..."
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
        [[ -f "$f" ]] && rm -f "$f" 2>/dev/null && echo "  Removed $f"
    done
done
echo "  Done"
echo ""

# --- 2. Kill agent processes ---
echo "[2/5] Killing agent processes..."
found=0
for p in $(pgrep -f "haproxy-agent" 2>/dev/null || true); do
    [[ "$p" == "$SELF_PID" || "$p" == "$PPID" ]] && continue
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
    /opt/homebrew/bin/haproxy-agent \
    /usr/bin/haproxy-agent \
    /opt/homebrew/sbin/haproxy-agent \
    /usr/sbin/haproxy-agent; do
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
$ok && echo "  Agent completely removed."

# Verify HAProxy was not affected
echo ""
echo "[post] HAProxy integrity after uninstall:"
if [[ -n "$haproxy_bin" && -f "$haproxy_bin" ]]; then
    echo "  Binary : $haproxy_bin (untouched)"
else
    [[ -n "$haproxy_bin" ]] && echo "  Binary : $haproxy_bin (was not present before)"
fi
if [[ -n "$haproxy_cfg" && -f "$haproxy_cfg" ]]; then
    haproxy_cfg_hash_after=$(md5 -q "$haproxy_cfg" 2>/dev/null || true)
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
