#!/bin/bash
# HAProxy Agent Uninstaller for macOS - Complete Agent Cleanup
# Run with: sudo ./uninstall-agent-macos.sh
# Removes ALL agent components while keeping HAProxy intact
#
# IMPORTANT: 'set -e' intentionally NOT used here.
# safe_remove returns non-zero for missing files which would cause
# premature exit before cleaning up config, logs, and binaries.

echo "=========================================="
echo "HAProxy Agent Uninstaller for macOS v6.0"
echo "Complete Agent Cleanup"
echo "=========================================="

# Check root permissions
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root"
    echo "  Please run: sudo $0"
    exit 1
fi

echo ""
echo "Starting complete agent cleanup (HAProxy untouched)..."
echo ""

# --------------------------------------------
# Helper: safely remove a file or directory
# Always returns 0 so the script never exits early
# --------------------------------------------
safe_remove() {
    local path="$1"
    local desc="$2"

    if [[ -e "$path" ]]; then
        rm -rf "$path" 2>/dev/null || true
        if [[ ! -e "$path" ]]; then
            echo "  [REMOVED] $desc"
        else
            echo "  [WARN]    Failed to remove $desc"
        fi
    else
        echo "  [SKIP]    $desc (not found)"
    fi
    return 0
}

# --------------------------------------------
# 1. Terminate all agent processes
# --------------------------------------------
echo "[1/6] Terminating agent processes..."

killed_count=0
patterns=(
    "haproxy-agent"
    "/usr/local/bin/haproxy-agent"
    "/opt/homebrew/bin/haproxy-agent"
    "com.haproxy.agent"
    "haproxy-agent daemon"
    "bash.*haproxy-agent"
    "nohup.*haproxy-agent"
)

for pattern in "${patterns[@]}"; do
    pids=$(pgrep -f "$pattern" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        echo "  Killing processes matching: $pattern (PIDs: $pids)"
        kill -TERM $pids 2>/dev/null || true
        sleep 2
        # Force kill if still running
        remaining=$(pgrep -f "$pattern" 2>/dev/null || true)
        if [[ -n "$remaining" ]]; then
            echo "  Force killing remaining: $remaining"
            kill -KILL $remaining 2>/dev/null || true
            sleep 1
        fi
        killed_count=$((killed_count + $(echo "$pids" | wc -w)))
    fi
done

# Final sweep
final_pids=$(pgrep -f "haproxy-agent" 2>/dev/null || true)
if [[ -n "$final_pids" ]]; then
    echo "  Final cleanup: force killing PIDs $final_pids"
    kill -KILL $final_pids 2>/dev/null || true
fi

if [[ $killed_count -gt 0 ]]; then
    echo "  Terminated $killed_count agent process(es)"
else
    echo "  No agent processes found"
fi
echo ""

# --------------------------------------------
# 2. Stop and remove launchd services
# --------------------------------------------
echo "[2/6] Cleaning up launchd services..."

services=(
    "com.haproxy.agent"
    "haproxy.agent"
    "haproxy-agent"
    "com.haproxy-agent"
)

for svc in "${services[@]}"; do
    if launchctl list 2>/dev/null | grep -q "$svc"; then
        echo "  Stopping and removing: $svc"
        launchctl stop "$svc" 2>/dev/null || true
        launchctl unload "/Library/LaunchDaemons/$svc.plist" 2>/dev/null || true
        launchctl unload "/Library/LaunchAgents/$svc.plist" 2>/dev/null || true
        launchctl remove "$svc" 2>/dev/null || true
    fi
done

# Remove plist files
for svc in "${services[@]}"; do
    safe_remove "/Library/LaunchDaemons/$svc.plist" "LaunchDaemon: $svc"
    safe_remove "/Library/LaunchAgents/$svc.plist" "LaunchAgent: $svc"
    safe_remove "$HOME/Library/LaunchAgents/$svc.plist" "User LaunchAgent: $svc"
done
echo ""

# --------------------------------------------
# 3. Remove agent binaries
# --------------------------------------------
echo "[3/6] Removing agent binaries..."

bin_paths=(
    "/usr/local/bin/haproxy-agent"
    "/opt/homebrew/bin/haproxy-agent"
    "/usr/bin/haproxy-agent"
    "/bin/haproxy-agent"
    "/opt/homebrew/sbin/haproxy-agent"
    "/usr/sbin/haproxy-agent"
    "/sbin/haproxy-agent"
)

for bp in "${bin_paths[@]}"; do
    safe_remove "$bp" "binary: $bp"
done

# Deep search for any remaining binaries
found_extra=$(find /usr /opt /Applications -name "haproxy-agent" -type f 2>/dev/null || true)
if [[ -n "$found_extra" ]]; then
    while IFS= read -r extra; do
        safe_remove "$extra" "binary (deep search): $extra"
    done <<< "$found_extra"
fi
echo ""

# --------------------------------------------
# 4. Remove ALL agent configuration and data
# --------------------------------------------
echo "[4/6] Removing agent configuration and data..."

config_dirs=(
    "/etc/haproxy-agent"
    "/opt/homebrew/etc/haproxy-agent"
    "/usr/local/etc/haproxy-agent"
    "/var/lib/haproxy-agent"
    "/usr/local/share/haproxy-agent"
    "/usr/local/share/haproxy-agent-backups"
    "/opt/homebrew/share/haproxy-agent"
    "/opt/homebrew/share/haproxy-agent-backups"
)

for cd in "${config_dirs[@]}"; do
    safe_remove "$cd" "config dir: $cd"
done

log_dirs=(
    "/var/log/haproxy-agent"
    "/opt/homebrew/var/log/haproxy-agent"
    "/usr/local/var/log/haproxy-agent"
    "/tmp/haproxy-agent-logs"
)

for ld in "${log_dirs[@]}"; do
    safe_remove "$ld" "log dir: $ld"
done

pid_files=(
    "/var/run/haproxy-agent.pid"
    "/tmp/haproxy-agent.pid"
    "/usr/local/var/run/haproxy-agent.pid"
    "/opt/homebrew/var/run/haproxy-agent.pid"
)

for pf in "${pid_files[@]}"; do
    safe_remove "$pf" "PID file: $pf"
done
echo ""

# --------------------------------------------
# 5. Remove temporary files, markers, sockets
# --------------------------------------------
echo "[5/6] Cleaning up temporary files and markers..."

# Fixed-name temp files
fixed_temps=(
    "/tmp/agent_debug.log"
    "/tmp/debug_agent.log"
    "/tmp/fixed_agent_test.log"
    "/tmp/agent-startup-with-config.sh"
    "/tmp/haproxy-new-config.cfg"
)

for ft in "${fixed_temps[@]}"; do
    safe_remove "$ft" "temp: $ft"
done

# Wildcard patterns - files
wildcard_file_patterns=(
    "haproxy-agent-*"
    "daemon-test-agent*.sh"
    "haproxy-failed-*.cfg"
    "haproxy_new_*.cfg"
    "haproxy-merged*.cfg"
    "haproxy-global*.cfg"
    "haproxy-defaults*.cfg"
    "haproxy-listen*.cfg"
    "haproxy-agent-upgrade-complete-*"
    "haproxy-agent-upgrade-test-*"
    "haproxy-agent-*.pid"
    "haproxy-agent-ssl-sync-*"
    "heartbeat_payload_*.json"
    "heartbeat_response_*.txt"
    "ssl_cert_*.pem"
)

for wp in "${wildcard_file_patterns[@]}"; do
    for search_dir in "/tmp" "/var/tmp"; do
        if [[ -d "$search_dir" ]]; then
            found=$(find "$search_dir" -maxdepth 1 -name "$wp" 2>/dev/null || true)
            if [[ -n "$found" ]]; then
                while IFS= read -r f; do
                    safe_remove "$f" "temp: $f"
                done <<< "$found"
            fi
        fi
    done
done

# Wildcard patterns - sockets
for search_dir in "/tmp" "/var/run"; do
    if [[ -d "$search_dir" ]]; then
        found_sockets=$(find "$search_dir" -maxdepth 1 -name "haproxy-agent-*" -type s 2>/dev/null || true)
        if [[ -n "$found_sockets" ]]; then
            while IFS= read -r sock; do
                safe_remove "$sock" "socket: $sock"
            done <<< "$found_sockets"
        fi
    fi
done
echo ""

# --------------------------------------------
# 6. Verification
# --------------------------------------------
echo "[6/6] Verifying cleanup..."

remaining_procs=$(pgrep -f "haproxy-agent" 2>/dev/null | wc -l || echo "0")
remaining_svcs=$(launchctl list 2>/dev/null | grep -c "haproxy.agent\|haproxy-agent" || echo "0")
remaining_bins=$(find /usr /opt /Applications -name "haproxy-agent" -type f 2>/dev/null | wc -l || echo "0")
remaining_conf=$(test -d "/etc/haproxy-agent" && echo "1" || echo "0")

echo ""
if [[ $remaining_procs -eq 0 && $remaining_svcs -eq 0 && $remaining_bins -eq 0 && $remaining_conf -eq 0 ]]; then
    echo "CLEANUP VERIFIED - Agent completely removed."
else
    echo "WARNING: Some agent remnants detected:"
    [[ $remaining_procs -gt 0 ]] && echo "  - $remaining_procs agent process(es) still running"
    [[ $remaining_svcs -gt 0 ]] && echo "  - $remaining_svcs agent service(s) still loaded"
    [[ $remaining_bins -gt 0 ]] && echo "  - $remaining_bins agent binary(ies) still found"
    [[ $remaining_conf -gt 0 ]] && echo "  - /etc/haproxy-agent/ config directory still exists"

    if [[ $remaining_bins -gt 0 ]]; then
        echo "  Remaining binaries:"
        find /usr /opt /Applications -name "haproxy-agent" -type f 2>/dev/null | while read -r b; do
            echo "    - $b"
        done
    fi

    if [[ $remaining_procs -gt 0 ]]; then
        echo "  Remaining processes:"
        pgrep -f "haproxy-agent" 2>/dev/null | while read -r pid; do
            ps -p "$pid" -o pid,ppid,command 2>/dev/null || true
        done
    fi
fi

echo ""
echo "=========================================="
echo "HAProxy Agent Uninstall Complete"
echo "=========================================="
echo ""
echo "What was removed:"
echo "  - All agent processes (including daemon mode)"
echo "  - All launchd services (stopped and unloaded)"
echo "  - All agent binaries"
echo "  - All agent config files (including config.json)"
echo "  - All agent logs"
echo "  - All agent temp files, markers, and sockets"
echo ""
echo "What was NOT touched:"
echo "  - HAProxy service"
echo "  - HAProxy configuration"
echo "  - HAProxy SSL certificates"
echo "  - HAProxy logs"
echo ""
echo "System is ready for fresh agent installation."
echo ""
echo "Verify with:"
echo "  ps aux | grep haproxy-agent"
echo "  launchctl list | grep haproxy"
echo "  ls -la /etc/haproxy-agent/"
