#!/bin/bash
# HAProxy Agent Uninstaller for Linux - Complete Agent Cleanup
# Run with: sudo ./uninstall-agent-linux.sh
# Removes ALL agent components while keeping HAProxy intact
#
# IMPORTANT: 'set -e' intentionally NOT used here.
# safe_remove returns non-zero for missing files which would cause
# premature exit before cleaning up config, logs, and binaries.

echo "=========================================="
echo "HAProxy Agent Uninstaller for Linux v6.0"
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
echo "[1/7] Terminating agent processes..."

killed_count=0
patterns=(
    "haproxy-agent"
    "/usr/local/bin/haproxy-agent"
    "/usr/bin/haproxy-agent"
    "haproxy-agent.service"
    "haproxy-agent daemon"
    "bash.*haproxy-agent"
    "nohup.*haproxy-agent"
)

SELF_PID=$$

for pattern in "${patterns[@]}"; do
    pids=$(pgrep -f "$pattern" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        # Filter out our own PID and parent PID to avoid killing ourselves
        filtered_pids=""
        for p in $pids; do
            if [[ "$p" != "$SELF_PID" && "$p" != "$PPID" ]]; then
                filtered_pids="$filtered_pids $p"
            fi
        done
        filtered_pids=$(echo "$filtered_pids" | xargs)
        if [[ -n "$filtered_pids" ]]; then
            echo "  Killing processes matching: $pattern (PIDs: $filtered_pids)"
            kill -TERM $filtered_pids 2>/dev/null || true
            sleep 2
            # Force kill if still running
            remaining=$(pgrep -f "$pattern" 2>/dev/null || true)
            if [[ -n "$remaining" ]]; then
                rem_filtered=""
                for p in $remaining; do
                    if [[ "$p" != "$SELF_PID" && "$p" != "$PPID" ]]; then
                        rem_filtered="$rem_filtered $p"
                    fi
                done
                rem_filtered=$(echo "$rem_filtered" | xargs)
                if [[ -n "$rem_filtered" ]]; then
                    echo "  Force killing remaining: $rem_filtered"
                    kill -KILL $rem_filtered 2>/dev/null || true
                    sleep 1
                fi
            fi
            killed_count=$((killed_count + $(echo "$filtered_pids" | wc -w)))
        fi
    fi
done

# Final sweep (exclude self)
final_pids=$(pgrep -f "haproxy-agent" 2>/dev/null || true)
if [[ -n "$final_pids" ]]; then
    final_filtered=""
    for p in $final_pids; do
        if [[ "$p" != "$SELF_PID" && "$p" != "$PPID" ]]; then
            final_filtered="$final_filtered $p"
        fi
    done
    final_filtered=$(echo "$final_filtered" | xargs)
    if [[ -n "$final_filtered" ]]; then
        echo "  Final cleanup: force killing PIDs $final_filtered"
        kill -KILL $final_filtered 2>/dev/null || true
    fi
fi

if [[ $killed_count -gt 0 ]]; then
    echo "  Terminated $killed_count agent process(es)"
else
    echo "  No agent processes found"
fi
echo ""

# --------------------------------------------
# 2. Stop and remove systemd services
# --------------------------------------------
echo "[2/7] Cleaning up systemd services..."

services=(
    "haproxy-agent.service"
    "haproxy.agent.service"
)

for svc in "${services[@]}"; do
    if systemctl is-active "$svc" &>/dev/null; then
        echo "  Stopping: $svc"
        systemctl stop "$svc" 2>/dev/null || true
    fi
    if systemctl is-enabled "$svc" &>/dev/null; then
        echo "  Disabling: $svc"
        systemctl disable "$svc" 2>/dev/null || true
    fi
    # Unmask in case it was masked previously, then mask to prevent reactivation
    systemctl unmask "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
done

# Remove service unit files
service_files=(
    "/etc/systemd/system/haproxy-agent.service"
    "/etc/systemd/system/haproxy.agent.service"
    "/lib/systemd/system/haproxy-agent.service"
    "/usr/lib/systemd/system/haproxy-agent.service"
    "/etc/systemd/user/haproxy-agent.service"
)

for sf in "${service_files[@]}"; do
    safe_remove "$sf" "systemd unit: $sf"
done

# Reload systemd
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed 2>/dev/null || true
echo "  systemd daemon reloaded"
echo ""

# --------------------------------------------
# 3. Remove agent binaries
# --------------------------------------------
echo "[3/7] Removing agent binaries..."

bin_paths=(
    "/usr/local/bin/haproxy-agent"
    "/usr/bin/haproxy-agent"
    "/bin/haproxy-agent"
    "/usr/sbin/haproxy-agent"
    "/sbin/haproxy-agent"
    "/opt/bin/haproxy-agent"
    "/usr/local/sbin/haproxy-agent"
)

for bp in "${bin_paths[@]}"; do
    safe_remove "$bp" "binary: $bp"
done

# Deep search for any remaining binaries
found_extra=$(find /usr /opt /bin /sbin -name "haproxy-agent" -type f 2>/dev/null || true)
if [[ -n "$found_extra" ]]; then
    while IFS= read -r extra; do
        safe_remove "$extra" "binary (deep search): $extra"
    done <<< "$found_extra"
fi
echo ""

# --------------------------------------------
# 4. Remove ALL agent configuration and data
# --------------------------------------------
echo "[4/7] Removing agent configuration and data..."

config_dirs=(
    "/etc/haproxy-agent"
    "/usr/local/etc/haproxy-agent"
    "/var/lib/haproxy-agent"
    "/opt/haproxy-agent"
    "/usr/local/share/haproxy-agent"
    "/usr/local/share/haproxy-agent-backups"
)

for cd in "${config_dirs[@]}"; do
    safe_remove "$cd" "config dir: $cd"
done

log_dirs=(
    "/var/log/haproxy-agent"
    "/usr/local/var/log/haproxy-agent"
    "/tmp/haproxy-agent-logs"
    "/var/log/syslog.d/haproxy-agent"
)

for ld in "${log_dirs[@]}"; do
    safe_remove "$ld" "log dir: $ld"
done

pid_files=(
    "/var/run/haproxy-agent.pid"
    "/tmp/haproxy-agent.pid"
    "/usr/local/var/run/haproxy-agent.pid"
    "/run/haproxy-agent.pid"
)

for pf in "${pid_files[@]}"; do
    safe_remove "$pf" "PID file: $pf"
done
echo ""

# --------------------------------------------
# 5. Remove temporary files, markers, sockets
# --------------------------------------------
echo "[5/7] Cleaning up temporary files and markers..."

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
for search_dir in "/tmp" "/var/run" "/run"; do
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
# 6. Clean up cron jobs
# --------------------------------------------
echo "[6/7] Cleaning up cron jobs..."

cron_files=(
    "/etc/cron.d/haproxy-agent"
    "/etc/crontab"
    "/var/spool/cron/root"
    "/var/spool/cron/crontabs/root"
)

for cf in "${cron_files[@]}"; do
    if [[ -f "$cf" ]] && grep -q "haproxy-agent" "$cf" 2>/dev/null; then
        cp "$cf" "${cf}.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
        sed -i '/haproxy-agent/d' "$cf" 2>/dev/null || true
        echo "  [CLEANED] Removed haproxy-agent entries from $cf"
    fi
done
echo ""

# --------------------------------------------
# 7. Verification
# --------------------------------------------
echo "[7/7] Verifying cleanup..."

remaining_procs=$(pgrep -f "haproxy-agent" 2>/dev/null | wc -l || echo "0")
remaining_svcs=$(systemctl list-units --all 2>/dev/null | grep -c "haproxy-agent" || echo "0")
remaining_bins=$(find /usr /opt /bin /sbin -name "haproxy-agent" -type f 2>/dev/null | wc -l || echo "0")
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
        find /usr /opt /bin /sbin -name "haproxy-agent" -type f 2>/dev/null | while read -r b; do
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
echo "  - All systemd services (stopped, disabled, masked)"
echo "  - All agent binaries"
echo "  - All agent config files (including config.json)"
echo "  - All agent logs"
echo "  - All agent temp files, markers, and sockets"
echo "  - Agent-related cron entries"
echo ""
echo "What was NOT touched:"
echo "  - HAProxy service"
echo "  - HAProxy configuration (/etc/haproxy/haproxy.cfg)"
echo "  - HAProxy SSL certificates"
echo "  - HAProxy logs"
echo ""
echo "System is ready for fresh agent installation."
echo ""
echo "Verify with:"
echo "  ps aux | grep haproxy-agent"
echo "  systemctl status haproxy-agent"
echo "  ls -la /etc/haproxy-agent/"
