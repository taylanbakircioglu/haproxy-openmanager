#!/bin/bash
# Check agent logs for HAProxy stats data

echo "=== Checking Agent Logs for HAProxy Stats ==="
echo ""

# Check if agent log file exists
if [ ! -f /var/log/haproxy-agent/agent.log ]; then
    echo "❌ Agent log file not found at /var/log/haproxy-agent/agent.log"
    echo "Agent might not be installed or running"
    exit 1
fi

echo "✅ Agent log file found"
echo ""

# Check recent heartbeat entries
echo "=== Recent Heartbeat Entries ==="
tail -50 /var/log/haproxy-agent/agent.log | grep -i "heartbeat" | tail -5
echo ""

# Check if stats are being collected
echo "=== HAProxy Stats Collection ==="
tail -100 /var/log/haproxy-agent/agent.log | grep -i "stats" | tail -10
echo ""

# Check for CSV data
echo "=== Checking for CSV Stats Data ==="
tail -100 /var/log/haproxy-agent/agent.log | grep -i "haproxy_stats_csv" | tail -5
echo ""

# Check for errors
echo "=== Recent Errors ==="
tail -100 /var/log/haproxy-agent/agent.log | grep -i "error\|fail" | tail -5
echo ""

# Check stats socket
echo "=== HAProxy Stats Socket Status ==="
if [ -S /var/run/haproxy/admin.sock ]; then
    echo "✅ Stats socket exists: /var/run/haproxy/admin.sock"
    echo "Testing socket access..."
    echo "show info" | socat stdio /var/run/haproxy/admin.sock 2>&1 | head -5
else
    echo "❌ Stats socket not found at /var/run/haproxy/admin.sock"
    echo "Check HAProxy configuration for stats socket"
fi

