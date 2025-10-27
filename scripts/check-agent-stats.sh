#!/bin/bash

# HAProxy Agent Stats Diagnostic Script
# Bu script agent'ların stats gönderip göndermediğini kontrol eder

AGENT_LOG="/var/log/haproxy-agent/agent.log"
CONFIG_FILE="/etc/haproxy-agent/config.json"

echo "========================================="
echo "HAProxy Agent Stats Diagnostic"
echo "========================================="
echo ""

# 1. Agent çalışıyor mu?
if pgrep -f "haproxy-agent" > /dev/null; then
    echo "✅ Agent çalışıyor"
else
    echo "❌ Agent çalışmıyor!"
    exit 1
fi

# 2. Config dosyası var mı?
if [[ -f "$CONFIG_FILE" ]]; then
    echo "✅ Config dosyası mevcut: $CONFIG_FILE"
    STATS_SOCKET=$(jq -r '.haproxy.stats_socket_path // "/var/run/haproxy/admin.sock"' "$CONFIG_FILE")
    echo "   Stats Socket: $STATS_SOCKET"
else
    echo "❌ Config dosyası bulunamadı: $CONFIG_FILE"
    exit 1
fi

# 3. Stats socket var mı?
if [[ -S "$STATS_SOCKET" ]]; then
    echo "✅ Stats socket mevcut: $STATS_SOCKET"
else
    echo "❌ Stats socket bulunamadı: $STATS_SOCKET"
    echo ""
    echo "   HAProxy config'inize şu satırı ekleyin:"
    echo "   global"
    echo "       stats socket $STATS_SOCKET mode 660 level admin"
    exit 1
fi

# 4. Stats socket'e erişim var mı?
if echo "show stat" | socat stdio "$STATS_SOCKET" &>/dev/null; then
    echo "✅ Stats socket erişilebilir"
    STATS_COUNT=$(echo "show stat" | socat stdio "$STATS_SOCKET" 2>/dev/null | wc -l)
    echo "   Stats satır sayısı: $STATS_COUNT"
else
    echo "❌ Stats socket'e erişilemiyor"
    echo "   Permission sorunu olabilir. Şunu deneyin:"
    echo "   sudo chmod 666 $STATS_SOCKET"
    exit 1
fi

# 5. Socat kurulu mu?
if command -v socat &>/dev/null; then
    echo "✅ Socat kurulu: $(command -v socat)"
else
    echo "❌ Socat kurulu değil!"
    echo "   Yüklemek için: sudo apt-get install socat (Debian/Ubuntu)"
    echo "                  sudo yum install socat (RHEL/CentOS)"
    exit 1
fi

# 6. Agent log'larını kontrol et
if [[ -f "$AGENT_LOG" ]]; then
    echo ""
    echo "📊 Agent Log Analizi:"
    echo "-------------------"
    
    # Son heartbeat
    LAST_HEARTBEAT=$(grep "Heartbeat sent successfully" "$AGENT_LOG" | tail -1)
    if [[ -n "$LAST_HEARTBEAT" ]]; then
        echo "✅ Son başarılı heartbeat:"
        echo "   $LAST_HEARTBEAT"
    else
        echo "⚠️  Son 100 satırda başarılı heartbeat bulunamadı"
    fi
    
    # Stats socket hataları
    STATS_ERRORS=$(grep -i "stats socket" "$AGENT_LOG" | tail -3)
    if [[ -n "$STATS_ERRORS" ]]; then
        echo ""
        echo "⚠️  Stats socket ile ilgili log'lar:"
        echo "$STATS_ERRORS"
    fi
    
    # Heartbeat hataları
    HEARTBEAT_ERRORS=$(grep "Heartbeat failed" "$AGENT_LOG" | tail -3)
    if [[ -n "$HEARTBEAT_ERRORS" ]]; then
        echo ""
        echo "❌ Heartbeat hataları:"
        echo "$HEARTBEAT_ERRORS"
    fi
else
    echo "⚠️  Agent log dosyası bulunamadı: $AGENT_LOG"
fi

echo ""
echo "========================================="
echo "Diagnostic Tamamlandı"
echo "========================================="
echo ""

# 7. Test: Stats CSV'yi göster
echo "📋 HAProxy Stats Örnek (ilk 10 satır):"
echo "-------------------"
echo "show stat" | socat stdio "$STATS_SOCKET" 2>/dev/null | head -10

echo ""
echo "✅ Agent stats göndermeye hazır!"
echo ""
echo "Dashboard'da veri görmek için:"
echo "1. Pipeline'ın bitmesini bekleyin"
echo "2. Agent'ların en az 1-2 heartbeat göndermesini bekleyin (1 dakika)"
echo "3. Dashboard'u yenileyin"
echo "4. 24 saatlik trend verileri için 24 saat bekleyin"

