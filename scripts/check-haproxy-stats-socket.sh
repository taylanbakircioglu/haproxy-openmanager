#!/bin/bash

# HAProxy Stats Socket Checker
# Bu script HAProxy config'inde stats socket tanımlı mı kontrol eder

HAPROXY_CONFIG="${1:-/etc/haproxy/haproxy.cfg}"

echo "========================================="
echo "HAProxy Stats Socket Checker"
echo "========================================="
echo ""
echo "Config dosyası: $HAPROXY_CONFIG"
echo ""

if [[ ! -f "$HAPROXY_CONFIG" ]]; then
    echo "❌ HAProxy config dosyası bulunamadı: $HAPROXY_CONFIG"
    exit 1
fi

# Stats socket tanımını kontrol et
STATS_SOCKET_LINE=$(grep -n "^\s*stats socket" "$HAPROXY_CONFIG")

if [[ -n "$STATS_SOCKET_LINE" ]]; then
    echo "✅ Stats socket tanımlı:"
    echo ""
    echo "$STATS_SOCKET_LINE"
    echo ""
    
    # Socket yolunu çıkar
    SOCKET_PATH=$(echo "$STATS_SOCKET_LINE" | sed 's/.*stats socket//' | awk '{print $1}')
    echo "Socket yolu: $SOCKET_PATH"
    
    # Socket var mı kontrol et
    if [[ -S "$SOCKET_PATH" ]]; then
        echo "✅ Socket dosyası mevcut: $SOCKET_PATH"
        
        # Erişim kontrolü
        if echo "show info" | socat stdio "$SOCKET_PATH" &>/dev/null; then
            echo "✅ Socket erişilebilir ve çalışıyor"
            echo ""
            echo "HAProxy Bilgileri:"
            echo "show info" | socat stdio "$SOCKET_PATH" 2>/dev/null | head -5
        else
            echo "⚠️  Socket mevcut ama erişilemiyor (permission sorunu olabilir)"
            echo "   Çözüm: sudo chmod 666 $SOCKET_PATH"
        fi
    else
        echo "⚠️  Socket dosyası henüz oluşturulmamış: $SOCKET_PATH"
        echo "   HAProxy'yi yeniden başlatın: systemctl restart haproxy"
    fi
else
    echo "❌ Stats socket tanımlı DEĞİL!"
    echo ""
    echo "HAProxy config'inizde global section'a şu satırları ekleyin:"
    echo ""
    echo "global"
    echo "    stats socket /var/run/haproxy/admin.sock mode 660 level admin"
    echo "    stats timeout 30s"
    echo ""
    echo "Örnek tam config:"
    echo "---"
    cat <<'EOF'
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /var/run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

# Frontend ve backend tanımları buraya...
EOF
    echo "---"
    echo ""
    echo "Değişiklik sonrası HAProxy'yi reload edin:"
    echo "  sudo systemctl reload haproxy"
    echo ""
    exit 1
fi

echo ""
echo "========================================="
echo "✅ HAProxy Stats Socket Hazır!"
echo "========================================="

