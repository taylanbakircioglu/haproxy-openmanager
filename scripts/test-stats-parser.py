#!/usr/bin/env python3
"""
HAProxy Stats CSV Parser Test Script
Bu script HAProxy stats CSV'sini parse edip sonuçları gösterir.
"""

import sys
import base64
import csv
import io
from datetime import datetime

def parse_csv_stats(csv_data):
    """Parse HAProxy stats CSV"""
    if not csv_data or not csv_data.strip():
        print("❌ CSV data is empty!")
        return None
    
    # Parse CSV
    reader = csv.DictReader(io.StringIO(csv_data))
    
    frontends = {}
    backends = {}
    servers = []
    
    for row in reader:
        try:
            # Skip comment lines
            if not row or row.get('# pxname', '').startswith('#'):
                continue
            
            pxname = row.get('# pxname') or row.get('pxname', '')
            svname = row.get('svname', '')
            stat_type = int(row.get('type', -1)) if row.get('type', '').isdigit() else -1
            
            # Frontend (type=0)
            if stat_type == 0:
                frontends[pxname] = {
                    'name': pxname,
                    'status': row.get('status', 'UNKNOWN'),
                    'requests_total': int(row.get('stot', 0) or 0),
                    'current_sessions': int(row.get('scur', 0) or 0),
                    'hrsp_2xx': int(row.get('hrsp_2xx', 0) or 0),
                    'hrsp_4xx': int(row.get('hrsp_4xx', 0) or 0),
                    'hrsp_5xx': int(row.get('hrsp_5xx', 0) or 0),
                }
            
            # Backend (type=1)
            elif stat_type == 1:
                backends[pxname] = {
                    'name': pxname,
                    'status': row.get('status', 'UNKNOWN'),
                    'requests_total': int(row.get('stot', 0) or 0),
                    'current_sessions': int(row.get('scur', 0) or 0),
                    'response_time_avg': int(row.get('rtime', 0) or 0),
                }
            
            # Server (type=2)
            elif stat_type == 2:
                if svname and svname not in ['BACKEND', 'FRONTEND']:
                    servers.append({
                        'backend': pxname,
                        'name': svname,
                        'status': row.get('status', 'UNKNOWN'),
                    })
        
        except Exception as e:
            print(f"⚠️  Failed to parse row: {e}")
            continue
    
    return {
        'frontends': frontends,
        'backends': backends,
        'servers': servers,
        'timestamp': datetime.utcnow().isoformat()
    }

def main():
    """Main test function"""
    print("=" * 80)
    print("HAProxy Stats CSV Parser Test")
    print("=" * 80)
    print()
    
    # Read CSV from stdin or file
    if len(sys.argv) > 1:
        # From file
        csv_file = sys.argv[1]
        print(f"📂 Reading from file: {csv_file}")
        
        with open(csv_file, 'r') as f:
            csv_data = f.read()
        
        # Check if base64 encoded
        if len(sys.argv) > 2 and sys.argv[2] == '--base64':
            print("🔓 Decoding base64...")
            csv_data = base64.b64decode(csv_data).decode('utf-8')
    else:
        # From stdin
        print("📥 Reading from stdin (paste CSV and press Ctrl+D)...")
        csv_data = sys.stdin.read()
    
    print(f"📊 CSV Data Size: {len(csv_data)} bytes")
    print()
    
    # Show preview
    lines = csv_data.split('\n')
    print("📋 CSV Preview (first 5 lines):")
    print("-" * 80)
    for line in lines[:5]:
        print(line[:100] + ('...' if len(line) > 100 else ''))
    print("-" * 80)
    print()
    
    # Parse
    print("🔍 Parsing CSV...")
    result = parse_csv_stats(csv_data)
    
    if not result:
        print("❌ Parse failed!")
        return 1
    
    # Display results
    print("✅ Parse successful!")
    print()
    print("=" * 80)
    print("PARSE RESULTS")
    print("=" * 80)
    print()
    
    # Frontends
    print(f"🌐 FRONTENDS: {len(result['frontends'])}")
    if result['frontends']:
        print("-" * 80)
        for name, stats in result['frontends'].items():
            print(f"  • {name}")
            print(f"    - Status: {stats['status']}")
            print(f"    - Requests: {stats['requests_total']:,}")
            print(f"    - Sessions: {stats['current_sessions']}")
            print(f"    - 2xx: {stats['hrsp_2xx']:,}, 4xx: {stats['hrsp_4xx']:,}, 5xx: {stats['hrsp_5xx']:,}")
    else:
        print("  ⚠️  No frontends found!")
    print()
    
    # Backends
    print(f"☁️  BACKENDS: {len(result['backends'])}")
    if result['backends']:
        print("-" * 80)
        for name, stats in result['backends'].items():
            print(f"  • {name}")
            print(f"    - Status: {stats['status']}")
            print(f"    - Requests: {stats['requests_total']:,}")
            print(f"    - Sessions: {stats['current_sessions']}")
            print(f"    - Response Time: {stats['response_time_avg']}ms")
    else:
        print("  ⚠️  No backends found!")
    print()
    
    # Servers
    print(f"🖥️  SERVERS: {len(result['servers'])}")
    if result['servers']:
        print("-" * 80)
        # Group by backend
        by_backend = {}
        for server in result['servers']:
            backend = server['backend']
            if backend not in by_backend:
                by_backend[backend] = []
            by_backend[backend].append(server)
        
        for backend, servers in by_backend.items():
            print(f"  Backend: {backend}")
            for server in servers:
                status_icon = "🟢" if server['status'] == 'UP' else "🔴"
                print(f"    {status_icon} {server['name']} - {server['status']}")
    else:
        print("  ⚠️  No servers found!")
    print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"✅ Successfully parsed:")
    print(f"   - {len(result['frontends'])} frontends")
    print(f"   - {len(result['backends'])} backends")
    print(f"   - {len(result['servers'])} servers")
    print()
    
    if len(result['frontends']) == 0 and len(result['backends']) == 0:
        print("⚠️  WARNING: No frontends or backends found!")
        print("   This CSV might be:")
        print("   - Empty")
        print("   - Corrupted")
        print("   - Not from HAProxy stats socket")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

