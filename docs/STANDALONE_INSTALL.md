# Standalone Installation Guide

This guide covers installing HAProxy OpenManager directly on a server, VM, or LXC container **without Docker or Kubernetes**.

## Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11+ | Backend runtime |
| Node.js | 18+ | Frontend build |
| PostgreSQL | 15+ | Database |
| Redis | 7+ | Cache & real-time metrics |
| Nginx | Any recent | Reverse proxy (optional but recommended) |

## 1. Install System Dependencies

### RHEL / CentOS / Rocky Linux

```bash
sudo dnf install -y python3.11 python3.11-pip python3.11-venv \
    nodejs npm postgresql-server redis nginx git
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql redis nginx
```

### Ubuntu / Debian

```bash
sudo apt update && sudo apt install -y python3.11 python3.11-venv python3-pip \
    nodejs npm postgresql redis-server nginx git
sudo systemctl enable --now postgresql redis-server nginx
```

## 2. Configure PostgreSQL

```bash
sudo -u postgres psql <<SQL
CREATE USER haproxy_user WITH PASSWORD 'your-secure-password';
CREATE DATABASE haproxy_openmanager OWNER haproxy_user;
GRANT ALL PRIVILEGES ON DATABASE haproxy_openmanager TO haproxy_user;
SQL
```

Verify the connection:

```bash
psql -U haproxy_user -d haproxy_openmanager -h 127.0.0.1 -c "SELECT 1;"
```

> **Note**: You may need to edit `pg_hba.conf` to allow `md5` authentication for local connections.

## 3. Configure Redis

Redis works out of the box for local use. For production, edit `/etc/redis/redis.conf` or `/etc/redis.conf`:

```conf
maxmemory 2gb
maxmemory-policy volatile-lru
save ""
appendonly no
```

Restart Redis after changes:

```bash
sudo systemctl restart redis
```

## 4. Clone the Repository

```bash
cd /opt
sudo git clone https://github.com/taylanbakircioglu/haproxy-openmanager.git
sudo chown -R $USER:$USER /opt/haproxy-openmanager
cd /opt/haproxy-openmanager
```

## 5. Set Up the Backend

### Create a Python virtual environment

```bash
cd /opt/haproxy-openmanager/backend
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configure environment variables

```bash
cp /opt/haproxy-openmanager/.env.template /opt/haproxy-openmanager/backend/.env
```

Edit `backend/.env` with your actual values:

```env
DATABASE_URL=postgresql://haproxy_user:your-secure-password@127.0.0.1:5432/haproxy_openmanager
REDIS_URL=redis://127.0.0.1:6379
SECRET_KEY=generate-a-random-64-char-string-here
PUBLIC_URL=http://your-server-ip:8080
MANAGEMENT_BASE_URL=http://your-server-ip:8080
LOG_LEVEL=INFO
DEBUG=False
```

> **Tip**: Generate a secret key with `python3 -c "import secrets; print(secrets.token_hex(32))"`

### Test the backend

```bash
cd /opt/haproxy-openmanager/backend
source venv/bin/activate
uvicorn main:app --host 127.0.0.1 --port 8000
```

Database migrations run automatically on first startup. Verify by visiting `http://127.0.0.1:8000/api/health`.

### Create a systemd service for the backend

```bash
sudo tee /etc/systemd/system/haproxy-openmanager-backend.service > /dev/null <<EOF
[Unit]
Description=HAProxy OpenManager Backend
After=network.target postgresql.service redis.service
Requires=postgresql.service redis.service

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/haproxy-openmanager/backend
EnvironmentFile=/opt/haproxy-openmanager/backend/.env
ExecStart=/opt/haproxy-openmanager/backend/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now haproxy-openmanager-backend
```

## 6. Build and Serve the Frontend

### Build the production bundle

```bash
cd /opt/haproxy-openmanager/frontend
npm install
NODE_OPTIONS=--openssl-legacy-provider npm run build
```

### Serve with a simple static server

Option A — using `serve`:

```bash
npm install -g serve
serve -s build -l 3000
```

Option B — copy to nginx (recommended, see next section).

### Create a systemd service for the frontend (if using `serve`)

```bash
sudo tee /etc/systemd/system/haproxy-openmanager-frontend.service > /dev/null <<EOF
[Unit]
Description=HAProxy OpenManager Frontend
After=network.target haproxy-openmanager-backend.service

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/haproxy-openmanager/frontend
ExecStart=/usr/bin/npx serve -s build -l 3000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now haproxy-openmanager-frontend
```

## 7. Configure Nginx as Reverse Proxy

This exposes both frontend and backend on a single port (8080).

```bash
sudo tee /etc/nginx/conf.d/haproxy-openmanager.conf > /dev/null <<'EOF'
upstream frontend {
    server 127.0.0.1:3000;
}

upstream backend {
    server 127.0.0.1:8000;
}

server {
    listen 8080;
    server_name _;

    location /health {
        access_log off;
        return 200 'ok';
    }

    location /api/ {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

sudo nginx -t && sudo systemctl reload nginx
```

Alternatively, serve the frontend build directly from nginx instead of using `serve`:

```bash
sudo cp -r /opt/haproxy-openmanager/frontend/build /var/www/haproxy-openmanager
```

Then replace the frontend `location /` block with:

```nginx
location / {
    root /var/www/haproxy-openmanager;
    try_files $uri /index.html;
}
```

## 8. Verify the Installation

```bash
# Backend health
curl -s http://127.0.0.1:8000/api/health | python3 -m json.tool

# Frontend (through nginx)
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/

# Login
curl -s -X POST http://127.0.0.1:8080/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "admin"}' | python3 -m json.tool
```

> **Default credentials**: `admin` / `admin` — change the password immediately after first login.

## 9. Firewall

Open port 8080 (or whichever port you configured nginx on):

```bash
# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-port=8080/tcp && sudo firewall-cmd --reload

# ufw (Ubuntu/Debian)
sudo ufw allow 8080/tcp
```

## Quick Reference

| Service | Port | URL |
|---------|------|-----|
| Backend API | 8000 | `http://127.0.0.1:8000/api/health` |
| Frontend | 3000 | `http://127.0.0.1:3000` |
| Nginx (unified) | 8080 | `http://your-server-ip:8080` |
| PostgreSQL | 5432 | local |
| Redis | 6379 | local |

## Updating

```bash
cd /opt/haproxy-openmanager
git pull

# Backend
cd backend && source venv/bin/activate && pip install -r requirements.txt
sudo systemctl restart haproxy-openmanager-backend

# Frontend
cd ../frontend && npm install && NODE_OPTIONS=--openssl-legacy-provider npm run build
sudo systemctl restart haproxy-openmanager-frontend
```
