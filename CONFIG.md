# Configuration Guide - HAProxy OpenManager

## 📋 Yapılandırma Dosyaları

### Dosya Yapısı

```
haproxy-openmanager/
├── .env.template           # ✅ Template (GIT'e commit edilir)
├── .env                    # ❌ Gerçek config (GIT'e commit EDİLMEZ)
├── .gitignore              # .env dosyalarını korur
└── CONFIG.md               # Bu dosya
```

## 🎯 Quick Start

### 1. Template'den Config Oluşturma

```bash
# Template'i kopyala
cp .env.template .env

# Gerçek değerleri düzenle
nano .env
```

### 2. Örnek Yapılandırmalar

#### Development (Local)
```bash
# .env dosyası
PUBLIC_URL=http://localhost:8000
MANAGEMENT_BASE_URL=http://localhost:8000
DEBUG=True
LOG_LEVEL=DEBUG
```

#### Staging
```bash
# .env dosyası veya K8s ConfigMap
PUBLIC_URL=https://haproxy-staging.company.com
MANAGEMENT_BASE_URL=https://haproxy-staging.company.com
DEBUG=False
LOG_LEVEL=INFO
```

#### Production (OpenShift)
```bash
# K8s ConfigMap: k8s/manifests/07-configmaps.yaml
data:
  PUBLIC_URL: 'https://haproxy-manager.example.com'
  MANAGEMENT_BASE_URL: 'https://haproxy-manager.example.com'
  DEBUG: 'False'
  LOG_LEVEL: 'INFO'
```

## 🔐 Güvenlik

### Hassas Bilgiler

`.env` dosyası hassas bilgiler içerir:
- ❌ Database şifreleri
- ❌ Secret key'ler  
- ❌ API token'ları

**Bu yüzden**:
- ✅ `.env` → `.gitignore`'da (commit edilmez)
- ✅ `.env.template` → Git'e commit edilir (örnek değerler)
- ✅ Production'da: Kubernetes Secrets kullan

### .gitignore Kontrolü

```bash
# .env dosyalarının ignore edildiğini kontrol et
grep "^\.env" .gitignore

# Çıktı olmalı:
# .env
# .env.local
# .env.development.local
# .env.test.local
# .env.production.local
```

## 📚 Environment Variable Detayları

### PUBLIC_URL

**Ne İşe Yarar**: Agent kurulum script'lerinde kullanılır

**Örnekler**:
```bash
# Development
PUBLIC_URL=http://localhost:8000

# Production
PUBLIC_URL=https://haproxy-manager.company.com

# OpenShift
PUBLIC_URL=https://haproxy-manager.example.com
```

**Nasıl Kullanılır**:
1. Agent Management sayfasından "Generate Install Script"
2. Script içinde `{{MANAGEMENT_URL}}` bu değerle değiştirilir
3. Agent bu URL'ye bağlanarak backend'i dinler

### REACT_APP_API_URL

**Ne İşe Yarar**: Frontend'in backend'e bağlanacağı URL

**Özel Durum**: 
```bash
# Boş bırakılırsa → Auto-detect (production için önerilen)
REACT_APP_API_URL=

# Development için explicit
REACT_APP_API_URL=http://localhost:8000
```

**Auto-detect Mantığı**:
```javascript
// frontend/src/utils/api.js
if (process.env.REACT_APP_API_URL) {
  return process.env.REACT_APP_API_URL;
}

// Production'da same-origin kullan
if (window.location) {
  return `${window.location.protocol}//${window.location.hostname}`;
}
```

## 🚀 Deployment Senaryoları

### Docker Compose

```bash
# 1. .env dosyası oluştur
cp .env.template .env

# 2. Değerleri düzenle
nano .env

# 3. Başlat
docker-compose up -d

# 4. Kontrol et
docker-compose logs backend | grep "PUBLIC_URL"
```

### Kubernetes/OpenShift

```bash
# 1. ConfigMap'i düzenle
vim k8s/manifests/07-configmaps.yaml

# 2. Apply
kubectl apply -f k8s/manifests/

# 3. Kontrol et
kubectl get configmap backend-config -n haproxy-manager -o yaml
```

### Manuel (Development)

```bash
# 1. Backend
cd backend
cp ../.env.template .env
export $(cat .env | xargs)
uvicorn main:app --reload

# 2. Frontend (başka terminal)
cd frontend
export REACT_APP_API_URL=http://localhost:8000
npm start
```

## 🔧 Troubleshooting

### Agent Script'inde Yanlış URL

**Sorun**: Agent script hala eski URL içeriyor

**Çözüm**:
```bash
# 1. Backend'deki değeri kontrol et
docker exec haproxy-openmanager-backend env | grep PUBLIC_URL

# 2. Container'ı yeniden başlat
docker-compose restart backend

# 3. Yeni script oluştur
# UI'dan tekrar "Generate Install Script"
```

### Frontend Backend'e Bağlanamıyor

**Sorun**: CORS hatası veya connection refused

**Çözüm**:
```bash
# 1. Frontend config'i kontrol et
docker exec haproxy-openmanager-frontend env | grep REACT_APP_API_URL

# 2. Browser console'da kontrol et
# [API Config] Base URL: http://localhost:8000

# 3. Network sekmesinde request URL'i kontrol et
```

## 📖 En İyi Pratikler

### ✅ YAPILMASI GEREKENLER

1. **Her ortam için ayrı değerler**
   ```
   Dev:     PUBLIC_URL=http://localhost:8000
   Staging: PUBLIC_URL=https://staging.company.com
   Prod:    PUBLIC_URL=https://prod.company.com
   ```

2. **Template'i güncelle**
   - Yeni variable eklendiğinde `.env.template`'e ekle
   - Dokümantasyon ile birlikte

3. **Secrets kullan (Production)**
   ```yaml
   # K8s Secret
   apiVersion: v1
   kind: Secret
   metadata:
     name: backend-secret
   data:
     SECRET_KEY: <base64-encoded>
   ```

### ❌ YAPILMAMASI GEREKENLER

1. **`.env` dosyasını commit etmeyin**
   ```bash
   # Yanlış!
   git add .env
   
   # Doğru!
   git add .env.template
   ```

2. **Production secret'larını template'e koymayın**
   ```bash
   # .env.template içinde YANLIŞLAR:
   SECRET_KEY=actual-production-secret-12345  ❌
   DATABASE_URL=postgresql://admin:realpass@prod-db  ❌
   
   # Doğru:
   SECRET_KEY=your-secret-key-change-this-in-production  ✅
   DATABASE_URL=postgresql://user:pass@host:5432/db  ✅
   ```

3. **Hardcoded URL kullanmayın**
   ```python
   # Yanlış!
   MANAGEMENT_URL = "https://my-server.com"  ❌
   
   # Doğru!
   MANAGEMENT_URL = os.getenv("PUBLIC_URL")  ✅
   ```

## 🆘 Yardım

Sorularınız için:
- 📘 Bu dosya: `CONFIG.md`
- 📗 Ana dokümantasyon: `README.md`
- 📙 Template: `.env.template`

