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
PUBLIC_URL=https://haproxy-staging.example.com
MANAGEMENT_BASE_URL=https://haproxy-staging.example.com
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
PUBLIC_URL=https://haproxy-manager.example.com

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

### REQUEST_LOG_ENABLED (v1.11.0)

**Ne İşe Yarar**: Request/Response Log özelliğinin sert (hard) kill-switch'i. `false` yapıldığında
loglama middleware'i ASGI zincirine **hiç eklenmez**, yazıcı ve retention görevleri başlatılmaz —
yani sıfır ek yük, ayar okuması bile yapılmaz. Değişiklik için restart gerekir.

**Örnekler**:
```bash
# Varsayılan: açık
REQUEST_LOG_ENABLED=true

# Tamamen kapat (ör. çok yüksek trafikli kurulum, veya regülasyon gereği)
REQUEST_LOG_ENABLED=false
```

**Nasıl Kullanılır**:
1. Restart gerektirmeden kapatmak isterseniz bunun yerine **Settings → Request Log → Enable request
   log** anahtarını kullanın; o anında etkili olur.
2. Retention süreleri, gövde (body) yakalama, örnekleme oranı ve hariç tutulan path'ler bu env
   değişkeniyle değil, veritabanındaki `requestlog.*` ayarlarıyla yönetilir — arayüzden düzenlenir.
3. Disk büyümesi asıl operasyonel konudur: sırasıyla `sample_rate`'i düşürün, `capture_get`'i
   kapatın, `capture_bodies`'i kapatın, sonra `success_retention_days`'i kısaltın.

### REQUEST_LOG_QUEUE_MAX / REQUEST_LOG_QUEUE_MAX_BYTES / REQUEST_LOG_BATCH_SIZE / REQUEST_LOG_FLUSH_MS (v1.11.0)

**Ne İşe Yarar**: Log satırlarını yazan arka plan görevinin ayarları. Satırlar sınırlı bir kuyruğa
konur ve toplu (batch) INSERT ile yazılır; böylece istek yolu asla veritabanını beklemez.

**Örnekler**:
```bash
# Worker başına kuyruk derinliği. Dolduğunda satırlar DÜŞÜRÜLÜR (sayılır ve
# Request Log sayfasında gösterilir), istek bloklanmaz.
REQUEST_LOG_QUEUE_MAX=2000

# Aynı kuyruğun BAYT tavanı (worker başına). Satır sayısı tek başına belleği
# sınırlamaz: `max_body_bytes` Settings'ten 256 KB'a kadar ayarlanabilir ve bir
# satır bunu iki kez taşıyabilir, o tavanda 2000 satırlık kuyruk ~1 GiB tutar.
# Hangi sınır önce dolarsa kuyruk orada durur.
REQUEST_LOG_QUEUE_MAX_BYTES=67108864

# Tek INSERT'te kaç satır yazılacağı (havuzdan istek başına değil, batch başına
# bir bağlantı alınır)
REQUEST_LOG_BATCH_SIZE=100

# Yarım dolu bir batch'in en fazla ne kadar bekletileceği (ms)
REQUEST_LOG_FLUSH_MS=500
```

**Nasıl Kullanılır**:
1. Request Log sayfasında "rows dropped" uyarısı görüyorsanız önce `requestlog.max_body_bytes`
   veya `sample_rate`'i düşürün. `REQUEST_LOG_QUEUE_MAX`'ı artırmak bu worker'ın tutabileceği
   belleği de artırır; artıracaksanız `REQUEST_LOG_QUEUE_MAX_BYTES`'ı da birlikte artırın.
2. Bu değerler worker başınadır — `UVICORN_WORKERS` arttıkça toplam bellek de o oranda artar.
   `GET /api/request-logs/stats` içindeki sayaçlar da worker başınadır ve yanıtta öyle
   etiketlenir; 4 worker'da gördüğünüz düşüş sayısı gerçeğin dörtte biridir.
3. Büyük filolarda tek en etkili ayar `requestlog.capture_agent_success`'tir (varsayılan kapalı).
   Açık olsaydı 200 düğümlük bir filo günde ~2M satır yazar ve 500.000 satır tavanına 6 saatte
   ulaşırdı; yapılandırılmış 7 gün / 30 gün saklama o noktada birkaç saate iner. Başarısız ajan
   çağrıları bu ayardan bağımsız olarak her zaman loglanır.

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
   Staging: PUBLIC_URL=https://staging.example.com
   Prod:    PUBLIC_URL=https://prod.example.com
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

