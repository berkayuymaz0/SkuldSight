# PixelPaw SOC

`PixelPaw SOC` is a Chrome Extension (Manifest V3) for security operations workflows.  
It helps analysts investigate IoCs quickly via VirusTotal, supports optional AbuseIPDB enrichment for IPs, and provides local history and lightweight analytics.

## Highlights

- Single IoC scan (IP, domain, URL, file hash)
- Batch scan from multiline input or file import
- Context-menu scan on selected text
- Inline page badges for detected domains/public IPs
- Optional IP enrichment with AbuseIPDB
- Local history and dashboard-style analytics
- Bilingual UI support (`en`, `tr`)

## Tech Stack

- Chrome Extension, Manifest V3
- Service worker background architecture
- Vanilla JavaScript, HTML, CSS
- Local persistence with `chrome.storage.local`

## Project Structure

- `manifest.json` - Extension manifest, permissions, CSP, content scripts
- `background.js` - Main service worker (queue, VT/Abuse requests, storage orchestration)
- `background-guards.js` - Runtime sender/port/message validation guards
- `popup.html` / `popup.js` / `popup.css` - Primary scan interface and result rendering
- `options.html` / `options.js` / `options.css` - Settings, presets, analytics view
- `content.js` / `content.css` - Inline domain/IP badge detection and mini panel behavior
- `utils.js` - Shared utilities (IoC normalization, presets, analytics helpers, key expiry helpers)
- `i18n.js` - Translation resources and localization helpers
- `scripts/prepush-check.sh` - Local pre-push quality/security checks
- `SECURITY_HARDENING_CHECKLIST.md` - Security hardening checklist

## Supported IoC Types

- IPv4 / IPv6 (public-only logic in content side)
- Domain
- URL
- File hash (`md5`, `sha1`, `sha256`)

## Installation (Development)

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the project root folder.
5. Confirm extension loads and popup opens correctly.

## Configuration

Open settings from popup or directly via `options.html`.

### API Keys

- **VirusTotal API key** (required for scans)
- **AbuseIPDB API key** (optional, used for IP enrichment)

Keys are stored in `chrome.storage.local` and validated with TTL logic via shared utility helpers.

### Behavior Controls

- UI mode: popup or side panel
- Local rate interval for VT requests
- Notification toggles (queue/news/context)
- Domain badge blacklist rules

## Scan Modes

- **Single scan:** One IoC lookup with full result card
- **Batch scan:** Line-by-line processing with progress and summary
- **Context scan:** Right-click selected text and scan directly

## Security Notes

- Permissions and CSP are scoped with least-privilege intent.
- Runtime messaging is guarded by sender and schema checks.
- HTTPS-only network policy is enforced in current manifest strategy.
- See `SECURITY_HARDENING_CHECKLIST.md` for release-hardening steps.

## Pre-Push Checks

Run local checks before committing or publishing:

```bash
bash scripts/prepush-check.sh
```

This script currently validates:

1. `manifest.json` syntax
2. JavaScript syntax (`node --check`)
3. Obvious hardcoded-secret patterns

## Manual Smoke Test Checklist

- Popup loads and basic scan works
- Batch mode produces progress and completion output
- Content badges appear on supported HTTPS pages
- Options page saves/reloads settings correctly
- VT/Abuse test-connection actions respond as expected

## Troubleshooting

- **No scan results:** verify API key and network access
- **Rate-related delays:** check configured rate interval and queue load
- **No inline badges:** verify page is HTTPS and not blacklisted
- **Missing UI text:** confirm localization resources load correctly

## Privacy

- History/analytics are stored locally in browser profile storage.
- The extension sends data only to configured external providers needed for lookup operations.

## License

If you plan to distribute publicly, add a `LICENSE` file and reference it here.
# PixelPaw SOC

`PixelPaw SOC`, SOC ve güvenlik operasyon ekipleri için geliştirilmiş bir Chrome uzantısıdır (Manifest V3). Uzantı; IoC taraması, toplu tarama, geçmiş yönetimi, sayfa içi domain rozeti, haber akışı ve ayarlar/analitik panelini tek bir ürün içinde sunar.

Uzantı VirusTotal API v3 ile çalışır ve iki dil desteği içerir: Türkçe (`tr`) ve İngilizce (`en`).

## Kapsam

- IoC türleri: IPv4/IPv6, domain, URL, dosya hash (`md5`, `sha1`, `sha256`)
- Tarama tipleri: tekil tarama, çok satırlı toplu tarama, içerik menüsünden tarama
- Sonuç bileşenleri: tehdit istatistikleri, permalink, detaylar, opsiyonel ek analizler
- Operasyonel özellikler: kuyruk/rate limit yönetimi, geçmiş, batch özeti, yerel analitik
- Ek modüller: sayfa içi domain rozeti, siber haber RSS paneli

## Mimari

### `background.js` (Service Worker)

- VirusTotal API isteklerini yönetir
- İstekleri tek işçi kuyruğunda seri işler
- İstemci tarafı rate limit uygular (`vtRateIntervalSec`, `vtProMode`)
- Popup ve content script ile port tabanlı haberleşmeyi yürütür (`vt-single`, `vt-batch`)
- Context menu taramasını yönetir
- RSS haber kaynaklarını çeker, önbellekler ve opsiyonel bildirim üretir
- Geçmiş (`vtRecentHistory`, `vtBatchHistory`) ve analitik (`vtAnalytics`) güncellemelerini yapar

### `popup.*`

- Ana kullanıcı arayüzüdür
- Scan / News sekmelerini sunar
- Tekil ve toplu taramayı başlatır
- Sonuç kartı, geçmiş ve batch geçmişi gösterir

### `options.*`

- API anahtarı, dil, davranış ve bildirim ayarlarını yönetir
- Tarama presetlerini düzenler
- Domain badge blacklist yapılandırmasını sunar
- Yerel analitik verisini KPI ve grafiklerle gösterir

### `content.js`

- Sayfada görünen domain metinlerini tespit eder
- Domain yanında `VT` rozeti ekler
- Rozet üzerinden mini sonuç paneli açar
- Blacklist kurallarına göre ilgili sayfalarda kendini devre dışı bırakır

### `i18n.js` / `utils.js`

- Ortak çeviri mekanizması (`VT_I18N`)
- IoC normalize etme, analytics normalize etme ve yardımcı fonksiyonlar

## Kurulum (Geliştirme)

1. Chrome'da `chrome://extensions` sayfasını açın.
2. **Developer mode** seçeneğini etkinleştirin.
3. **Load unpacked** ile proje klasörünü seçin.
4. Uzantının yüklendiğini ve popup ekranının açıldığını doğrulayın.

> Not: `manifest.json` içindeki ikon dosyalarının `icons/` klasöründe bulunması gerekir.

## Pre-push kontrolü

Git'e yüklemeden önce yerel kalite ve güvenlik kontrollerini çalıştırın:

```bash
bash scripts/prepush-check.sh
```

Ek sertleştirme maddeleri için `SECURITY_HARDENING_CHECKLIST.md` dosyasını takip edin.

## Yapılandırma

### 1) API anahtarları

1. Uzantı popup'ından veya doğrudan `options.html` üzerinden Ayarlar ekranını açın.
2. **VirusTotal** API anahtarınızı girip kaydedin (zorunlu — tarama VT olmadan çalışmaz).
3. **AbuseIPDB** API anahtarını isteğe bağlı ekleyin (yalnızca **IP** taramalarında hibrit sonuç).
4. Her sağlayıcı için **Test connection** ile bağlantıyı doğrulayın.

Anahtarlar yalnızca yerel depoda tutulur (`chrome.storage.local`). VT ve Abuse anahtarları için **14 gün** tabanlı geçerlilik kontrolü vardır (`vtApiKeySavedAt`, `abuseipdbApiKeySavedAt`).

| Sağlayıcı | Depolama | Test çağrısı |
|-----------|----------|--------------|
| VirusTotal | `vtApiKey`, `vtApiKeySavedAt` | `GET /users/{key}` |
| AbuseIPDB | `abuseipdbApiKey`, `abuseipdbApiKeySavedAt` | `GET /api/v2/check` (1.1.1.1) |

### 2) Davranış ayarları

- **Arayüz modu** (`vtUiMode`): **Popup** (varsayılan) veya **Side panel** — Ayarlar’da seçildiğinde anında uygulanır. Chrome 114+ gerekir. Popup moduna geçince açık yan panel kapanır.
- **Pro mode**: yerel rate limit'i devre dışı bırakır
- **Minimum interval**: VT çağrıları arasındaki en düşük süre (sn) — AbuseIPDB çağrıları bu kuyruğa dahil değildir; IP taramasında VT ile paralel gider
- Bildirim tercihleri:
  - Kuyruk bekleme bildirimi
  - Yeni haber bildirimi
  - Context-menu tarama bildirimi

### 3) Tarama şablonları (preset)

Popup’ta **Hızlı / Detaylı / Analist** seçilir; arka planda `vtScanPreset` + `vtScanPresets` (sürüm **3**) kullanılır. Şablonlar **ek VT HTTP çağrılarını**, **UI’da gösterilen AV etiket derinliğini** ve (IP için) **AbuseIPDB derinliğini** belirler.

#### Her şablonda ücretsiz (ana `GET` yanıtı)

| Bileşen | Kaynak | Ek API |
|---------|--------|--------|
| Motor özeti (M/S/Undet + çubuk) | `last_analysis_stats` | Hayır |
| Threat context | Konsensüs, popüler ad/kategori; Analyst’te geniş AV etiket listesi | Hayır |
| Hero (tam IoC, tag chip’leri, reputation, imza) | Ana nesne `attributes` | Hayır |
| Details | IoC türüne göre metadata satırları | Hayır |

**Community tags** Details’ta değil; hero’da renkli chip olarak gösterilir.

#### Kısaltmalar (matris kodları)

| Kod | Açılım | Ne yapar? |
|-----|--------|-----------|
| **REL** | **Relationship** (ilişki, birincil) | VT’ye **+1** ek çağrı: IoC’ye bağlı birincil pivot (ör. IP/domain için `resolutions`, URL için `contacted_domains`, dosya için `contacted_ips`). Matriste `REL` = `relMode: primary`. |
| **REL+** | **Relationship, full** (tam pivot) | **REL** + ikincil pivot (**+1** çağrı daha, toplam **+2** ek ilişki): örn. `communicating_files`, dosyada `contacted_domains`. Matriste `REL+` = `relMode: full`. |
| **STD** | **Standard** (standart etiketler) | Threat context’te gösterilen benzersiz AV motor etiketleri üst sınırı **8**; yalnızca ana rapordaki `last_analysis_results` parse edilir, **ek API yok**. `labels: standard`. |
| **EXT** | **Extended** (genişletilmiş etiketler) | Aynı parse, üst sınır **20** benzersiz etiket; yine **ek API yok**. `labels: extended`. |
| **—** | Yok / kapalı | O sütun için özellik devre dışı (`relMode: none` veya MITRE kapalı). |
| **LBL** | **Labels** (etiket modu) | Sütun başlığı; hücrede **STD** veya **EXT** görünür. |
| **MITRE** | MITRE ATT&CK | Yalnızca **dosya** satırında anlamlı: sandbox `behaviours` veya dosya özniteliklerinden taktik ID’leri (+1 çağrı mümkün). `✓` = açık. |
| **ABU** | **AbuseIPDB** (yalnızca **IP** satırı) | Matriste `CHK` = yalnızca check; `R{window}/{overall}` = check + kategori raporları (+1 çağrı). |

#### Ayarlar sayfasındaki matris (IOC × REL × LBL × MITRE × ABU)

Her şablon kartının üstündeki tablo, **kaydedilmiş profilin** IoC türü başına özetidir. Sütunlar:

| Sütun | Kod | Anlamı |
|-------|-----|--------|
| **IOC** | IP / Domain / URL / File | Tarama sırasında algılanan tür; o satırdaki profil uygulanır. |
| **REL** | `—` | Ek ilişki yok → yukarıdaki **REL / REL+** tablosuna bakın. |
| **REL** | `REL` | Birincil ilişki (+1 çağrı). |
| **REL** | `REL+` | Birincil + ikincil pivot (+2 ek çağrı toplam). |
| **LBL** | `STD` | Standart AV etiket listesi (8). |
| **LBL** | `EXT` | Genişletilmiş AV etiket listesi (20). |
| **MITRE** | `—` / `✓` | Dosya MITRE kapalı / açık. |
| **ABU** | `—` / `CHK` / `R30/90` vb. | IP dışı türlerde `—`; IP için Abuse özeti (aşağıdaki tablo). |

**relMode → VT ilişki uçları**

| IoC türü | `primary` (+1) | `full` (+2 toplam) |
|----------|----------------|---------------------|
| IP | `resolutions` | + `communicating_files` |
| Domain | `resolutions` | + `communicating_files` |
| URL | `contacted_domains` | (ikincil yok) |
| File | `contacted_ips` | + `contacted_domains` |

URL VT’de yoksa önce `POST` + `GET` (preset’ten bağımsız). Batch taramada tüm ekler kapalı (`skipExtras`).

#### Fabrika varsayılanı matrisleri (`utils.js` → `DEFAULT_SCAN_PRESETS`)

**Hızlı mod** — yalnızca ana rapor; ek ilişki/MITRE yok.

| IOC | REL | LBL | MITRE |
|-----|-----|-----|-------|
| IP | — | STD | — |
| Domain | — | STD | — |
| URL | — | STD | — |
| File | — | STD | — |

**Detaylı mod** — pivot ağırlıklı; dosyada MITRE; standart etiket listesi.

| IOC | REL | LBL | MITRE |
|-----|-----|-----|-------|
| IP | REL | STD | — |
| Domain | REL+ | STD | — |
| URL | REL | STD | — |
| File | REL+ | STD | ✓ |

**Analist modu** — en derin pivot (IP/domain/file); URL’de birincil ilişki; genişletilmiş AV etiketleri.

| IOC | REL | LBL | MITRE |
|-----|-----|-----|-------|
| IP | REL+ | EXT | — |
| Domain | REL+ | EXT | — |
| URL | REL | EXT | — |
| File | REL+ | EXT | ✓ |

Tahmini üst sınır VT çağrısı (popup ipucu): Hızlı 1–2; Detaylı 2–4; Analist 2–5 (IoC türüne göre değişir).

IP taramalarında popup ayrıca **AbuseIPDB çağrı sayısı** gösterir (Hızlı 1; Detaylı/Analist 2).

#### AbuseIPDB (yalnızca IP)

AbuseIPDB **domain, URL ve dosya** taramalarında çalışmaz. Anahtar yoksa VT sonuçları gösterilir; Abuse kartında yapılandırılmamış mesajı çıkar.

| API | Ne zaman | Parametre |
|-----|----------|-----------|
| `GET /api/v2/check` | Her IP taraması (anahtar varsa) | `maxAgeInDays` = preset **Check overview** (`abuseOverallDays`) |
| `GET /api/v2/reports` | Preset’te **Category reports** açıksa | `maxAgeInDays` = **Report window** (`abuseWindowDays`); `perPage=100`, `page=1` |

**Fabrika varsayılanı (IP Abuse profili)**

| Preset | Matris ABU | Check overview | Report window | Reports API | Tahmini Abuse çağrı |
|--------|------------|----------------|---------------|-------------|------------------------|
| Hızlı | `CHK` | 90 gün | — | kapalı | 1 |
| Detaylı | `R30/180` | 180 gün | 30 gün | açık (kategori özeti) | 2 |
| Analist | `R90/365` | 365 gün | 90 gün | açık | 2 |

UI’da seçilebilir günler: report window **30 / 90**; check overview **90 / 180 / 365**. Kategori adları sabit sözlükten (`ABUSE_CATEGORIES` in `background.js`) gelir.

**Birleşik tehdit seviyesi (IP):** VT `threatLevel` ile Abuse skoru birleştirilir (`combineIpThreatLevel`). Abuse skoru için **tehdit etiketi** eşikleri: **≥75** malicious, **≥50** suspicious, altı clean.

**Görsel katman (rozet / skor çubuğu):** Aynı 0–100 skoru UI renk katmanında farklı dilimlerle gösterilir (`abuseScoreToRiskTier`): **≤24** low, **≤49** medium, **≤74** high, **≥75** critical. Bu, birleşik `threatLevel` etiketinden bağımsızdır; örn. skor 69 “suspicious” tehdit + “high” görsel katman olabilir.

**Hata davranışı:** Abuse anahtarı yok → `not_configured`, VT-only. HTTP **429** → kısa bekleme ile bir yeniden deneme; başarısızsa kullanıcıya rate-limit mesajı. Abuse hatası VT sonucunu iptal etmez.

#### Onay kutuları vs matris

Kart altındaki dört kutu **kaydet** dediğinizde o şablonun **tüm IoC satırlarına aynı** `relMode` / `labels` / `mitre` değerini yazar; matristeki tür başına farklar sıfırlanır. Fabrika ayrımını korumak için **Varsayılana sıfırla** kullanın.

Matris, depodaki gerçek v3 profili yansıtır; kutular profilin **en derin REL** + herhangi bir satırda **EXT** / **MITRE** olup olmadığına göre doldurulur (yalnızca dosya satırına bakılmaz).

#### Depolama ve sıfırlama

- Anahtar: `vtScanPresets` → `{ version: 3, presets: { quick, detailed, analyst } }`
- Eski v1/v2 otomatik yükseltilir.
- Ayarlar → **Varsayılana sıfırla**: yukarıdaki fabrika tablolarını depoya yazar ve matrisi günceller (kaydetmeye gerek kalmadan uygulanır).

---

#### IP adresi

| | Quick | Detailed / Analyst |
|---|--------|-------------------|
| **API** | `GET /ip_addresses/{ip}` | + `resolutions`; **full**: + `communicating_files` |
| **Hero** | IoC + chip’ler | Reputation (ülke/AS yalnızca Details) |
| **Details** | ASN, network, tags, JARM, HTTPS cert, votes | Aynı |
| **İlişki** | — | Çözümlenen host adları; iletişim kuran dosyalar (plan izin verirse) |
| **relMode** | `none` | **Detailed:** `primary` · **Analyst:** `full` |
| **AbuseIPDB** | Check only (`CHK`, 90d overview) | Check + 30d category reports · Analyst: 90d reports, 365d overview |

---

#### Domain

| | Quick | Detailed / Analyst |
|---|--------|-------------------|
| **API** | `GET /domains/{domain}` | + `resolutions`; **full**: + `communicating_files` |
| **Hero** | IoC adı, etiket chip’leri, reputation | Konsensüs etiketi + **tags** (kayıtçı/tarih yalnızca Details) |
| **Details** | DNS A/AAAA/CNAME **değerleri**, WHOIS özeti, kategoriler | Aynı |
| **Domain badge (sayfa)** | M/S/Undet, oran | + tehdit etiketi, reputation, son analiz |
| **relMode** | `none` | **Detailed & Analyst:** `full` |

---

#### URL

| | Quick | Detailed / Analyst |
|---|--------|-------------------|
| **API** | `GET /urls/{id}` (varsa); yoksa `POST`+`GET` | + `contacted_domains` |
| **Hero** | Kısaltılmış URL | HTTP / redirect chip (başlık ve final URL Details’ta) |
| **Details** | Final URL, başlık, kategoriler, redirect zinciri | Aynı |
| **Batch CSV** | Temel stats + details | + `suggested_label`, `detail_http_status`, vb. |
| **relMode** | `none` | **Detailed & Analyst:** `primary` |
| **labels** | `standard` | **Analyst:** `extended` |

---

#### File (hash)

| | Quick | Detailed | Analyst |
|---|--------|----------|---------|
| **API** | `GET /files/{hash}` | + `contacted_ips`; **full**: + `contacted_domains` | Aynı |
| **MITRE** | — | Önce dosya `attributes`; yoksa `behaviours` | Aynı |
| **Hero** | Dosya adı · tip · imza chip | Aynı | Aynı |
| **labels** | `standard` | `standard` | `extended` |

**İmza notu:** VT `signature_info.verified` değeri `"Valid"`, `"Signed"`, `true` vb. olabilir; uzantı bunları **Signed/Unsigned** chip’ine doğru çevirir (ham `"Valid"` metninin `Unsigned` sayılması hatası giderildi).

---

#### Batch (çoklu tarama)

| | Tüm preset’ler |
|---|----------------|
| **VT API ekleri** | Kapalı (`skipExtras`) — ilişki/MITRE sandbox çağrılmaz |
| **AbuseIPDB (IP satırları)** | **Açık** — aktif preset’in IP Abuse profili uygulanır (check ± reports) |
| **Gösterilen** | Stats, threat context, hero, details, CSV’de genişletilmiş sütunlar |
| **Atlanan (VT)** | İlişki listeleri, sandbox MITRE, extended AV label listesi |
| **CSV (IP)** | `abuse_score`, `abuse_reports`, `abuse_top_category`, `threat_level_vt`, `threat_level_abuse`, vb. |

---

Bazı ilişki türleri (`communicating_files`, `embedded_*`) VT **Enterprise** hesabında gerekebilir; 403/hata durumunda ilgili blok sessizce atlanır veya hata satırı gösterilir.

### 4) Domain badge blacklist

Her satıra bir kural olacak şekilde desteklenen biçimler:

- Domain: `example.com`
- Wildcard domain: `*.example.com`
- URL prefix: `https://example.com/private`
- Path prefix: `/internal`
- Tümünü kapat: `*`

## Kullanım

### Popup üzerinden tarama

1. IoC verisini metin alanına girin (toplu tarama için her satıra bir IoC).
2. İsterseniz dosyadan (`.csv`, `.txt`, `.tsv`) içe aktarın.
3. Preset seçin ve **Scan** ile başlatın.
4. Sonuç kartından:
   - VirusTotal raporunu açın
   - Özet kopyalayın
   - JSON kopyalayın

### Context menu taraması

- Sayfada metin seçin
- Sağ tık > **Scan selection with PixelPaw SOC**
- Sonuç arka plan akışıyla işlenir

### Domain / IP badge taraması (content script)

- Desteklenen sayfalarda **domain** metinlerinin yanında `VT` rozeti; **public IPv4/IPv6** için risk renkli IP rozeti
- Tıklanınca mini panel: domain için VT özeti; IP için VT + AbuseIPDB (anahtar varsa) hibrit panel
- Oturum önbelleği ile aynı IoC’ye tekrar API çağrısı yapılmaz

### Haberler sekmesi

- RSS kaynaklarından haberleri listeler
- Kaynak filtresi ve arama destekler
- Ön bellek kullanır; manuel yenileme yapılabilir

## Veri Saklama Modeli

Veriler `chrome.storage.local` altında saklanır. Başlıca anahtarlar:

- `vtApiKey`, `vtApiKeySavedAt`
- `abuseipdbApiKey`, `abuseipdbApiKeySavedAt`
- `vtUiLang`, `vtPopupTheme`, `vtUiMode` (`popup` | `sidepanel`)
- `vtRateIntervalSec`, `vtProMode`
- `vtNotifyQueued`, `vtNotifyNews`, `vtNotifyContext`
- `vtScanPresets`
- `vtDomainBadgeBlacklist`
- `vtRecentHistory`, `vtBatchHistory`
- `vtAnalytics`
- `vtNewsCache`, `vtNewsFetchedAt`

## İzinler

`manifest.json` kapsamında kullanılan temel izinler:

- `storage`: ayarlar, geçmiş, analytics, haber önbelleği
- `sidePanel`: yan panel arayüz modu (Chrome 114+)
- `contextMenus`: seçili metinden tarama başlatma
- `notifications`: kuyruk/haber/context bildirimleri
- `clipboardWrite`: özet ve JSON kopyalama
- `host_permissions`: VirusTotal, AbuseIPDB (`api.abuseipdb.com`) ve RSS kaynaklarına erişim

## Güvenlik ve Gizlilik

- API anahtarları yalnızca yerel depoda saklanır.
- IoC sorguları **VirusTotal** ve (IP + anahtar varsa) **AbuseIPDB** API uç noktalarına gönderilir.
- Haber verileri tanımlı RSS kaynaklarından çekilir.
- Proje yapısında reklam/izleme amaçlı üçüncü taraf telemetry bulunmaz.

## Sınırlamalar ve Operasyonel Notlar

- Manifest V3 service worker doğası gereği arka plan süreci kalıcı değildir.
- Yüksek hacimli taramada API limitleri hesabınızın VT ve AbuseIPDB planlarına bağlıdır; Abuse günlük kota aşımında HTTP 429 dönebilir.
- Domain rozeti dinamik sayfalarda performans için badge sayısını sınırlar.
- Batch geçmişi ve recent listesi sınırlı sayıda kayıt tutar.

## Proje Yapısı

```text
manifest.json
background.js
popup.html
popup.js
popup.css
options.html
options.js
options.css
content.js
i18n.js
utils.js
tokens.css
base.css
icons/
```
# PixelPaw-SOC
# PixelPaw-SOC
