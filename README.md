# PixelPaw SOC

Chrome uzantısı (Manifest V3): IoC taraması (VirusTotal), isteğe bağlı AbuseIPDB (IP), yerel geçmiş ve analitik. Arayüz: Türkçe / İngilizce.

## Özellikler

- Tekil ve toplu IoC taraması (IP, domain, URL, hash)
- Sağ tık ve sayfa içi domain/IP rozeti
- Tarama şablonları (Hızlı / Detaylı / Analist)
- VirusTotal **yeniden analiz** (reanalyze) — sonuç kartından
- Ayarlar: API anahtarları, hız limiti, bildirimler, analitik panel

## Kurulum

1. `chrome://extensions` → **Geliştirici modu**
2. **Paketlenmemiş öğe yükle** → proje klasörü

## Yapılandırma

**Ayarlar** sayfasından:

| Anahtar | Zorunlu | Açıklama |
|---------|---------|----------|
| VirusTotal API | Evet | Tüm taramalar |
| AbuseIPDB API | Hayır | Yalnızca IP zenginleştirme |

Anahtarlar yalnızca `chrome.storage.local` içinde tutulur (14 gün TTL).

## Geliştirme

```bash
bash scripts/prepush-check.sh
```

Güvenlik kontrol listesi: [`SECURITY_HARDENING_CHECKLIST.md`](SECURITY_HARDENING_CHECKLIST.md)

## Changelog

### [1.0.1] — 2026-05-29

**Eklenen**
- Tüm IoC türleri için VT **Reanalyze** (sonuç kartı, sağ üst ikon)
- Chart üstü durum bandı (kuyruk / hata mesajları)
- Arka plan: `VT_REANALYZE` → VT v3 `POST .../analyse`

**Değişen**
- Reanalyze geri bildirimi toast yerine chart alanında
- Sürüm: `1.0.1`

### [1.0.0] — 2026-05-28

- İlk yayın: popup tarama, batch, içerik scripti, ayarlar/analitik, güvenlik sertleştirme temeli
