# 🔐 Hash Checker

**🌐 Language / Dil:** [English](#-english) · [Türkçe](#-türkçe)

---

## 🇬🇧 English

A simple Python tool that calculates file hashes and verifies them against an expected value, so you can tell whether a downloaded file is intact or has been tampered with. It comes with both a **command-line tool** and a **graphical interface**, and has **no required dependencies** (standard library only).

### Features

- Supports **MD5, SHA-1, SHA-256, SHA-512**
- **Auto-detects the algorithm** from the hash length (32 / 40 / 64 / 128 hex characters)
- Reads files in chunks, so **huge files (e.g. multi-GB ISOs) don't fill your RAM**
- Verifies **checksum lists** in `sha256sum` format (e.g. `SHA256SUMS`)
- Scans **folders**, optionally recursively
- Case- and whitespace-insensitive, timing-safe comparison
- GUI with progress bar, cancel button, copy/paste buttons and live comparison
- Meaningful exit codes for scripting (CLI)
- Both the CLI and the GUI are in English

### Requirements

- Python 3.8 or newer (the code uses the `:=` operator)
- GUI: `tkinter` (bundled with Python on Windows/macOS; on some Linux distros run `sudo apt install python3-tk`)
- Optional: `tqdm` for a progress bar in the CLI (`pip install -r requirements.txt`)

### Installation

```bash
git clone https://github.com/talha200624/hash-checker.git
cd hash-checker
```

### Usage

#### Graphical interface

```bash
python hashcheck_gui.py
```

- **Verify File** tab: pick a file, paste the expected hash, click *Calculate & Verify*.
- **Verify Checksum List** tab: pick a `SHA256SUMS`-style file to check many files at once.

#### Command line

```bash
# Just calculate the hash (default: SHA-256)
python hashcheck.py ubuntu.iso

# Verify against an expected hash (algorithm is auto-detected)
python hashcheck.py ubuntu.iso -c 3a7bd3e2...

# Choose the algorithm; several files at once
python hashcheck.py a.zip b.zip -a md5

# Scan a folder recursively
python hashcheck.py downloads/ -r

# Verify a checksum list
python hashcheck.py --verify-list SHA256SUMS
```

| Option | Description |
|---|---|
| `-a`, `--algorithm` | `md5`, `sha1`, `sha256`, `sha512` |
| `-c`, `--expected` | Expected hash to compare against (single file only) |
| `-r`, `--recursive` | Scan folders recursively |
| `-l`, `--verify-list` | Verify a `sha256sum`-style checksum list |

**Exit codes:** `0` = everything OK · `1` = mismatch or missing/unreadable file · `2` = invalid usage.

### Security note

MD5 and SHA-1 are vulnerable to collision attacks. They are fine for detecting accidental corruption, but if you need to make sure a file was not deliberately modified, prefer **SHA-256** or stronger, and get the expected hash from a trusted source.

### License

[MIT](LICENSE)

---

## 🇹🇷 Türkçe

Dosyaların hash değerini hesaplayıp beklenen değerle karşılaştıran, böylece indirdiğin bir dosyanın bozulup bozulmadığını ya da değiştirilip değiştirilmediğini anlamanı sağlayan basit bir Python aracıdır. Hem **komut satırı aracı** hem de **grafik arayüz** içerir ve **zorunlu bir bağımlılığı yoktur** (sadece standart kütüphane).

### Özellikler

- **MD5, SHA-1, SHA-256, SHA-512** desteği
- Hash uzunluğundan **algoritmayı otomatik tespit** (32 / 40 / 64 / 128 hex karakter)
- Dosyayı parça parça okur, bu yüzden **çok büyük dosyalar (örn. birkaç GB'lık ISO) belleği doldurmaz**
- `sha256sum` biçimindeki **checksum listelerini** (örn. `SHA256SUMS`) doğrular
- **Klasörleri** tarar, istenirse alt klasörlerle birlikte
- Büyük/küçük harf ve boşluktan bağımsız, zamanlama saldırısına dayanıklı karşılaştırma
- İlerleme çubuğu, iptal düğmesi, kopyala/yapıştır düğmeleri ve canlı karşılaştırma olan arayüz
- Scriptlerde kullanılabilecek anlamlı çıkış kodları (CLI)

### Gereksinimler

- Python 3.8 veya üstü (kodda `:=` operatörü kullanılıyor)
- Arayüz için `tkinter` (Windows/macOS'ta Python ile gelir; bazı Linux sürümlerinde `sudo apt install python3-tk` gerekir)
- Opsiyonel: CLI'da ilerleme çubuğu için `tqdm` (`pip install -r requirements.txt`)

### Kurulum

```bash
git clone https://github.com/talha200624/hash-checker.git
cd hash-checker
```

### Kullanım

#### Grafik arayüz

```bash
python hashcheck_gui.py
```

- **Verify File** sekmesi: dosyayı seç, beklenen hash'i yapıştır, *Calculate & Verify*'a tıkla.
- **Verify Checksum List** sekmesi: birçok dosyayı tek seferde doğrulamak için `SHA256SUMS` benzeri bir liste seç.

> Arayüzün dili İngilizcedir.

#### Komut satırı

> Komut satırı aracının mesajları ve seçenek adları İngilizcedir.

```bash
# Sadece hash hesapla (varsayılan: SHA-256)
python hashcheck.py ubuntu.iso

# Beklenen hash ile doğrula (algoritma otomatik tespit edilir)
python hashcheck.py ubuntu.iso -c 3a7bd3e2...

# Algoritma seç; birden fazla dosya
python hashcheck.py a.zip b.zip -a md5

# Klasörü alt klasörleriyle tara
python hashcheck.py indirilenler/ -r

# Checksum listesini doğrula
python hashcheck.py --verify-list SHA256SUMS
```

| Seçenek | Açıklama |
|---|---|
| `-a`, `--algorithm` | `md5`, `sha1`, `sha256`, `sha512` |
| `-c`, `--expected` | Karşılaştırılacak beklenen hash (yalnızca tek dosya) |
| `-r`, `--recursive` | Klasörleri alt klasörleriyle tara |
| `-l`, `--verify-list` | `sha256sum` biçimindeki listeyi doğrula |

**Çıkış kodları:** `0` = her şey tamam · `1` = eşleşmeme veya eksik/okunamayan dosya · `2` = hatalı kullanım.

### Güvenlik notu

MD5 ve SHA-1 çakışma saldırılarına açıktır. Rastgele bozulmaları yakalamak için yeterlidir, ancak dosyanın kasıtlı olarak değiştirilmediğinden emin olmak istiyorsan **SHA-256** veya daha güçlüsünü kullan ve beklenen hash'i güvenilir bir kaynaktan al.

### Lisans

[MIT](LICENSE)
