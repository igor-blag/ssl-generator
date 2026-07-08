# ssl-generator

Генератор CSR (Certificate Signing Request) и RSA-ключей с графическим интерфейсом.

Поддерживает OV (Organization Validation) и DV (Domain Validation) сертификаты для российских УЦ, включая поля ИНН, ОГРН и мультиязычные имена (IDNA/punycode).

## Возможности

- **OV-сертификаты**: полные реквизиты организации (O, ST, L, street, ИНН, ОГРН)
- **DV-сертификаты**: только CN + C (упрощённая форма)
- Несколько SAN (Subject Alternative Names) с возможностью удаления
- WildCard-домены (*.example.ru)
- Punycode для доменов с кириллицей
- Размер ключа: 2048 / 4096 бит
- Генерация `.cnf` файла (конфиг OpenSSL)
- Кроссплатформенность: Windows, macOS, Linux
- Проверка обновлений через GitHub

## Установка

### Windows

Скачайте `ssl-generator-windows-amd64.zip` со [страницы релизов](https://github.com/igor-blag/ssl-generator/releases/latest), распакуйте и запустите `ssl-generator.exe`.

### macOS / Linux

Соберите из исходников (требуется Go 1.21+ и CGO / gcc):

```bash
git clone https://github.com/igor-blag/ssl-generator.git
cd ssl-generator
go build -o ssl-generator .
```

#### macOS

Установите Xcode Command Line Tools:

```bash
xcode-select --install
```

#### Linux

Установите GCC и зависимости:

```bash
# Debian/Ubuntu
sudo apt install gcc libgl1-mesa-dev xorg-dev

# Fedora
sudo dnf install gcc libX11-devel libXcursor-devel libXrandr-devel mesa-libGL-devel
```

## Использование

1. Выберите тип сертификата: **OV** (организация) или **DV** (домен)
2. Заполните поля:
   - **CN** — домен, на который оформляется сертификат
   - **C** — код страны (RU)
   - Для OV: организация, регион, город, улица, ИНН, ОГРН
3. Добавьте DNS-имена в SAN (для DV — ровно одно, равное CN)
4. Выберите папку для сохранения
5. Нажмите **«Сгенерировать CSR»**

### После генерации

- `site.key` — приватный ключ (сохраните, понадобится на хостинге)
- `site.csr` — запрос на сертификат (подайте в УЦ, подпишите в КриптоПро)
- `site.cnf` — конфиг OpenSSL (опционально, для справки)

## Сборка под разные платформы

```bash
# Windows (из Linux/macOS)
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -o ssl-generator.exe .

# macOS (Intel)
GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -o ssl-generator-darwin .

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -o ssl-generator-darwin-arm64 .

# Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o ssl-generator-linux .
```

## Технологии

- [Go](https://go.dev/) 1.26
- [Fyne](https://fyne.io/) v2 — GUI toolkit
- [crypto/x509](https://pkg.go.dev/crypto/x509) — генерация CSR
- [golang.org/x/net/idna](https://pkg.go.dev/golang.org/x/net/idna) — punycode

## Лицензия

MIT
