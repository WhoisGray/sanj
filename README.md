# sanj

[![CI](https://github.com/whoisGray/sanj/actions/workflows/ci.yml/badge.svg)](https://github.com/whoisGray/sanj/actions/workflows/ci.yml)

بررسی زنده بودن سرورهای VPN. فهرست NordVPN را از API رسمی می‌گیرد و فقط پروتکلی را که انتخاب کنید آزمایش می‌کند. پیش‌فرض IKEv2 است. برای فهرست دامنه یا IP خودتان هم یک حالت جدا دارد.

فقط سرورهایی را اسکن کنید که اجازهٔ بررسی‌شان را دارید.

## دانلود

آخرین نسخه را با یک دستور نصب کنید. الان آخرین انتشار [`v1.0.1`](https://github.com/WhoisGray/sanj/releases/tag/v1.0.1) است. دستور خودش سیستم و معماری را می‌فهمد و همان بسته را با چک‌سام SHA256 می‌گذارد روی PATH.

macOS و Linux. همین یک خط نصب می‌کند، و با `-update` همان خط را برای آخرین نسخه دوباره می‌زند:

```bash
curl -fsSL https://raw.githubusercontent.com/whoisGray/sanj/main/install.sh | sh -s -- -update
```

Windows در PowerShell. دوباره اجرا کردنش یعنی به‌روزرسانی:

```powershell
irm https://raw.githubusercontent.com/whoisGray/sanj/main/install.ps1 | iex
```

بعد از اینکه این کد داخل Release باشد، روی هر سه سیستم:

```bash
sanj -update
```

نسخهٔ منتشرشدهٔ `v1.0.1` پرچم `-update` را ندارد. تا تگ بعدی، همان دستور نصب را دوباره اجرا کنید.

فایل هر سیستم از [Releases](https://github.com/whoisGray/sanj/releases) هم جداگانه هست. با پوش کردن یک تگ مثل `v1.0.1` ساخته می‌شود. کنار فایل‌ها `checksums.txt` هست.

| سیستم | معماری | فایل |
| --- | --- | --- |
| macOS اپل سیلیکون | arm64 | `sanj_1.0.1_darwin_arm64.tar.gz` |
| macOS اینتل | amd64 | `sanj_1.0.1_darwin_amd64.tar.gz` |
| Linux | amd64 | `sanj_1.0.1_linux_amd64.tar.gz` |
| Linux | arm64 | `sanj_1.0.1_linux_arm64.tar.gz` |
| Windows | amd64 | `sanj_1.0.1_windows_amd64.zip` |
| Windows | arm64 | `sanj_1.0.1_windows_arm64.zip` |

`1.0.1` همان شمارهٔ تگ است، بدون `v`.

### macOS و Linux

```bash
tar -xzf sanj_1.0.1_darwin_arm64.tar.gz
sudo mv sanj /usr/local/bin/
sanj -version
```

بایینری امضا نشده است. اگر Gatekeeper روی مک جلوی اجرا را گرفت:

```bash
xattr -d com.apple.quarantine /usr/local/bin/sanj
```

جمع چک:

```bash
shasum -a 256 -c checksums.txt
```

روی Linux به جای `shasum` از `sha256sum -c checksums.txt` استفاده کنید.

### Windows

zip را باز کنید و در PowerShell:

```powershell
.\sanj.exe -version
Get-FileHash .\sanj_1.0.1_windows_amd64.zip -Algorithm SHA256
```

هش را با خط همان فایل در `checksums.txt` مقایسه کنید.

### نصب با Go

Go 1.22 یا جدیدتر:

```bash
go install github.com/whoisGray/sanj@latest
```

## استفاده

```bash
sanj -nord                         # فقط IKEv2
sanj -nord -proto wire             # فقط WireGuard
sanj -nord -proto ikev2,wire
sanj -nord -proto full             # همه‌ی پروتکل‌ها
sanj -nord -country se -limit 40 -c 64
sanj -file servers.json
sanj -file server.txt              # هر خط یک دامنه یا IPv4
```

`-proto` این‌ها را می‌پذیرد: `ikev2`، `wire` (همان `wg` و `wireguard`)، `openvpn`، فهرست با ویرگول، یا `full`.

`full` علاوه بر WireGuard و OpenVPN و IKEv2، پورت‌های udp/53 و tcp/80 را هم چک می‌کند تا پاسخ عجیب فایروال در جدول بیاید. اسکن تک‌پروتکل این دو پورت اضافه را نمی‌زند.

سروری که پروتکل انتخاب‌شده را ندارد از فهرست حذف می‌شود.

خروجی Nord این سه فایل است:

- `nord-results.json`
- `nord-results.csv`
- `nord-results.xlsx`

حالت فایل، خروجی را در `sanj-results.json` و `sanj-results.csv` و `sanj-results.xlsx` می‌نویسد.

کش فهرست Nord در `~/.cache/nordike` است و ۶ ساعت می‌ماند. `-refresh` کش را دور می‌زند.

اگر VPN روشن باشد و DNS فقط آدرس خصوصی (مثل `10.10`) برگرداند، فاز کشف متوقف می‌شود. VPN را خاموش کنید، یا با `-allow-poisoned` ادامه دهید.

### معنی چند ستون

| مقدار | معنی |
| --- | --- |
| `real` | پاسخ شبیه سرور واقعی همان پروتکل بود |
| `p1` | فقط فاز اول IKEv2 جواب داد |
| `silent` | پاسخی نیامد |
| `fresh=yes` | حداقل یک پروتکل تأیید شد |
| `unproven` | جواب قابل اتکا نبود |

## پرچم‌ها

| پرچم | پیش‌فرض | کار |
| --- | --- | --- |
| `-nord` | خاموش | گرفتن فهرست NordVPN و آزمایش |
| `-proto` | `ikev2` | پروتکل آزمایش |
| `-country` | همه | کد یا نام کشور، با ویرگول |
| `-limit` | `0` | سقف تعداد؛ صفر یعنی همه. کم‌بارترین‌ها اول |
| `-load` | `100` | رد کردن سرور شلوغ‌تر از این |
| `-offline` | خاموش | سرورهای غیرآنلاین هم بیایند |
| `-refresh` | خاموش | دانلود دوبارهٔ فهرست |
| `-ttl` | `6h` | عمر کش |
| `-c` | `80` | تعداد کار همزمان. در `-nord` اگر این را ندهید ۳۲ است |
| `-ike-timeout` | `1s` | مهلت IKEv2 |
| `-tcp-timeout` | `1200ms` | مهلت TCP. در `-nord` اگر ندهید `1s` است |
| `-ike-user` | بسته به حالت | هویت کاربر در IKE_AUTH |
| `-ike-id` | بسته به حالت | شناسهٔ سمت سرور در IKE_AUTH |
| `-file` | | JSON کاتالوگ، فایل متنی، یا نتیجهٔ قبلی |
| `-phase` | | `1` کشف DNS، `2` آزمایش، `all` هر دو |
| `-dns` | `1.1.1.1:53` | سرور DNS فاز کشف |
| `-allow-poisoned` | خاموش | ادامه با وجود IP خصوصی |
| `-json` `-csv` `-xlsx` | بسته به حالت | مسیر خروجی |
| `-version` | | چاپ نسخه و خروج |
| `-update` | | جایگزینی همین برنامه با آخرین Release گیت‌هاب |

در `-nord` اگر `-ike-user` و `-ike-id` را ندهید، مقدارشان `health@nordvpn.com` و `nordvpn.com` است. در حالت فایل، `this is health check` و `ironnodes.com`.

## انتشار

```bash
git tag v1.0.0
git push origin v1.0.0
```

workflow به نام Release اول تست را اجرا می‌کند، بعد شش بسته را می‌سازد و روی صفحهٔ Releases می‌گذارد. `sanj -version` همان تگ را چاپ می‌کند. آخرین تگِ منتشرشده `v1.0.1` است.

هر push و هر pull request هم با workflow به نام CI تست و کامپایل هر شش سیستم را می‌گیرد.

## ساخت محلی

```bash
go test ./...
go build -o sanj .
./sanj -version
```
