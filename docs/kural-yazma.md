# Kural nasıl yazılır

Bir kural, log satırlarında neyin şüpheli sayılacağını söyleyen küçük bir YAML dosyasıdır. Bu belge kendi kuralını yazmak için gereken her şeyi anlatır: dosyanın nereye konacağı, bir kuralın hangi olaylara baktığı, beş kural türü, zamanın nasıl sayıldığı ve yazdığın kuralı nasıl deneyeceğin.

Alan adları [Sigma](https://github.com/SigmaHQ/sigma)'nın genel adlandırmasını izler (`src_ip`, `dst_port`, `user`); Sigma kuralı okumuş biri buradakileri tanır. İkisi arasındaki farklar [en sonda](#sigma-ile-karşılaştırma).

## En küçük kural

```yaml
# rules/SSH-001.yaml
id: SSH-001
name: SSH kaba kuvvet denemesi
type: threshold
severity: high
match:
  action: auth_fail
threshold: 5
window_seconds: 60
```

Okunuşu: başarısız giriş olaylarına (`match`) bak; aynı kaynak adresten (`group_by`, bu türde varsayılan `src_ip`) 60 saniye içinde 5 tane gelirse `high` önemde bir uyarı aç.

- Kurallar `rules/` klasöründe durur; her dosyada bir kural. İçindeki klasörler de okunur (`rules/sigma/`).
- Sunucu açılırken hepsini yükler. Bir dosyayı değiştirdikten sonra arayüzün Kurallar sayfasındaki **Kuralları yeniden yükle** düğmesine bas (ya da `POST /rules/reload`): kurallar saklanan bütün olaylar üzerinde baştan çalışır, uyarılar yeni kurallara göre güncellenir.
- Hatalı bir dosya diğerlerinin yüklenmesini engellemez. Neyin yanlış olduğu Kurallar sayfasında ve `GET /rules` yanıtının `errors` listesinde yazar: `SSH-009.yaml: treshold: Extra inputs are not permitted`.
- Bilinmeyen bir alan hatadır. Yanlış yazılmış bir ayar sessizce yok sayılmaz.

## Bir kural hangi olaylara bakar

Her log satırı bir olaydır. Parser satırı tanırsa alanlarını doldurur:

| Alan | İçeriği | Örnek |
|---|---|---|
| `action` | Satırın anlattığı şey (aşağıdaki tablo) | `auth_fail` |
| `service` | Satırı yazan program | `sshd`, `sudo`, `kernel`, `CRON` |
| `host` | Logu yazan makine | `web-01` |
| `user` | İlgili kullanıcı | `root` |
| `src_ip` | Kaynak adres | `203.0.113.45` |
| `dst_port` | Hedef port (güvenlik duvarı satırlarında) | `3389` |
| `level` | Satır tek başına dikkat çekici mi: `info` ya da `warning` | `warning` |
| `message` | Programın yazdığı metin | `Failed password for root from ...` |

| `action` | Anlamı | Hangi satırlardan |
|---|---|---|
| `auth_fail` | Giriş denemesi reddedildi | sshd: `Failed password for ...` |
| `auth_ok` | Giriş başarılı | sshd: `Accepted password/publickey for ...` |
| `invalid_user` | Var olmayan kullanıcı adı denendi | sshd: `Invalid user ...` |
| `disconnect` | SSH bağlantısı kapandı | sshd: `Disconnected from ...`, `Received disconnect from ...`, `Connection closed by ...` |
| `sudo_exec` | sudo ile komut çalıştırıldı | sudo: `... COMMAND=...` |
| `sudo_denied` | sudo komutu reddetti | sudo: `user NOT in sudoers`, `command not allowed` |
| `conn_block` | Güvenlik duvarı paketi düşürdü | çekirdek: `[UFW BLOCK]` |
| `conn_allow` | Güvenlik duvarı bağlantıyı geçirdi | çekirdek: `[UFW ALLOW]` |

Tanınmayan satırlar da saklanır; `action` alanları boştur, `service`, `host` ve `message` alanları doludur. Onlara anahtar kelime kurallarıyla bakılır.

### `match`: kuralın süzgeci

`match`, kuralın hangi olayları göreceğini seçer. Alanları `action`, `service`, `host`, `user`, `level` ve `dst_port`; her biri tek değer ya da liste alır. Listedeki değerlerden biri yeter, yazılan alanların hepsi tutmalıdır:

```yaml
match:
  action: [conn_block, conn_allow]   # ikisinden biri
  dst_port: 22                        # ve hedef port 22
```

`match` yazılmazsa kural bütün olaylara bakar.

### `group_by`: kim için sayılıyor

Kurallar olayları bir alana göre gruplar ve her grubu ayrı değerlendirir: `src_ip` (çoğu türde varsayılan), `user`, `host` ya da `service`. "Beş başarısız giriş" her kaynak adres için ayrı sayılır; on adresten birer deneme uyarı üretmez.

Gruplama alanı boş olan olay kurala hiç girmez: `group_by: src_ip` olan bir kural, kaynak adresi olmayan satırları görmez.

## Ortak alanlar

| Alan | Zorunlu | Açıklama |
|---|---|---|
| `id` | evet | Kimlik. Harf, rakam, `-`, `_`, `.`; iki kuralın kimliği aynı olamaz |
| `name` | evet | Uyarı listesinde görünen ad |
| `type` | evet | `keyword`, `threshold`, `sequence`, `port_scan`, `rare_port` |
| `severity` | evet | `low`, `medium`, `high`, `critical` |
| `description` | | Kuralın ne aradığı ve neyi bilerek aramadığı |
| `enabled` | | `false` ise kural yüklenir, çalıştırılmaz (varsayılan `true`) |
| `match` | | Yukarıda |
| `group_by` | | Yukarıda |
| `cooldown_seconds` | | Bir uyarının son olayından sonra bu süre içinde gelen eşleşmeler yeni uyarı açmaz, aynı uyarıya eklenir (varsayılan 300) |
| `allowlist` | | Kuralın yok saydığı kaynak adresler ya da ağlar: `192.0.2.10`, `192.0.2.0/24`, `2001:db8::/32` |
| `summary` | | Uyarı metni; [aşağıda](#uyarı-metni) |
| `author`, `source`, `license`, `references`, `tags`, `false_positives` | | Kuralın nereden geldiği; [aşağıda](#kuralın-kaynağı) |

## Kural türleri

### `keyword`: satırda belli bir metin

Aranan metni içeren her satır bir uyarıdır (yakın zamanlı olanlar aynı uyarıda toplanır).

```yaml
id: KW-001
name: sudo komutunda hassas dosya
type: keyword
severity: medium
match:
  action: [sudo_exec, sudo_denied]
keywords:
  - /etc/shadow
  - /etc/sudoers
  - authorized_keys
group_by: user
```

| Alan | Açıklama |
|---|---|
| `keywords` | Aranan metinler; biri yeter |
| `require` | Ayrıca geçmesi gereken metinler. Her madde tek bir metin ya da "biri yeter" anlamında bir listedir; maddelerin hepsi sağlanmalıdır |
| `exclude` | Biri geçiyorsa satır sayılmaz |
| `regex` | Düzenli ifade (Python `re`). `keywords` ile birlikte de, onun yerine de yazılabilir |
| `group_by` | Bu türde varsayılan `host` |

Bilinmesi gerekenler:

- **Büyük/küçük harf ayrımı yoktur.** `regex` için vardır; istemiyorsan `(?i)` ile başlat.
- **Metin olduğu gibi aranır**, kalıp değildir: `a.c` yalnızca `a.c` ile eşleşir. Tek istisna `*`: araya giren herhangi bir metin demektir. `wget *; chmod +x`, önce `wget `, ilerisinde `; chmod +x` geçen satırı bulur. Yıldızın kendisini aramak için `\*` yaz.
- **Satır, programın adı ve mesajıdır:** `sudo: bob : TTY=pts/0 ; ...`. Yani `pkexec` anahtar kelimesi, `pkexec` programının yazdığı satırları da bulur. Zaman damgasına ve makine adına bakılmaz. `regex` yalnızca mesajı görür; `^` mesajın başıdır.
- **Baştaki ve sondaki boşluk anlamlıdır.** `"scp "` ile `scp` aynı şey değildir: ilki `scp` sözcüğünden sonra boşluk ister, `scpd` ile eşleşmez. Böyle metinleri tırnak içinde yaz.
- **Vurgu:** arayüz, eşleşen metinleri (`require` ile istenenler dahil) satırın içinde işaretler.

`require` ve `exclude` ile:

```yaml
id: KW-002
name: Uzak makineye dosya kopyalama
type: keyword
severity: low
keywords: ["scp ", "rsync "]
require:
  - ["@", "::"]        # bunlardan biri de geçmeli
  - "COMMAND="         # ve bu da
exclude:
  - --dry-run
```

### `threshold`: kısa sürede çok sayıda olay

Bir gruptan `window_seconds` içinde `threshold` tane eşleşen olay gelince uyarır.

```yaml
type: threshold
match:
  action: auth_fail
threshold: 5
window_seconds: 60
```

Uyarının kanıtı, eşiği dolduran olaylar ve ardından `cooldown_seconds` içinde gelen her eşleşmedir: yetmiş denemelik bir saldırı tek uyarıdır, yetmiş kanıt satırıyla.

### `sequence`: sırayla olan olaylar

Bir grup, adımları sırayla ve `within_seconds` dolmadan tamamlayınca uyarır.

```yaml
id: SSH-002
name: Başarısız denemelerden sonra başarılı giriş
type: sequence
severity: critical
within_seconds: 600
steps:
  - match:
      action: auth_fail
    count: 5              # bu adım beş olay ister (varsayılan 1)
  - match:
      action: auth_ok
```

- En az iki adım gerekir ve her adımın bir `match` süzgeci olmalıdır.
- Bir olay yalnızca bir adıma sayılır.
- Süre son adımdan geriye doğru ölçülür: yarım saat süren bir deneme dizisinin ardından gelen giriş, dizinin son on dakikasıyla yakalanır.
- Kuralın kendi `match` alanı, adımların hepsine uygulanan ek bir süzgeçtir.

### `port_scan`: çok sayıda farklı port

Bir grup `window_seconds` içinde `min_ports` farklı hedef porta paket gönderince uyarır. Aynı porta giden yüz paket bir port sayılır.

```yaml
type: port_scan
match:
  action: [conn_block, conn_allow]
min_ports: 15
window_seconds: 60
```

### `rare_port`: beklenmeyen port

Portu listeye uyan her bağlantı bir uyarıdır.

```yaml
type: rare_port
match:
  action: conn_allow
mode: watchlist               # listedeki portlar şüpheli
ports: [23, 135, 139, 445, 3389, 5900]
```

`mode: allowlist` tersini söyler: listedekiler beklenen portlardır, **geri kalan her port** şüphelidir. Yalnızca 22, 80 ve 443'ün açık olması gereken bir sunucuda `match: {action: conn_allow}`, `mode: allowlist`, `ports: [22, 80, 443]` yazmak, güvenlik duvarından geçen başka her bağlantıyı gösterir.

## Zaman nasıl sayılır

- **Pencereler yarı açıktır.** İlk ve son olay arasındaki fark verilen saniyeden **küçük** olmalıdır. Tam 60 saniyeye yayılan beş olay `window_seconds: 60` içinde sayılmaz; 59 saniyeye yayılanlar sayılır.
- **`cooldown_seconds` uyarıları birleştirir.** Bir uyarı açıldıktan sonra, son olayından itibaren bu süre içinde gelen her eşleşme aynı uyarıya eklenir. Süre sessiz geçerse sonraki eşleşme sıfırdan başlar: yeni bir uyarı için eşik yeniden dolmalıdır. `0` yazılırsa yalnızca aynı saniyedeki eşleşmeler birleşir.
- **Uyarılar türetilmiş veridir.** Olaylardan ve kurallardan hesaplanırlar; kural değişince eski uyarılar yeni kurala göre yeniden hesaplanır. Aynı olay kümesinin uyarısı kimliğini korur ve yeni olaylar geldikçe büyür.
- Zamanlar UTC olarak saklanır; logun saat dilimi yüklerken verilir.

## Uyarı metni

`summary`, uyarı listesinde görünen cümledir. Süslü parantez içindeki adlar uyarının değerleriyle doldurulur:

```yaml
summary: "{key} adresinden {seconds} sn içinde {count} başarısız giriş"
# 203.0.113.45 adresinden 85 sn içinde 71 başarısız giriş
```

| Yer tutucu | Değeri | Türler |
|---|---|---|
| `{key}` | Grubun değeri (adres, kullanıcı, ...) | hepsi |
| `{count}` | Kanıt satırı sayısı | hepsi |
| `{seconds}` | İlk ve son kanıt arasındaki süre | hepsi |
| `{rule_id}`, `{rule_name}` | Kuralın kimliği ve adı | hepsi |
| `{threshold}`, `{window_seconds}` | Kuralın ayarları | `threshold` |
| `{within_seconds}` | Kuralın ayarı | `sequence` |
| `{ports}` | Görülen farklı port sayısı | `port_scan`, `rare_port` |
| `{min_ports}`, `{window_seconds}` | Kuralın ayarları | `port_scan` |

Bilinmeyen bir yer tutucu kuralın yüklenmesini engeller ve hata mesajı kullanılabilecekleri sayar. `summary` yazılmazsa türün kendi cümlesi kullanılır.

## Kuralın kaynağı

Başka bir koleksiyondan alınan kurallar için. Hiçbiri kuralın ne yaptığını değiştirmez; arayüz bunları kuralın ve uyarılarının yanında gösterir.

```yaml
author: Florian Roth (Nextron Systems)
source: https://github.com/SigmaHQ/sigma/blob/.../lnx_sshd_susp_ssh.yml
license: Detection Rule License 1.1 (https://github.com/SigmaHQ/Detection-Rule-License)
references:
  - https://example.org/advisory
tags: [attack.initial-access, attack.t1190]      # örneğin MITRE ATT&CK
false_positives:
  - Yanlış yapılandırılmış istemciler
```

## Kuralı denemek

1. **Yükleniyor mu?** Dosyayı `rules/` altına koy, Kurallar sayfasında yeniden yükle. Hata varsa sayfanın altında dosya adıyla birlikte görünür.
2. **Beklediğini buluyor mu?** Örnek logları ya da kendi logunu yükle, uyarı listesine bak. Bir uyarıya tıklayınca kanıt satırları ve satırlarda işaretlenen yerler görünür: kuralın neye takıldığı oradan okunur.
3. **Beklemediğini buluyor mu?** İnceleme sayfasındaki "Kural" süzgeci, o kuralın kanıtı olan bütün satırları gösterir. Zararsız olanlar varsa `match` süzgecini daralt, eşiği yükselt ya da `allowlist` ekle.
4. **Sınırı nerede?** [`samples/measure.py`](../samples/measure.py), her adresin ne yaptığı bilinen bir log üretip kuralların neyi yakaladığını, neyi kaçırdığını ve neye yanlış alarm verdiğini sayar. Sonuçları ve yorumu: [Tespit ölçümü](tespit-olcumu.md).

Sunucu olmadan denemek için:

```bash
cd backend
python -m app.load ../samples/auth.log ../samples/ufw.log --year 2026
# ../samples/auth.log: 1057 lines, 605 parsed, 452 unparsed, 0 duplicates, 0 conflicts
# ../samples/ufw.log: 781 lines, 781 parsed, 0 unparsed, 0 duplicates, 0 conflicts
# 8 alerts, 8 of them new
```

## Sık yapılan hatalar

| Belirti | Neden |
|---|---|
| Kural yüklü ama hiç uyarı yok | `group_by` alanı o satırlarda boş (ör. `src_ip`, cron satırlarında yoktur). `group_by: host` dene |
| `keyword` kuralı hiçbir şey bulmuyor | `match.service` programın adıyla birebir aynı olmalı: `CRON` ile `cron` farklıdır |
| `not valid YAML ...: found undefined alias` | Metin `*` ile başlıyor ve tırnak içinde değil. `"*wget *"` yaz |
| `keywords.0: Input should be a valid string` | Metinde `: ` var ve tırnak yok; YAML onu ad-değer çifti sandı. `"sudo: denied"` yaz |
| `'*' has nothing to look for` | Yalnızca yıldızdan oluşan bir anahtar kelime hiçbir şey aramaz |
| Eşik tam sınırda tetiklenmiyor | Pencere yarı açık: beş olay 60 saniyeden **kısa** bir süreye sığmalı |
| Her turda yeni uyarı | Olaylar arası süre `cooldown_seconds` değerinden uzun. Süreyi uzat ya da kaynağı `allowlist` içine al |
| `id ... is already used by ...` | İki dosyada aynı kimlik. İkinci dosya yüklenmez |

## Sigma ile karşılaştırma

Sigma kuralları bir olay kaydının alanlarını sınar ve hangi kayıt türüne baktığını `logsource` ile söyler. Buradaki kurallar tek bir kaynağa, log satırlarından çıkarılan olaylara bakar; karşılığında sayma, sıralama ve port sayma gibi, Sigma'da ayrı bir "correlation" kuralı gerektiren şeyler kuralın türüdür.

| Sigma | Burada |
|---|---|
| `title`, `id`, `description` | `name`, `id`, `description` |
| `level`: `informational`, `low`, `medium`, `high`, `critical` | `severity`: `low`, `medium`, `high`, `critical` |
| `status` | `enabled` (yalnızca açık/kapalı) |
| `logsource` (product, service, category) | `match.service`, `match.action` |
| `detection` içinde metin listesi (`keywords`) | `type: keyword`, `keywords` |
| `detection` içinde alan koşulu (`dst_port: 3389`) | `match` |
| `condition: a and b`, `a and not b` | `require`, `exclude` |
| `\|all`, `\|contains` gibi değiştiriciler | Yok. Metinler her zaman "içerir" anlamındadır; `require` "hepsi" demenin yoludur |
| `*` ve `?` joker karakterleri | Yalnızca `*` |
| Correlation kuralları (`event_count`, `value_count`, `temporal_ordered`) | `threshold`, `port_scan`, `sequence` türleri |
| `falsepositives`, `author`, `references`, `tags` | `false_positives`, `author`, `references`, `tags` |
| `src_ip`, `dst_ip`, `src_port`, `dst_port`, `user` alan adları | Aynı adlar |

Log satırlarında metin arayan Sigma kuralları `python -m app.sigma` ile çevrilebilir; depodaki 28 kural böyle geldi. Hangilerinin çevrilebildiği ve nedenleri: [`rules/sigma/README.md`](../rules/sigma/README.md).
