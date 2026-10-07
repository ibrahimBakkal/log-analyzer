# Performans: bir milyon satır

Aşama 6'nın sorusu şuydu: araç, bir sunucunun bir aylık logu büyüklüğünde bir dosyayla ne yapar? Bu sayfa ölçümü, ölçümün gösterdiği yavaş noktaları, bunlar için yapılanları ve hâlâ yavaş kalanları anlatır.

```bash
cd backend
python ../samples/benchmark.py                   # bir milyon satır, yaklaşık dört dakika
python ../samples/benchmark.py --lines 100000    # yarım dakika
python ../samples/benchmark.py --keep /tmp/olcum # logu ve veritabanını saklar
```

Betik, istenen büyüklükte sentetik bir log yazar (bir sunucunun yoğun bir ayı: SSH girişleri ve başarısız denemeler, cron, güvenlik duvarı kayıtları; aralarına kaba kuvvet dalgaları ve port taramaları serpiştirilmiş), onu bir yüklemenin kullandığı kodla boş bir SQLite dosyasına yükler, kuralları çalıştırır, canlı takibin yapacağı gibi yüz satır daha ekler ve arayüzün yaptığı istekleri zamanlar. Kaynak adresler RFC 2544'ün ölçümler için ayırdığı `198.18.0.0/15` aralığından gelir.

Ölçümler 2 çekirdekli bir bulut makinesinde (Intel Xeon 2,1 GHz), Python 3.11 ve SQLite 3.45 ile, depodaki 32 etkin kuralla (5 kendi kuralı, 27 Sigma kuralı) alındı. Süreler çalıştırmadan çalıştırmaya oynar: uzun adımlar yüzde on kadar, milisaniyelik istekler bazen yarı yarıya.

## Bir milyon satır

Log dosyası: 147 MB, 6.9 sn içinde üretildi.

| Adım | Süre | Not |
|---|---|---|
| Yükleme (ayrıştırma + yazma) | 95.9 sn | 10.428 satır/sn; 904.884 ayrıştırıldı, 95.116 tanınmadı |
| Aynı dosyayı yeniden yükleme | 23.7 sn | hepsi kopya, atlandı |
| Kuralların tümü (32), baştan | 23.8 sn | 600 uyarı |
| &nbsp;&nbsp;28 anahtar kelime kuralı, tek geçişte | 5.6 sn | 0 uyarı |
| &nbsp;&nbsp;NET-001 (port_scan) | 6.9 sn | 192 uyarı |
| &nbsp;&nbsp;NET-002 (rare_port) | 0.2 sn | 0 uyarı |
| &nbsp;&nbsp;SSH-001 (threshold) | 4.6 sn | 384 uyarı |
| &nbsp;&nbsp;SSH-002 (sequence) | 8.2 sn | 24 uyarı |
| Canlı takip adımı: 100 yeni satır | 1120 ms | yazma 25 ms, kurallar 1095 ms; 600 uyarı |
| Veritabanı dosyası | 705 MB | 129.678 farklı kaynak adres |
| En yüksek bellek kullanımı | 409 MB | ölçüm betiğinin tamamı |

| İstek | Ortanca | En kötü | Yanıt |
|---|---|---|---|
| Özet sayıları (`/stats`) | 468 ms | 573 ms | 1 kB |
| Uyarı listesi (500) (`/alerts`) | 16 ms | 71 ms | 157 kB |
| Zaman çizelgesi, tüm dönem, saatlik (`/timeline`) | 129 ms | 170 ms | 39 kB |
| Zaman çizelgesi, tüm dönem, günlük (`/timeline`) | 102 ms | 119 ms | 2 kB |
| Zaman çizelgesi, bir gün, 5 dakikalık (`/timeline`) | 15 ms | 18 ms | 16 kB |
| Zaman çizelgesi, bir saat, 1 dakikalık (`/timeline`) | 10 ms | 12 ms | 3 kB |
| Zaman çizelgesi, tüm dönem, tek adres (`/timeline`) | 309 ms | 375 ms | 37 kB |
| Zaman çizelgesi, tüm dönem, yalnızca şüpheli (`/timeline`) | 421 ms | 518 ms | 39 kB |
| Olaylar, ilk sayfa (`/events`) | 17 ms | 20 ms | 104 kB |
| Olaylar, dönemin ortasından sayfa (`/events`) | 17 ms | 77 ms | 105 kB |
| Olaylar, en yeni 200 (`/events`) | 16 ms | 18 ms | 108 kB |
| Olaylar, çok görülen adres (`/events`) | 20 ms | 24 ms | 96 kB |
| Olaylar, iki kez görülen adres (`/events`) | 276 ms | 328 ms | 1 kB |
| Olaylar, bir uyarının çevresi (`/events`) | 15 ms | 65 ms | 98 kB |
| Olaylar, bir uyarının kanıtları (`/events`) | 14 ms | 19 ms | 78 kB |
| Olaylar, bir kuralın tüm kanıtları (`/events`) | 33 ms | 39 ms | 102 kB |
| Olaylar, program süzgeci (`/events`) | 16 ms | 63 ms | 95 kB |
| Port görünümü, tarama yapan adres (`/ports`) | 6 ms | 13 ms | 15 kB |

Her istek 15 kez yapıldı. 600 uyarı, 129.678 kaynak adres.

## Yüz bin satır

Log dosyası: 15 MB, 0.6 sn içinde üretildi.

| Adım | Süre | Not |
|---|---|---|
| Yükleme (ayrıştırma + yazma) | 5.4 sn | 18.588 satır/sn; 90.494 ayrıştırıldı, 9.506 tanınmadı |
| Aynı dosyayı yeniden yükleme | 2.2 sn | hepsi kopya, atlandı |
| Kuralların tümü (32), baştan | 2.0 sn | 56 uyarı |
| &nbsp;&nbsp;28 anahtar kelime kuralı, tek geçişte | 0.5 sn | 0 uyarı |
| &nbsp;&nbsp;NET-001 (port_scan) | 0.5 sn | 15 uyarı |
| &nbsp;&nbsp;NET-002 (rare_port) | 0.0 sn | 0 uyarı |
| &nbsp;&nbsp;SSH-001 (threshold) | 0.3 sn | 39 uyarı |
| &nbsp;&nbsp;SSH-002 (sequence) | 0.6 sn | 2 uyarı |
| Canlı takip adımı: 100 yeni satır | 129 ms | yazma 20 ms, kurallar 109 ms; 56 uyarı |
| Veritabanı dosyası | 70 MB | 57.787 farklı kaynak adres |
| En yüksek bellek kullanımı | 111 MB | ölçüm betiğinin tamamı |

| İstek | Ortanca | En kötü | Yanıt |
|---|---|---|---|
| Özet sayıları (`/stats`) | 94 ms | 117 ms | 1 kB |
| Uyarı listesi (500) (`/alerts`) | 5 ms | 45 ms | 18 kB |
| Zaman çizelgesi, tüm dönem, saatlik (`/timeline`) | 19 ms | 25 ms | 38 kB |
| Zaman çizelgesi, tüm dönem, günlük (`/timeline`) | 15 ms | 20 ms | 2 kB |
| Zaman çizelgesi, bir gün, 5 dakikalık (`/timeline`) | 10 ms | 14 ms | 15 kB |
| Zaman çizelgesi, bir saat, 1 dakikalık (`/timeline`) | 7 ms | 9 ms | 3 kB |
| Zaman çizelgesi, tüm dönem, tek adres (`/timeline`) | 36 ms | 47 ms | 32 kB |
| Zaman çizelgesi, tüm dönem, yalnızca şüpheli (`/timeline`) | 45 ms | 63 ms | 37 kB |
| Olaylar, ilk sayfa (`/events`) | 14 ms | 21 ms | 104 kB |
| Olaylar, dönemin ortasından sayfa (`/events`) | 14 ms | 59 ms | 106 kB |
| Olaylar, en yeni 200 (`/events`) | 14 ms | 19 ms | 108 kB |
| Olaylar, çok görülen adres (`/events`) | 18 ms | 21 ms | 96 kB |
| Olaylar, iki kez görülen adres (`/events`) | 35 ms | 38 ms | 1 kB |
| Olaylar, bir uyarının çevresi (`/events`) | 14 ms | 58 ms | 79 kB |
| Olaylar, bir uyarının kanıtları (`/events`) | 13 ms | 16 ms | 75 kB |
| Olaylar, bir kuralın tüm kanıtları (`/events`) | 16 ms | 19 ms | 102 kB |
| Olaylar, program süzgeci (`/events`) | 15 ms | 56 ms | 95 kB |
| Port görünümü, tarama yapan adres (`/ports`) | 5 ms | 11 ms | 14 kB |

Her istek 15 kez yapıldı. 56 uyarı, 57.787 kaynak adres.

## Ne yavaştı, ne yapıldı

İlk ölçüm (aynı büyüklükte, benzer içerikte bir log; o sırada yalnızca beş kural vardı) dört yavaş nokta gösterdi.

| | Önce | Sonra | Ne değişti |
|---|---|---|---|
| Özet sayıları (`/stats`) | 3,3 sn | 0,5 sn | Her satırı okuyan tek sorgu yerine, her biri bir indeksin tek başına yanıtladığı küçük sorgular |
| Zaman çizelgesi, tüm dönem | 0,85 sn | 0,1 sn | Yalnızca zaman süzülmüşse kova kova sayım: her kova için zaman indeksinde iki arama, hiçbir satır okunmadan |
| Olaylar, dönemin ortasından sayfa | 89 ms | 17 ms | İmleç `(zaman, kimlik)` çifti olarak tek karşılaştırmayla veriliyor; arama aralığın başından değil imleçten başlıyor |
| Yeni satırlardan sonra kurallar | 29 sn | 1 sn | Bütün kuralların bütün olaylar üzerinde baştan çalışması yerine, yalnızca yeni satırların ait olduğu grupların (adres, kullanıcı) yeniden hesaplanması |

Sigma kuralları eklendiğinde beşinci bir sorun çıktı: anahtar kelime kuralları veritabanına kelime başına bir `LIKE` soruyordu. Birkaç kelimede sorun değil; 28 kuralın iki yüz kelimesiyle bir milyon satırda 94 saniye. Şimdi satırlar bütün anahtar kelime kuralları için bir kez okunuyor ve her kelime, o logda en seyrek geçen karakteriyle temsil ediliyor: o karakteri içermeyen satır o kelimeyi içeremez. Aynı iş 5 saniye sürüyor.

Bunlar için iki indeks (`(level, ts)` ve `(action, src_ip, ts)`) ve kuralların hangi halleriyle çalıştırıldığını hatırlayan küçük bir tablo eklendi. İndeksler yüklemeyi yüzde on kadar yavaşlattı ve veritabanını 597 MB'tan 705 MB'a çıkardı.

Yeni satırlardan sonra yalnızca etkilenen grupları hesaplamak, sonucun baştan hesaplamayla aynı olmasını gerektirir. Testler bunu, iki örnek logu rastgele büyüklükte parçalar halinde besleyip her adımda iki yolun aynı uyarıları verdiğini karşılaştırarak denetler (`backend/tests/test_alert_keeper.py`).

## Hâlâ yavaş olanlar

- **Yükleme: saniyede on bin satır.** Bir milyon satır bir buçuk dakika sürer. Aynı dosyayı yeniden yüklemek (satırlar ayrıştırılır, kopya oldukları görülür, hiçbir şey yazılmaz) 24 saniye sürdüğüne göre, sürenin dörtte üçü satırların ve altı indeksin yazılmasıdır. Tek çekirdek kullanılır.
- **Çok olayı olan bir adresten gelen her yeni satır.** Bir grubun uyarıları, o grubun ilk olayından başlanarak yeniden hesaplanır. Ölçüm logunda üç adres on altışar bin kez giriş yapıyor; yüz yeni satırın içinde onlardan biri varsa `SSH-002` kırk sekiz bin olayı yeniden okur. Canlı takip adımının bir saniyesinin çoğu budur. Yüz bin satırda aynı adım 0,13 saniyedir.
- **Alan süzgeçli zaman çizelgesi (0,3-0,4 sn).** Kova kova sayım yalnızca zaman süzgeciyle çalışır; adres ya da düzey seçilince her satırın kovası hesaplanır.
- **Az görülen bir adresin olayları (0,3 sn).** Adres süzgeci kaynak ya da hedef adrese bakar; hedef adresin indeksi yoktur, veritabanı zaman indeksini baştan sona yürür. Çok görülen adreste ilk iki yüz satır hemen bulunur.
- **Özet sayıları (0,5 sn).** Çoğu, yüz otuz bin farklı kaynak adresi saymaktır.
- **Kuralları baştan çalıştırmak (24 sn).** Kural dosyaları değiştiğinde ve "Kuralları yeniden yükle" denince olur. Olağan kullanımda (yükleme, canlı takip) yalnızca yeni satırların grupları hesaplanır.

Bir milyon satırın ötesi denenmedi. SQLite tek yazıcıya izin verir: büyük bir yükleme sürerken canlı takip sırasını bekler.
