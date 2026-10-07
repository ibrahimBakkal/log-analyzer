# Tespit ölçümü: kurallar neyi yakalıyor, neyi kaçırıyor, neye yanlış alarm veriyor

Örnek loglardaki sekiz uyarının hepsi yerinde, ama o loglar kuralları göstermek için yazıldı; kuralların sınırını göstermezler. Bu ölçüm sınırı arar: her kaynak adresin ne yaptığı bilinen bir log üretir, kuralları çalıştırır ve her adresi uyarıların arasında arar.

```bash
cd backend
python ../samples/measure.py            # bu sayfadaki tabloları yazdırır
python ../samples/measure.py --seed 7   # aynı roller, başka zamanlar ve portlar
```

## Yöntem

Logdaki her adres tek bir rol oynar: belli türde ve belli yoğunlukta bir saldırı, ya da saldırıya benzeyen zararsız bir davranış. Roller bilindiği için her uyarı ya doğrudur ya yanlış, uyarı almayan her adres de ya doğru bırakılmıştır ya kaçırılmıştır.

Roller kuralların eşiklerinin iki yanına bilerek yerleştirildi: 14 portluk tarama ile 15 portluk, dört yanlış parolanın ardından giriş ile beş. Bu yüzden aşağıdaki genel oranlar tek başına bir şey söylemez; hangi role kaç adres verildiğine bağlıdır. Anlamlı olan, her kuralın nerede görmeyi bıraktığıdır.

Ölçülen kurallar depodaki haliyle `rules/` klasörüdür: beş kural ve Sigma'dan alınan yirmi yedi etkin kural.

## Sonuç

33.093 satır, 1.174 kaynak adres, 7 gün. Tohum: 1.

| | Adres | Uyarı aldı | Almadı |
|---|---|---|---|
| Saldırı | 294 | 143 (yakalandı) | 151 (kaçırıldı) |
| Zararsız | 880 | 35 (yanlış alarm) | 845 (doğru) |

Yakalama oranı (recall): %49. Uyarı alan adreslerin saldırgan olma oranı (precision): %80.

### Saldırılar

| Davranış | Ayrıntı | Adres | Uyarı alan | Uyaran kurallar |
|---|---|---|---|---|
| Hızlı kaba kuvvet | 0,2-2 sn arayla 20-150 deneme | 40 | 40 | SSH-001 |
| Aralıklı kaba kuvvet | 5 sn arayla 40 deneme | 10 | 10 | SSH-001 |
| Aralıklı kaba kuvvet | 10 sn arayla 40 deneme | 10 | 10 | SSH-001 |
| Aralıklı kaba kuvvet | 14 sn arayla 40 deneme | 10 | 10 | SSH-001 |
| Aralıklı kaba kuvvet | 16 sn arayla 40 deneme | 10 | 0 | - |
| Aralıklı kaba kuvvet | 30 sn arayla 40 deneme | 10 | 0 | - |
| Aralıklı kaba kuvvet | 120 sn arayla 40 deneme | 10 | 0 | - |
| Aralıklı kaba kuvvet | 1500 sn arayla 40 deneme | 10 | 0 | - |
| Kullanıcı adı taraması | her adla bir parola denemesi | 15 | 15 | SSH-001 |
| Kullanıcı adı taraması | parola denemeden bağlantıyı kesiyor | 15 | 0 | - |
| Tahmin edilen parola | 1 başarısız denemeden sonra giriş | 8 | 0 | - |
| Tahmin edilen parola | 3 başarısız denemeden sonra giriş | 8 | 0 | - |
| Tahmin edilen parola | 4 başarısız denemeden sonra giriş | 8 | 0 | - |
| Tahmin edilen parola | 5 başarısız denemeden sonra giriş | 8 | 8 | SSH-001, SSH-002 |
| Tahmin edilen parola | 8 başarısız denemeden sonra giriş | 8 | 8 | SSH-001, SSH-002 |
| Tahmin edilen parola | 25 başarısız denemeden sonra giriş | 8 | 8 | SSH-001, SSH-002 |
| Port taraması | 5 port, 0.3 sn arayla | 4 | 0 | - |
| Port taraması | 5 port, 3 sn arayla | 4 | 0 | - |
| Port taraması | 5 port, 5 sn arayla | 4 | 0 | - |
| Port taraması | 5 port, 30 sn arayla | 4 | 0 | - |
| Port taraması | 10 port, 0.3 sn arayla | 4 | 0 | - |
| Port taraması | 10 port, 3 sn arayla | 4 | 0 | - |
| Port taraması | 10 port, 5 sn arayla | 4 | 0 | - |
| Port taraması | 10 port, 30 sn arayla | 4 | 0 | - |
| Port taraması | 14 port, 0.3 sn arayla | 4 | 0 | - |
| Port taraması | 14 port, 3 sn arayla | 4 | 0 | - |
| Port taraması | 14 port, 5 sn arayla | 4 | 0 | - |
| Port taraması | 14 port, 30 sn arayla | 4 | 0 | - |
| Port taraması | 15 port, 0.3 sn arayla | 4 | 4 | NET-001 |
| Port taraması | 15 port, 3 sn arayla | 4 | 4 | NET-001 |
| Port taraması | 15 port, 5 sn arayla | 4 | 0 | - |
| Port taraması | 15 port, 30 sn arayla | 4 | 0 | - |
| Port taraması | 30 port, 0.3 sn arayla | 4 | 4 | NET-001 |
| Port taraması | 30 port, 3 sn arayla | 4 | 4 | NET-001 |
| Port taraması | 30 port, 5 sn arayla | 4 | 0 | - |
| Port taraması | 30 port, 30 sn arayla | 4 | 0 | - |
| Port taraması | 100 port, 0.3 sn arayla | 4 | 4 | NET-001 |
| Port taraması | 100 port, 3 sn arayla | 4 | 4 | NET-001 |
| Port taraması | 100 port, 5 sn arayla | 4 | 0 | - |
| Port taraması | 100 port, 30 sn arayla | 4 | 0 | - |
| Açık kalmış RDP portuna bağlantı | 1-3 bağlantı | 10 | 10 | NET-002 |

### Zararsız davranışlar

| Davranış | Ayrıntı | Adres | Uyarı alan | Uyaran kurallar |
|---|---|---|---|---|
| Parolasını yanlış yazan kullanıcı | 1 yanlış, sonra doğru | 10 | 0 | - |
| Parolasını yanlış yazan kullanıcı | 2 yanlış, sonra doğru | 10 | 0 | - |
| Parolasını yanlış yazan kullanıcı | 4 yanlış, sonra doğru | 10 | 0 | - |
| Parolasını yanlış yazan kullanıcı | 5 yanlış, sonra doğru | 10 | 10 | SSH-001, SSH-002 |
| Parolasını yanlış yazan kullanıcı | 7 yanlış, sonra doğru | 10 | 10 | SSH-001, SSH-002 |
| Tek adresten çıkan ofis | 3 kişi birer kez yanlış yazıyor | 5 | 0 | - |
| Tek adresten çıkan ofis | 4 kişi birer kez yanlış yazıyor | 5 | 0 | - |
| Tek adresten çıkan ofis | 5 kişi birer kez yanlış yazıyor | 5 | 5 | SSH-001, SSH-002 |
| Tek adresten çıkan ofis | 8 kişi birer kez yanlış yazıyor | 5 | 5 | SSH-001, SSH-002 |
| İzleme sunucusu | 10 dakikada bir 8 port | 5 | 0 | - |
| İzleme sunucusu | 10 dakikada bir 20 port | 5 | 5 | NET-001 |
| İnternet gürültüsü | saatler arayla 1-3 deneme | 400 | 0 | - |
| Site ziyaretçisi | 80 ve 443'e birkaç bağlantı | 400 | 0 | - |

### Kural başına uyarı sayısı

| Kural | Uyarı |
|---|---|
| NET-001 | 744 |
| NET-002 | 10 |
| SSH-001 | 139 |
| SSH-002 | 54 |

Sigma'dan alınan kurallar bu logda hiç uyarı üretmedi: aradıkları komutlar ve hata mesajları logda yok, zararsız satırların hiçbiri de onlara takılmadı.

## Ne öğrenildi

### Kaçırılanlar

1. **Eşiğin hemen altında kalan saldırı görünmez.** `SSH-001` bir dakikada beş başarısız giriş ister; denemelerini 15 saniyeden seyrek yapan saldırgan 40 denemeyle de, 400 denemeyle de uyarı üretmez. `NET-001` bir dakikada 15 farklı port ister; portlar arasında 4,3 saniyeden fazla bekleyen tarama 100 port denese de geçer. Yavaş saldırı için uzun pencereli ikinci bir kural gerekir (aşağıda).
2. **Parola denemeyen kullanıcı adı taraması `SSH-001`'e görünmez.** Kural yalnızca `auth_fail` olaylarını sayar. Saldırgan her adı deneyip parola göndermeden bağlantıyı keserse log yalnızca `Invalid user ...` satırları içerir (`invalid_user`), kural da bunları saymaz. Ölçümden önce bilinmeyen bir boşluktu.
3. **Az denemeyle bulunan parola ayırt edilemez.** Dört ya da daha az yanlış denemeden sonra giren saldırgan, parolasını yanlış yazan kullanıcıyla aynı satırları üretir. `SSH-002`'nin eşiğini düşürmek ikisini birlikte yakalar. Bunu ayırmak için logda olmayan bilgi gerekir: adresin o kullanıcı için yeni olup olmadığı, saat, ülke.
4. **Az portlu tarama.** 15'ten az port deneyen tarama `NET-001`'e takılmaz. Hedefli bir tarama (yalnızca 22, 3389, 5900) böyledir; onu, portlar güvenlik duvarından geçiyorsa `NET-002` yakalar.

### Yanlış alarmlar

5. **Kurallar kaynağa bakar, kişiye bakmaz.** Parolasını beş kez yanlış yazıp sonra giren kullanıcı ile aynı çıkış adresini paylaşan ve o sabah birer kez yanlış yazan beş kişi, `SSH-001` ve `SSH-002` için kaba kuvvetin ardından gelen girişle aynıdır. Bir sıralı kural olayları tek bir alana göre gruplar; "aynı adres **ve** aynı kullanıcı" diyemez.
6. **Düzenli tarama yapan kendi makinen her turda uyarı üretir.** Yirmi portu on dakikada bir yoklayan beş izleme sunucusu, `NET-001` uyarılarının 744'ünden 720'sini üretti. Turlar arası süre (600 sn) kuralın `cooldown_seconds` değerinden (300 sn) uzun olduğu için her tur yeni bir uyarıdır.

### Doğru kalanlar

7. Saatler arayla bir iki deneme yapan 400 adres ve 400 site ziyaretçisi hiç uyarı almadı. Bir sunucunun logunun çoğu budur; kuralların bu gürültüye uyarı üretmemesi, uyarı listesinin okunabilir kalmasının koşuludur.

## Ne yapılabilir

Aşağıdakiler kurulumdan kuruluma değişir, bu yüzden depodaki kurallara eklenmediler. Yazım kuralları için [Kural nasıl yazılır](kural-yazma.md) belgesine bak.

Kendi makinelerini ve ofisinin çıkış adresini kuralın dışında tut (5 ve 6):

```yaml
# rules/NET-001.yaml ve rules/SSH-001.yaml içine
allowlist:
  - 192.0.2.50        # izleme sunucusu
  - 192.0.2.0/24      # ofis
```

Yavaş kaba kuvvet için uzun pencereli ikinci bir kural (1). Altı saatte 20 deneme, saatler arayla bir iki deneme yapan gürültüyü dışarıda bırakır:

```yaml
id: SSH-003
name: Yavaş SSH kaba kuvvet denemesi
type: threshold
severity: medium
match:
  action: auth_fail
group_by: src_ip
threshold: 20
window_seconds: 21600
cooldown_seconds: 3600
```

Parola denemeyen kullanıcı adı taraması (2):

```yaml
id: SSH-004
name: Kullanıcı adı taraması
type: threshold
severity: medium
match:
  action: invalid_user
group_by: src_ip
threshold: 10
window_seconds: 120
```

Bu iki kural eklenip ölçüm yeniden çalıştırıldığında yakalanan saldırgan sayısı 294'te 143'ten 188'e çıktı, yanlış alarm 35'te kaldı. 16, 30 ve 120 saniye arayla deneyenler ile parola denemeyen tarayıcılar artık yakalanıyor; 25 dakikada bir deneyen saldırgan (altı saatte 15 deneme) hâlâ görünmüyor. Bedeli: hızlı saldırganların her biri için `SSH-001`'in yanında ikinci bir uyarı.

Kendi kurulumunda denemek için dosyaları `rules/` altına koyup `python ../samples/measure.py` komutunu yeniden çalıştırmak yeter.

## Ölçümün sınırı

Log sentetiktir ve rolleri bu deponun yazarı seçti: kuralların hiç düşünülmemiş bir saldırıya ne yaptığını göstermez, yalnızca düşünülenlerin sınırını gösterir. Gerçek bir sunucunun logunda oranlar başka çıkar. Tabloların sayıları `backend/tests/test_measure.py` ile sabitlendi; kurallar ya da ölçüm değişirse test bu sayfanın güncellenmesi gerektiğini söyler.
