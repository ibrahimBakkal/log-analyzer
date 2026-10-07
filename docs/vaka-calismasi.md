# Vaka çalışması: 10 Eylül, 02:31

Örnek loglar bir sunucunun iki gününü anlatır. Bu belge, o iki günün en ciddi olayını araçla baştan sona izler: uyarıdan log satırına, oradan "ne oldu, ne zaman, kim yaptı, sonra ne oldu" sorularının yanıtına. Amaç, aracın bir incelemede hangi soruyu hangi görünümle yanıtladığını göstermektir.

Adımları kendin izlemek için `docker compose up --build` ile aç (`http://localhost:8080`) ya da [sunucusuz demoyu](../README.md#demo-sunucusuz-arayüz) kullan.

## 1. Nereden başlanır

![Özet sayfası](img/ozet.png)

Özet sayfası iki günü tek ekranda gösterir: 1.838 satır, 303 kaynak adres, sekiz uyarı. Zaman çizelgesinde turuncu, tek başına şüpheli sayılan satırlardır (başarısız giriş, reddedilen sudo, engellenen paket); çizelgenin üst kenarındaki işaretler uyarıların zamanıdır.

Sekiz uyarının yedisi bir şeyin **denendiğini** söyler. Biri bir şeyin **başarıldığını** söyler ve tek kritik olan odur:

> **SSH-002**: 203.0.113.99 adresi başarısız denemelerin ardından giriş yaptı (64 sn, 25 satır)

İnceleme buradan başlar.

## 2. Ne oldu

Uyarıya tıklamak İnceleme sayfasını o uyarının zamanına götürür: çizelge 02:30:40-02:33:45 aralığına yakınlaşır, log tablosu o aralıktaki bütün satırları gösterir, uyarının kanıtı olan satırlar kenar çizgisi ve işaretlenmiş adresle ayrılır.

![Uyarının zamanı: çizelge, port görünümü ve kanıt satırları](img/inceleme.png)

Kanıt satırları sırasıyla okunduğunda:

| Zaman | Ne oldu |
|---|---|
| 02:31:40 - 02:32:33 | `bob` hesabı için 24 başarısız parola, 53 saniyede. Bir insan bu hızda yazamaz |
| 02:32:44 | `Accepted password for bob from 203.0.113.99`. Parola bulundu |

Aynı 24 başarısız giriş `SSH-001` (kaba kuvvet) uyarısının da kanıtıdır; satırların sağındaki iki etiket bunu gösterir. İki kural aynı olaya iki açıdan bakar: biri "çok deneme var" der, öbürü "ve sonunda biri tuttu".

Kanıt olmayan satırlar da tablodadır ve bağlamı verir: güvenlik duvarının bu adresten 22 numaralı porta geçirdiği bağlantılar, `sshd`'nin her birkaç denemede bağlantıyı kapatması. "Yalnızca kanıt satırları" kutusu bunları gizler.

## 3. Bu adres tanıdık mı

Bir kullanıcının parolasını yanlış yazıp sonra doğru yazması olağandır. Bunu ondan ayıran iki şey var, ikisi de araçta görülür.

**Sayı ve hız.** `bob` bir gün önce, 9 Eylül 10:34'te kendi adresinden (`192.0.2.11`) bir kez yanlış yazıp girmişti; kural buna uyarı vermedi, çünkü beş başarısız deneme ister. Burada 24 tane var.

**Adres.** İnceleme sayfasında eylem süzgeci "başarılı giriş" yapıldığında iki günün 13 girişi listelenir. On ikisi `192.0.2.0/24` içinden, bilinen üç kullanıcının hep aynı adreslerinden gelir. Biri gelmez:

| Zaman | Kullanıcı | Adres |
|---|---|---|
| 9 Eyl 10:34 | bob | 192.0.2.11 |
| **10 Eyl 02:32** | **bob** | **203.0.113.99** |
| 10 Eyl 10:39 | bob | 192.0.2.11 |

Gece 02:32'de, `bob`'un hiç kullanmadığı bir adresten, parola kaba kuvvetle bulunarak yapılmış bir giriş.

## 4. İçeri girdikten sonra ne yaptı

Uyarının aralığını birkaç dakika ileri uzatmak (çizelgede sürükleyerek ya da bitiş zamanını değiştirerek) oturumun tamamını gösterir:

| Zaman | Satır | Anlamı |
|---|---|---|
| 02:32:44 | `session opened for user bob` | Oturum açıldı |
| 02:34:08 | `bob : user NOT in sudoers ; ... COMMAND=/usr/bin/cat /etc/shadow` | Parola özetlerini okumayı denedi; sudo reddetti |
| 02:36:28 | `bob : user NOT in sudoers ; ... COMMAND=/usr/bin/su -` | root olmayı denedi; sudo reddetti |
| 02:37:18 | `Disconnected from user bob 203.0.113.99` | Oturum kapandı |

İlk komut üçüncü bir uyarının kanıtıdır: `KW-001` (sudo komutunda hassas dosya), satırda `/etc/shadow` işaretlenmiş olarak. İkincisi hiçbir kuralın kanıtı değildir, ama tabloda turuncu noktayla (reddedilen sudo) durur.

sudo satırlarında kaynak adres yoktur; bu yüzden `KW-001` uyarısı adrese değil kullanıcıya göre gruplanır ve bu iki satır adres süzgeciyle değil zaman aralığıyla bulunur. Oturumun `203.0.113.99` adresine ait olduğunu aradaki satırlar bağlar: giriş 02:32:44'te o adresten, çıkış 02:37:18'de o adresten, arada `bob` için başka giriş yok.

Dört buçuk dakikalık oturumda saldırgan yetki yükseltmeyi iki kez denedi ve ikisinde de reddedildi. `bob` sudo yetkisi olan bir hesap olsaydı sonuç başka olurdu.

## 5. Başka ne yaptı

IP süzgecine `203.0.113.99` yazıp zaman aralığını kaldırmak, bu adresin iki gündeki bütün izini verir: 45 satır, hepsi 02:31 ile 02:37 arasında. Port görünümü güvenlik duvarının ne gördüğünü ekler: dokuz bağlantı, hepsi 22 numaralı porta, hepsi geçirilmiş. Tarama yok, başka porta deneme yok: adres doğrudan SSH'a geldi ve yalnızca `bob` hesabını denedi. Hesap adını önceden biliyordu.

Öbür uyarılarla bağı var mı? Aynı gün içinde iki başka adres de kaba kuvvet denedi (`203.0.113.45` iki dalga halinde, `198.51.100.23` otuz farklı kullanıcı adıyla), ama onlar `root` ve var olmayan hesapları denedi ve hiçbiri giremedi. Zamanları ve hedefleri farklı; logda bunları birbirine bağlayan bir şey yok.

## 6. Sonuç

| Soru | Yanıt | Nereden |
|---|---|---|
| Ne oldu? | `bob` hesabının parolası kaba kuvvetle bulundu ve hesaba girildi | `SSH-002` uyarısı ve kanıt satırları |
| Ne zaman? | 10 Eylül 02:31:40 - 02:37:18 UTC | Zaman çizelgesi, satır zamanları |
| Kim? | `203.0.113.99`; hesabın olağan adresi değil | Başarılı girişlerin listesi |
| Ne yaptı? | `/etc/shadow` okumayı ve root olmayı denedi; ikisi de reddedildi | Oturum aralığındaki sudo satırları, `KW-001` |
| Başka? | Yalnızca 22 numaralı port, yalnızca bu hesap | Adres süzgeci, port görünümü |

Yapılacaklar aracın işi değildir ama logdan çıkar: `bob`'un parolası değiştirilmeli, oturumun açık kaldığı dört buçuk dakikada hesabın dosyalarına ne olduğuna bakılmalı (sudo dışındaki komutlar bu loglarda görünmez), SSH'ta parola ile giriş kapatılıp anahtar zorunlu kılınmalı.

## Aynı logdaki iki küçük olay

**Port taraması, 9 Eylül 05:20.** `NET-001` uyarısına tıklayınca port görünümü taramanın şeklini gösterir: 39 saniyede 120 farklı porta birer paket. Düşey eksen hedef port olduğu için tarama, dar bir zaman aralığına yayılmış bir işaret bulutudur. 117 paket engellenmiş (çarpı), üçü geçirilmiş (nokta): tarayan, sunucunun açık üç portunu (22, 80, 443) öğrendi.

![Port taraması: her paket bir işaret](img/port-taramasi.png)

**Açık kalmış uzak masaüstü portu, 10 Eylül 13:05.** `NET-002`, güvenlik duvarının `203.0.113.77` adresinden 3389 numaralı porta üç bağlantı **geçirdiğini** söyler. Buradaki bulgu saldırı değil, yapılandırmadır: internete açık bir Linux sunucusunda RDP portuna izin veren bir kural unutulmuş.

## Uyarı vermeyen şey

Özet sayfasındaki "en çok başarısız giriş denemesi yapan adresler" tablosunun üçüncü satırı hiçbir uyarıda geçmez: `198.51.100.77`, 29 başarısız giriş. Adrese tıklayınca nedeni görünür: denemeler 9 Eylül 10:00 ile 21:48 arasına yayılmış, yirmi otuz dakikada bir. `SSH-001` bir dakikada beş deneme ister; bu saldırgan eşiğin çok altında kalır.

Kural onu görmez, tablo görür. Kuralların neyi kaçırdığı ve bunun için ne yapılabileceği ayrıca ölçüldü: [Tespit ölçümü](tespit-olcumu.md).
