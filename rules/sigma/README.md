# Sigma'dan alınan kurallar

Bu klasördeki kurallar [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) deposundan alındı. Sigma, tespit kuralları için ortak bir yazım biçimi; SigmaHQ deposu da bu biçimde yazılmış en büyük açık kural koleksiyonu.

- **Sürüm:** deponun 6 Ekim 2026 tarihli hali ([`8a48134`](https://github.com/SigmaHQ/sigma/tree/8a4813404ea3074890e0cda9272d4d1a8b2941d6)).
- **Lisans:** kurallar [Detection Rule License 1.1](LICENSE.Detection.Rules.md) ile dağıtılır. Lisans, kuralı başkasına aktaranın yazarı, özgün kurala bağlantıyı ve lisansı kuralla birlikte tutmasını ister; her dosyada `author`, `source` ve `license` alanları bunun için vardır. Arayüz de bir uyarının yanında kuralın yazarını gösterir.
- **Bu deponun kendi lisansı (MIT) bu klasör için geçerli değildir.**

## Hangi kurallar alındı

Bu araç sunucu loglarının satırlarını okur: `sshd`, `sudo`, `cron` ve diğer programların syslog satırları ile güvenlik duvarının paket kayıtları. Sigma kurallarından yalnızca böyle satırlarda **metin arayanlar** burada çalışabilir. Depodaki kuralların büyük çoğunluğu ise başka kayıtlar ister: süreç başlatma kayıtları (`process_creation`), `auditd`, dosya olayları, web sunucusu ve vekil sunucu kayıtları. Bu araç onları toplamadığı için o kurallar alınmadı.

| Kural | Önem | Yazar | Dosya |
|---|---|---|---|
| [Buffer Overflow Attempts](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_buffer_overflows.yml) | yüksek | Florian Roth (Nextron Systems) | [`lnx_buffer_overflows.yaml`](lnx_buffer_overflows.yaml) |
| [Cleartext Protocol Usage](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/network/firewall/net_firewall_cleartext_protocols.yml) (kapalı) | düşük | Alexandr Yampolskyi, SOC Prime, Tim Shelton | [`net_firewall_cleartext_protocols.yaml`](net_firewall_cleartext_protocols.yaml) |
| [Code Injection by ld.so Preload](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_ldso_preload_injection.yml) | yüksek | Christian Burkard (Nextron Systems) | [`lnx_ldso_preload_injection.yaml`](lnx_ldso_preload_injection.yaml) |
| [Commands to Clear or Remove the Syslog - Builtin](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_clear_syslog.yml) | yüksek | Max Altgelt (Nextron Systems) | [`lnx_clear_syslog.yaml`](lnx_clear_syslog.yaml) |
| [Disabling Security Tools - Builtin](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/syslog/lnx_syslog_security_tools_disabling_syslog.yml) | orta | Ömer Günal, Alejandro Ortuno, oscd.community | [`lnx_syslog_security_tools_disabling_syslog.yaml`](lnx_syslog_security_tools_disabling_syslog.yaml) |
| [Equation Group Indicators](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_apt_equationgroup_lnx.yml) | yüksek | Florian Roth (Nextron Systems) | [`lnx_apt_equationgroup_lnx.yaml`](lnx_apt_equationgroup_lnx.yaml) |
| [Guacamole Two Users Sharing Session Anomaly](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/guacamole/lnx_guacamole_susp_guacamole.yml) | yüksek | Florian Roth (Nextron Systems) | [`lnx_guacamole_susp_guacamole.yaml`](lnx_guacamole_susp_guacamole.yaml) |
| [JexBoss Command Sequence](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_susp_jexboss.yml) | yüksek | Florian Roth (Nextron Systems) | [`lnx_susp_jexboss.yaml`](lnx_susp_jexboss.yaml) |
| [Linux Command History Tampering](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_shell_clear_cmd_history.yml) | yüksek | Patrick Bareiss | [`lnx_shell_clear_cmd_history.yaml`](lnx_shell_clear_cmd_history.yaml) |
| [Modifying Crontab](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/cron/lnx_cron_crontab_file_modification.yml) | orta | Pawel Mazur | [`lnx_cron_crontab_file_modification.yaml`](lnx_cron_crontab_file_modification.yaml) |
| [Potential CVE-2023-2283 Exploitation](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules-emerging-threats/2023/Exploits/CVE-2023-2283/lnx_sshd_exploit_cve_2023_2283_libssh_authentication_bypass.yml) | orta | Florian Roth (Nextron Systems) | [`lnx_sshd_exploit_cve_2023_2283_libssh_authentication_bypass.yaml`](lnx_sshd_exploit_cve_2023_2283_libssh_authentication_bypass.yaml) |
| [Potential Nimbuspwn Exploit CVE-2022-29799 and CVE-2022-27800](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules-emerging-threats/2022/Exploits/CVE-2022-29799/lnx_exploit_cve_2022_27999_cve_2022_27800.yml) | yüksek | Bhabesh Raj | [`lnx_exploit_cve_2022_27999_cve_2022_27800.yaml`](lnx_exploit_cve_2022_27999_cve_2022_27800.yaml) |
| [Potential Suspicious BPF Activity - Linux](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_potential_susp_ebpf_activity.yml) | yüksek | Red Canary (idea), Nasreddine Bencherchali | [`lnx_potential_susp_ebpf_activity.yaml`](lnx_potential_susp_ebpf_activity.yaml) |
| [Privileged User Has Been Created](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_privileged_user_creation.yml) | yüksek | Pawel Mazur | [`lnx_privileged_user_creation.yaml`](lnx_privileged_user_creation.yaml) |
| [PwnKit Local Privilege Escalation](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules-emerging-threats/2021/Exploits/CVE-2021-4034/lnx_auth_exploit_cve_2021_4034_pwnkit_lpe.yml) | yüksek | Sreeman | [`lnx_auth_exploit_cve_2021_4034_pwnkit_lpe.yaml`](lnx_auth_exploit_cve_2021_4034_pwnkit_lpe.yaml) |
| [Relevant ClamAV Message](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/clamav/lnx_clamav_relevant_message.yml) | yüksek | Florian Roth (Nextron Systems) | [`lnx_clamav_relevant_message.yaml`](lnx_clamav_relevant_message.yaml) |
| [Remote File Copy](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_file_copy.yml) | düşük | Ömer Günal | [`lnx_file_copy.yaml`](lnx_file_copy.yaml) |
| [Shellshock Expression](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_shellshock.yml) | yüksek | Florian Roth (Nextron Systems) | [`lnx_shellshock.yaml`](lnx_shellshock.yaml) |
| [SSHD Error Message CVE-2018-15473](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules-emerging-threats/2018/Exploits/CVE-2018-15473/lnx_sshd_exploit_cve_2018_15473.yml) | orta | Florian Roth (Nextron Systems) | [`lnx_sshd_exploit_cve_2018_15473.yaml`](lnx_sshd_exploit_cve_2018_15473.yaml) |
| [Sudo Privilege Escalation CVE-2019-14287 - Builtin](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules-emerging-threats/2019/Exploits/CVE-2019-14287/lnx_sudo_exploit_cve_2019_14287.yml) | kritik | Florian Roth (Nextron Systems) | [`lnx_sudo_exploit_cve_2019_14287.yaml`](lnx_sudo_exploit_cve_2019_14287.yaml) |
| [Suspicious Activity in Shell Commands](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_shell_susp_commands.yml) | yüksek | Florian Roth (Nextron Systems) | [`lnx_shell_susp_commands.yaml`](lnx_shell_susp_commands.yaml) |
| [Suspicious Log Entries](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_shell_susp_log_entries.yml) | orta | Florian Roth (Nextron Systems) | [`lnx_shell_susp_log_entries.yaml`](lnx_shell_susp_log_entries.yaml) |
| [Suspicious Named Error](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/syslog/lnx_syslog_susp_named.yml) | yüksek | Florian Roth (Nextron Systems) | [`lnx_syslog_susp_named.yaml`](lnx_syslog_susp_named.yaml) |
| [Suspicious OpenSSH Daemon Error](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml) | orta | Florian Roth (Nextron Systems) | [`lnx_sshd_susp_ssh.yaml`](lnx_sshd_susp_ssh.yaml) |
| [Suspicious Reverse Shell Command Line](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_shell_susp_rev_shells.yml) | yüksek | Florian Roth (Nextron Systems) | [`lnx_shell_susp_rev_shells.yaml`](lnx_shell_susp_rev_shells.yaml) |
| [Suspicious Use of /dev/tcp](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_susp_dev_tcp.yml) | orta | frack113 | [`lnx_susp_dev_tcp.yaml`](lnx_susp_dev_tcp.yaml) |
| [Suspicious VSFTPD Error Messages](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml) | orta | Florian Roth (Nextron Systems) | [`lnx_vsftpd_susp_error_messages.yaml`](lnx_vsftpd_susp_error_messages.yaml) |
| [Symlink Etc Passwd](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/linux/builtin/lnx_symlink_etc_passwd.yml) | yüksek | Florian Roth (Nextron Systems) | [`lnx_symlink_etc_passwd.yaml`](lnx_symlink_etc_passwd.yaml) |

Alınmayan ama konuya yakın duran üç kural:

- **Equation Group C2 Communication** (güvenlik duvarı): 2017'de yayımlanmış iki IP adresini arar. Adres listesiyle karşılaştıran bir kural türü yok; göstergeler de eski.
- **Space After Filename** ve **Brute Force**: Sigma'nın kendisi kullanımdan kaldırdı. Kaba kuvvet denemelerini bu deponun kendi kuralı `SSH-001` yakalar.

## Nasıl çevrildi

`lnx_` ile başlayan dosyaları `backend/app/sigma.py` yazdı; elle değiştirilmediler:

```bash
cd backend
python -m app.sigma --root /sigma/deposunun/kopyasi \
    --ref 8a4813404ea3074890e0cda9272d4d1a8b2941d6 --out ../rules/sigma \
    rules/linux/builtin rules-emerging-threats
```

Komut, çeviremediği her kuralın nedenini de söyler (`--reasons` ile tek tek). Sigma'nın yeni bir sürümüyle yeniden çalıştırıldığında dosyaların üzerine yazar.

| Sigma | Burada |
|---|---|
| `title`, `description` | `name`, `description` (çevrilmeden, İngilizce bırakıldı) |
| `id` | `id`: `SIGMA-` ve Sigma kimliğinin ilk sekiz hanesi |
| `level` | `severity` (`informational` → `low`) |
| `logsource.service` | `sshd`, `sudo` ve `cron` için `match.service`; diğerlerinde kural her satıra bakar |
| `detection` içindeki metin listeleri | `keywords`; `and` ile bağlanan ikinci liste ve `\|all` → `require`; `and not` → `exclude` |
| `sudo` logunda alanlar (`USER`) | sudo'nun yazdığı biçimiyle metin: `USER=...` |
| `falsepositives` | `false_positives` ("Unknown" dışındakiler) |
| `author`, `references`, `tags` | aynı adla |

Sigma'da anahtar kelime satırın tamamında aranır. Burada kurallar programın adına ve mesajına bakar (`sudo: bob : TTY=pts/0 ; ...`), zaman damgasına ve makine adına bakmaz.

`net_firewall_cleartext_protocols.yaml` elle uyarlandı: özgün kural güvenlik duvarı kayıtlarının alanlarına bakar, burada aynı koşul `rare_port` türüyle yazıldı. **Kapalı gelir**, çünkü listesindeki 80 ve 8080 portları bir web sunucusunda olağan trafiktir.

## Bir kuralı kapatmak ya da değiştirmek

Dosyaya `enabled: false` ekle ve arayüzden kuralları yeniden yükle. Çevirme komutu yeniden çalıştırılırsa bu değişiklik kaybolur; kalıcı olması için kuralı `rules/` altına kendi kimliğinle kopyalayıp buradakini kapat.

Yanlış alarmlar için: bu kurallar genel yazılmıştır. `Remote File Copy` her `scp` ve `rsync` komutunda, `Modifying Crontab` her `crontab -e` sonrasında, `Suspicious Log Entries` bir arayüz dinleme kipine geçtiğinde (Docker bunu konteyner başlatırken yapar) uyarı verir. Her kuralın bilinen zararsız nedenleri dosyasındaki `false_positives` alanında yazar.
