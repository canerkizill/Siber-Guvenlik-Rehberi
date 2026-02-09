# 🛡️ Siber Güvenlik : Sıfırdan İleriye
  Bir siber güvenlikçinin görevi, sadece sistemlere sızmak veya onları korumak değil; bu sistemlerin nasıl oluşturulduğunu anlamak ve bu sistemlerin çalışma prensiplerini en iyi şekilde sürdürmektir. Bu repoda bir siber güvenlik araştırmacısının sıfırdan uzmanlığa uzanan yolculuğundaki tüm teknik adımları ve uygulama notları bulunacaktır.

## Siber Güvenliğin Temelleri
Siber güvenlik temel olarak dört ana disiplini kapsar. Bu alanlarda uzmanlaşmadan ileri seviye saldırı/savunma yapmak düşünülemez. İşte dört temel disiplin:

##### 1.Hacking 🛡️
Güvenliğin kalbi olan CIA Triad prensiplerini ve saldırı metodolojilerini kapsar.

-Keşif ve Tarama: Hedef sistem hakkında bilgi toplama.

-Zafiyet Analizi: Zayıf noktaların tespiti.

-Sömürü: Tespit edilen açıkların kullanılması.

-Raporlama: Bulguların etik çerçevede sunulması.


##### 2.Networking 🌐
Ağ bilgisi, bir siber güvenlikçi adayının görebilme yeteneğidir. Paketlerin yapısını bilmek, trafiğe müdahale etmenin ilk şartıdır.

-OSI Modeli & TCP/IP : Verinin katmanlar arası yolculuğu.

-Protokol Analizi : HTTP, DNS, SMB, FTP ve daha fazlası.

-Araçlar : Wireshark ile paket analizi ve Nmap ile ağ topolojisi.


##### 3.Operating Systems 🐧
Güvenlik, yetki yönetiminde başlar. Sistemlerin iç yapısını bilmek, yetki yükseltme mantığını kavramayı sağlar.

-Linux : Dosya sistemleri, kernel yapısı, Bash scripting ve terminal hakimiyeti.

-Windows : Active Directory, Registry kayıtları ve PowerShell kullanımı.

##### 4.Coding & Automation 🐍
Kodlama, bir siber güvenlikçinin en önemli yardımcılarından biridir. Hazır araçların bittiği yerde kendi çözümünü üretmek için programlama bilgisi gereklidir.

-Programlama Dilleri : Ağ tarayıcıları, brute-force scriptleri ve otomasyon araçları. Örneğin Python(vb.)

-Algoritmik Düşünce : Saldırı vektörlerini koda dökme ve savunma scriptleri yazma.

### Ekstralar :
##### Hardware Hacking & IoT 🔌

Siber güvenlik sadece yazılımla sınırlı değildir. Sanal dünyanın fiziksel dünya ile buluştuğu nokta, siber güvenliğin önemli alanlarından biridir.

-Gömülü Sistemler: Mikrodenetleyicilerin çalışma mantığı ve sensör etkileşimi.

-Protokol Analizi: UART, I2C ve SPI gibi donanım haberleşme dilleri üzerinden veri elde etme.

-Fiziksel Güvenlik: BadUSB saldırıları, RFID/NFC klonlama ve devre kartı analizi.

-IoT Güvenliği: Akıllı cihazların ekosistemindeki zayıflıkların tespiti.


##### Red Team, Blue Team ve Purple Team ⚔️

Bu bölüm, saldırı ve savunma stratejilerinin disiplinlerdir.

🔴 Red Team
Saldırgan bir bakış açısıyla sistemlerin direncini ölçer. Sadece zafiyet bulmakla kalmaz, bu zafiyetlerin gerçek bir saldırıda nasıl zincirlenebileceğini simüle eder.

-Adversary Emulation: Gerçek dünya tehdit aktörlerinin tekniklerini taklit etme.

-Social Engineering: İnsan faktörünü manipüle ederek sisteme sızma yolları.

-Metodoloji: Cyber Kill Chain ve MITRE ATT&CK matrisi üzerinden saldırı planlama.

🔵 Blue Team
Sürekli izleme, analiz ve koruma odaklıdır. Amaç, saldırıyı gerçekleşmeden durdurmak veya gerçekleştiği anda en az hasarla püskürtmektir.

-SIEM & SOC: Ağ trafiğini ve logları 7/24 izleyerek anomali tespiti yapma.

-Incident Response : Bir sızıntı anında sistemi izole etme ve temizleme süreci.

-DFIR : Saldırı sonrası dijital kanıt toplama ve saldırının kök nedenini bulma.


🟣 Purple Team
Red ve Blue takımlarıyla ortak olarak çalışan, saldırı verilerini savunma mekanizmalarını güçlendirmek için kullanılan bir üst disiplindir.

-Feedback Loop : Red Team'in başarılı olduğu noktaları Blue Team'e aktararak sistem eksikliklerini kapatmak.

-Dinamik Savunma : Saldırı simülasyonları ile savunma kurallarını (örneğin Sigma) sürekli güncelleme.

## Eğitim Kaynakları ve Uygulama Alanları
Aşağıdaki kaynaklardan teorik bilgiler edinip, öğrendiğiniz bilgileri laboratuvar ortamlarında pratik olarak deneyerek kalıcı bir şekilde pekiştirmeyi sağlayabilirsiniz:

##### 🌐 Ağ Bilgisi ve Simülasyon (Networking)
Cisco NetAcad : Ağ dünyasının "altın standardı" olarak bilinir. Özellikle CCNA müfredatı ve Packet Tracer simülasyonları ile karmaşık ağ topolojilerini sanal ortamda inşa edip analiz edilmesi için ideal bir platformdur.

##### 💻 Programlama ve Sorgu Dilleri 
W3Schools : Python, SQL ve Web teknolojileri (HTML/CSS) için hızlı ve interaktif bir referans kaynağı. "Try it Yourself" editörleri sayesinde kodun çıktısını anında görerek pratik bilgilerinizi eşzamanlı geliştirmenizde çok etkili bir platform haline gelmiştir.

##### 🔴 Ofansif Güvenlik & CTF
-TryHackMe : Siber güvenliğe yeni başlayanlar için en iyi rehberli öğrenme yolu. Özellikle "Learning Paths" kısmı ile yapılandırılmış bir ilerleme sunar.

-Hack The Box : Daha zorlu makineler ve gerçekçi kurumsal ağ senaryoları ile sızma testi becerilerinizi en üst seviyeye taşımak için idealdir.

-PicoCTF : CMU tarafından hazırlanan, temel seviyeden başlayarak rekabetçi siber güvenlik mantığını öğreten bir eğitim platformu.

-OverTheWire : Özellikle Linux ve ağ temellerini oyunlaştırılmış bir terminal üzerinden sıfırdan öğreten bağlangıç için çok popüler bir platformdur.

-Linux Journey : Linux dünyasına giriş yapmak için en çok bilinen kaynaklardan biridir. Dosya sistemlerinden kernel yönetimine kadar her şeyi modüler ve basit bir dille anlatıyor. Terminale aşina olmak isteyen her siber güvenlikçinin ilk durağı burası olmalıdır.


##### 🔵 Defansif Güvenlik & SOC
LetsDefend : Bir SOC analisti gibi davranıp gerçek olaylara müdahale edebileceğiniz, mavi takım odaklı bir simülasyon platformudur.

Blue Team Labs Online (BTLO) : Olay müdahalesi, dijital adli tıp (DFIR) ve thread hunting konularında uzmanlaşmış pratikler sunar.

CyberDefenders : Mavi takım becerilerini ölçen ve pratik yapmanı sağlayan yoğun "investigation" odaklı lablar bulunan platformdur.


##### 🌐 Web Uygulama Güvenliği
PortSwigger Academy: Burp Suite'in yapımcılarından, sektördeki en kapsamlı ve ücretsiz web güvenliği eğitimlerini içeren platformlardan biridir. SQLi, XSS ve diğer OWASP Top 10 açıklarını lab ortamlarında bizzat sömürmenizi sağlar.

## 📖 Dokümantasyon Çıkarma
Buradaki her dosya, sıfırdan öğrenen bir öğrenci gözüyle hazırlanmıştır. İçerikler şu yapıyı takip eder:

-"Nedir?" : Kavramın tanımı yapılır.

-"Nasıl çalışır?" : Çalışma mantığından bahsedilir.

-"Uygulama" : Örnek kodlar ve lab çıktılarını içerir.

-"Hacker's Note" : Detayları olarak profesyonel ipuçlar içerir.


## 🤝 İletişim ve Katkıda Bulunma
Siber güvenlik, paylaştıkça büyüyen ve gelişen bir ekosistemdir. Bu repodaki notlar hakkında bir sorunuz varsa, bir hatayı düzeltmek isterseniz veya sadece siber güvenlik üzerine sohbet etmek isterseniz bana ulaşabilirsiniz:

-LinkedIn : https://www.linkedin.com/in/canerkizil/

-TryHackMe : https://tryhackme.com/p/canercik

-Instagram : https://www.instagram.com/canerkzll/

-Mail Adresim : canerkizil@outlook.com

