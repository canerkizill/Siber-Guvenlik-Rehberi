# 🛡️ Siber Güvenlik : Sıfırdan İleri Seviyeye
  Bir siber güvenlikçinin görevi, sadece sistemlere sızmak veya onları korumak değil; bu sistemlerin nasıl oluşturulduğunu anlamak ve bu sistemlerin çalışma prensiplerini en iyi şekilde sürdürmektir. Bu repoda bir siber güvenlik araştırmacısının sıfırdan uzmanlığa uzanan yolculuğundaki tüm teknik adımları ve uygulama notları bulunacaktır.

## Siber Güvenlik Yolculuğu İçin Tavsiyeler 💡
Siber güvenlik sadece komut satırından ibaret değildir; bu yol bir maratondur. Yolda kaybolmanızı engelleyecek ve sizi ileriye taşıyacak birtakım tavsiyeler:

##### 🧠 1. Gelişim Süreci: Bilgi Zehirlenmesinden Korunun
Siber güvenlik alanı uçsuz bucaksızdır ve her şeyi aynı anda öğrenmeye çalışmak tükenmişliğe (burnout) yol açabilir.

* Derinlik vs. Genişlik : Her konudan biraz bilmektense tek bir anak konuya odaklanmak, öğrenme süreci için çok daha faydalı olacaktır.

* Kıyaslama Hatası : Başkalarının bulunduğu konumu kendi konumunuzla kıyaslamayın. Herkesin öğrenme eğrisi farklıdır.

* "Bilmiyorum" Demekten Korkmayın : Sektörün en iyileri bile her şeyi bilmez. Önemli olan, bilmediğiniz şeyi nasıl araştıracağınızı bilmektir.

##### ✍️ 2. "Write-up" Yazma Alışkanlığı Edinin
Çözdüğünüz bir labı veya sızdığınız bir makineyi sadece bitirip geçmeyin. Onu bir başkasına öğretir gibi adım adım belgeleyin.

* Kalıcı Öğrenme : Yazmak, bilgiyi kısa süreli bellekten uzun süreli belleğe taşır.

* Paylaşım : Linkedin profilinizde veya blog sayfanızda tutacağınız düzenli write-up'lar, ileride iş başvurularında en güçlü referansınız olacaktır.

##### 🌍 3. Dünyanın Nabzını Tutun
Siber güvenlik statik bir alan değildir; bugün güvenli olan yarın "Zero-day" ile sarsılabilir. Güncel kalmak için şu kaynakları radarınıza alın:

* **[The Hacker News](https://thehackernews.com/)** : Sektörün nabzını tutan en popüler haber kaynağı.

* **[BleepingComputer](https://www.bleepingcomputer.com/)** : Özellikle fidye yazılımları ve yeni zafiyetler için harika bir site.

* **[Darknet Diaries](https://darknetdiaries.com/)** : Teknikten ziyade hikayeleştirme ile siber dünyanın karanlık yüzünü anlatan bir podcast kanalıdır.

Analiz Edin : Sadece haberi okumayın; "Bu saldırı hangi zafiyet zinciriyle yapılmış olabilir?" diye üzerine düşünün.

##### 🗣️ 4. İngilizceyi Bir "Araç" Olarak Kullanın
Siber güvenliğin ana dili İngilizce'dir. En yeni exploitler, teknik dokümanlar ve topluluk tartışmaları ilk olarak bu dilde gerçekleşir. Teknik İngilizceyi geliştirmek, kaynaklara erişim hızını 10 kat artırır.

##### 🛡️ 6. Etik Sınırlara Sadık Kalın (White-Hat Mindset)
Öğrendiğiniz teknikler çok güçlü silahlardır. Bu gücü her zaman dijital dünyayı daha güvenli bir yer haline getirmek için kullanın. Etik duruş, bir siber güvenlikçinin en değerli kimliğidir.

## Siber Güvenliğin Temelleri
Siber güvenlik temel olarak dört ana disiplini kapsar. Bu alanlarda uzmanlaşmadan ileri seviye saldırı/savunma yapmak düşünülemez. İşte dört temel disiplin:

##### 1.Hacking 🛡️
Güvenliğin kalbi olan CIA Triad prensiplerini ve saldırı metodolojilerini kapsar.

* Keşif ve Tarama: Hedef sistem hakkında bilgi toplama.

* Zafiyet Analizi: Zayıf noktaların tespiti.

* Sömürü: Tespit edilen açıkların kullanılması.

* Raporlama: Bulguların etik çerçevede sunulması.


##### 2.Networking 🌐
Ağ bilgisi, bir siber güvenlikçi adayının görebilme yeteneğidir. Paketlerin yapısını bilmek, trafiğe müdahale etmenin ilk şartıdır.

* OSI Modeli & TCP/IP : Verinin katmanlar arası yolculuğu.

* Protokol Analizi : HTTP, DNS, SMB, FTP ve daha fazlası.

* Araçlar : Wireshark ile paket analizi ve Nmap ile ağ topolojisi.


##### 3.Operating Systems 🐧
Güvenlik, yetki yönetiminde başlar. Sistemlerin iç yapısını bilmek, yetki yükseltme mantığını kavramayı sağlar.

* Linux : Dosya sistemleri, kernel yapısı, Bash scripting ve terminal hakimiyeti.

* Windows : Active Directory, Registry kayıtları ve PowerShell kullanımı.

##### 4.Coding & Automation 🐍
Kodlama, bir siber güvenlikçinin en önemli yardımcılarından biridir. Hazır araçların bittiği yerde kendi çözümünü üretmek için programlama bilgisi gereklidir.

* Programlama Dilleri : Ağ tarayıcıları, brute-force scriptleri ve otomasyon araçları. Örneğin Python(vb.)

* Algoritmik Düşünce : Saldırı vektörlerini koda dökme ve savunma scriptleri yazma.

### Ekstralar :
##### Hardware Hacking & IoT 🔌

Siber güvenlik sadece yazılımla sınırlı değildir. Sanal dünyanın fiziksel dünya ile buluştuğu nokta, siber güvenliğin önemli alanlarından biridir.

* Gömülü Sistemler: Mikrodenetleyicilerin çalışma mantığı ve sensör etkileşimi.

* Protokol Analizi: UART, I2C ve SPI gibi donanım haberleşme dilleri üzerinden veri elde etme.

* Fiziksel Güvenlik: BadUSB saldırıları, RFID/NFC klonlama ve devre kartı analizi.

* IoT Güvenliği: Akıllı cihazların ekosistemindeki zayıflıkların tespiti.


##### Red Team, Blue Team ve Purple Team ⚔️

Bu bölüm, saldırı ve savunma stratejilerinin disiplinlerdir.

🔴 Red Team
Saldırgan bir bakış açısıyla sistemlerin direncini ölçer. Sadece zafiyet bulmakla kalmaz, bu zafiyetlerin gerçek bir saldırıda nasıl zincirlenebileceğini simüle eder.

* Adversary Emulation: Gerçek dünya tehdit aktörlerinin tekniklerini taklit etme.

* Social Engineering: İnsan faktörünü manipüle ederek sisteme sızma yolları.

* Metodoloji: Cyber Kill Chain ve **[MITRE ATT&CK matrisi](https://attack.mitre.org/)** üzerinden saldırı planlama.

🔵 Blue Team
Sürekli izleme, analiz ve koruma odaklıdır. Amaç, saldırıyı gerçekleşmeden durdurmak veya gerçekleştiği anda en az hasarla püskürtmektir.

* SIEM & SOC: Ağ trafiğini ve logları 7/24 izleyerek anomali tespiti yapma.

* Incident Response : Bir sızıntı anında sistemi izole etme ve temizleme süreci.

* DFIR : Saldırı sonrası dijital kanıt toplama ve saldırının kök nedenini bulma.


🟣 Purple Team
Red ve Blue takımlarıyla ortak olarak çalışan, saldırı verilerini savunma mekanizmalarını güçlendirmek için kullanılan bir üst disiplindir.

* Feedback Loop : Red Team'in başarılı olduğu noktaları Blue Team'e aktararak sistem eksikliklerini kapatmak.

* Dinamik Savunma : Saldırı simülasyonları ile savunma kurallarını (örneğin Sigma) sürekli güncelleme.

## Eğitim Kaynakları ve Uygulama Alanları
Aşağıdaki kaynaklardan teorik bilgiler edinip, öğrendiğiniz bilgileri laboratuvar ortamlarında pratik olarak deneyerek kalıcı bir şekilde pekiştirmeyi sağlayabilirsiniz:

##### 🌐 Ağ Bilgisi ve Simülasyon (Networking)
* **[Cisco Networking Academy](https://www.netacad.com/)** : Ağ dünyasının "altın standardı" olarak bilinir. Özellikle CCNA müfredatı ve Packet Tracer simülasyonları ile karmaşık ağ topolojilerini sanal ortamda inşa edip analiz edilmesi için ideal bir platformdur.

##### 💻 Programlama ve Sorgu Dilleri 
* **[W3Schools](https://www.w3schools.com/)** : Python, SQL ve Web teknolojileri (HTML/CSS) için hızlı ve interaktif bir referans kaynağı. "Try it Yourself" editörleri sayesinde kodun çıktısını anında görerek pratik bilgilerinizi eşzamanlı geliştirmenizde çok etkili bir platform haline gelmiştir.

##### 🔴 Ofansif Güvenlik & CTF
* **[TryHackMe](https://tryhackme.com/)** : Siber güvenliğe yeni başlayanlar için en iyi rehberli öğrenme yolu. Özellikle "Learning Paths" kısmı ile yapılandırılmış bir ilerleme sunar.

* **[HackTheBox](https://hs.hackthebox.com/)** : Daha zorlu makineler ve gerçekçi kurumsal ağ senaryoları ile sızma testi becerilerinizi en üst seviyeye taşımak için idealdir.

* **[PicoCTF](https://picoctf.org/)** : CMU tarafından hazırlanan, temel seviyeden başlayarak rekabetçi siber güvenlik mantığını öğreten bir eğitim platformu.

* **[OverTheWire](https://overthewire.org/wargames/)** : Özellikle Linux ve ağ temellerini oyunlaştırılmış bir terminal üzerinden sıfırdan öğreten bağlangıç için çok popüler bir platformdur.

* **[Linux Journey](https://labex.io/linuxjourney)** : Linux dünyasına giriş yapmak için en çok bilinen kaynaklardan biridir. Dosya sistemlerinden kernel yönetimine kadar her şeyi modüler ve basit bir dille anlatıyor. Terminale aşina olmak isteyen her siber güvenlikçinin ilk durağı burası olmalıdır.


##### 🔵 Defansif Güvenlik & SOC
* **[LetsDefend](https://letsdefend.io/)** : Bir SOC analisti gibi davranıp gerçek olaylara müdahale edebileceğiniz, mavi takım odaklı bir simülasyon platformudur.

* **[Blue Team Labs Online (BTLO)](https://blueteamlabs.online/)** : Olay müdahalesi, dijital adli tıp (DFIR) ve thread hunting konularında uzmanlaşmış pratikler sunar.

* **[CyberDefenders](https://cyberdefenders.org/)** : Mavi takım becerilerini ölçen ve pratik yapmanı sağlayan yoğun "investigation" odaklı lablar bulunan platformdur.


##### 🌐 Web Uygulama Güvenliği
* **[PortSwigger Academy](https://portswigger.net/web-security)** : Burp Suite'in yapımcılarından, sektördeki en kapsamlı ve ücretsiz web güvenliği eğitimlerini içeren platformlardan biridir. SQLi, XSS ve diğer OWASP Top 10 açıklarını lab ortamlarında bizzat sömürmenizi sağlar.


Ayrıca yol haritası ve daha fazla kaynak önerisi için bakabilirsiniz : https://github.com/Hamed233/Cybersecurity-Mastery-Roadmap

## 📖 Dokümantasyon Çıkarma
Buradaki her dosya, sıfırdan öğrenen bir öğrenci gözüyle hazırlanmıştır. İçerikler şu yapıyı takip eder:

* "Nedir?" : Kavramın tanımı yapılır.

* "Nasıl çalışır?" : Çalışma mantığından bahsedilir.

* "Uygulama" : Örnek kodlar ve lab çıktılarını içerir.

* "Hacker's Note" : Detayları olarak profesyonel ipuçlar içerir.


## 🤝 İletişim ve Katkıda Bulunma
Siber güvenlik, paylaştıkça büyüyen ve gelişen bir ekosistemdir. Bu repodaki notlar hakkında bir sorunuz varsa, bir hatayı düzeltmek isterseniz veya sadece siber güvenlik üzerine sohbet etmek isterseniz bana ulaşabilirsiniz:

-LinkedIn : https://www.linkedin.com/in/canerkizil/

-TryHackMe : https://tryhackme.com/p/canercik

-Instagram : https://www.instagram.com/canerkzll/

-Mail Adresim : canerkizil@outlook.com

