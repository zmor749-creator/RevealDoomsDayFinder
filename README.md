# Reveal ScreenShare — DoomsDay Finder

Windows 10/11 x64 için PowerShell tabanlı, kanıtları değiştirmeden okuyan inceleme aracı. Ana dosya `DoomsDayFinder.ps1`, sürüm 1.2.1.

**Araştırma sürümü: otomatik ban aracı değildir. Doğrulanmış DoomsDay örnek corpus'u ve ölçülmüş tespit oranı yoktur. “%100” veya “neredeyse %100” tespit iddiası yapılmaz.**

## Kullanım

Windows PowerShell 5.1 veya Windows üzerinde PowerShell 7 gerekir. Yönetici olmadan da çalışır; erişilemeyen kaynaklar kaydedilir. C#, Python, Node.js veya harici runtime gerekmez. Şüpheli dosyalar hiçbir zaman çalıştırılmaz.

İndirdiğiniz dosyayı masaüstüne kaydettikten sonra **PowerShell** içine yazın:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path ([Environment]::GetFolderPath('Desktop')) 'DoomsDayFinder.ps1') -Mode Full
```

Bu, önceden indirdiğiniz yerel scripti çalıştırır; internetten kod indirip çalıştırmaz. ExecutionPolicy seçeneği yalnızca açılan süreç için geçerlidir. Dosyanın içeriğini inceleyin. Menü için `-Mode Full` kısmını çıkarın.

```powershell
.\DoomsDayFinder.ps1 -Mode Quick
.\DoomsDayFinder.ps1 -Mode File -Path 'C:\Samples\example.jar'
.\DoomsDayFinder.ps1 -Mode Runtime
.\DoomsDayFinder.ps1 -Mode ADS -Path 'D:\SelectedFolder'
.\DoomsDayFinder.ps1 -Mode Update
.\DoomsDayFinder.ps1 -Mode SelfTest
```

Quick bilinen Minecraft/launcher köklerini; Full bunlara ek olarak geçerli kullanıcının Desktop, Downloads, Documents, Temp, LocalAppData ve Roaming dizinlerini inceler. Tüm diskler veya tüm kullanıcı hesapları otomatik taranmaz. Özel kurulumlar için File/ADS modunda açık yol verin. Menüden tekrar tekrar tarama yapılabilir; komut satırı modu sonuçları yazıp çağıran PowerShell'e döner.

## Tarama kapsamı

- Uzantı dışında magic bytes kontrolü; tarama köklerindeki farklı uzantılı dosyalarda da ZIP/PE/CLASS başlığı aranır.
- SHA-256, yeniden okuma ile doğrulama, class constant pool/ilişki indeksi, metadata ve manifest incelemesi.
- Her JAR entry'sinin byte içerikleri okunur. 30/50/100/1000 class sınırı yoktur.
- İç içe ZIP/JAR, uzantısı değiştirilmiş embedded archive/class ve embedded native entry hash'leri. Maksimum iç içe derinlik 3.
- Kaynak listesi fingerprint'i; entry içerik hash'lerinden isim/sıra/sıkıştırmadan bağımsız fingerprint; class adları normalize edilmiş yapısal fingerprint. Yapısal benzerlik tek başına `DETECTED` oluşturmaz; keyfi obfuscation'a dayanıklılık garantisi yoktur.
- Java süreçleri, JVM agent/classpath argümanları, Minecraft ilişkili süreçlerin görülebilen yüklü modülleri.
- Dosya ADS'leri; normal Zone.Identifier metadata olarak ele alınır. Adı Zone.Identifier olsa bile payload başlığı varsa içerik incelenir.
- Windows PowerShell 5.1 uyumluluğu için ADS içerikleri FileSystem provider ile okunur; 64 MiB üstündeki tek stream eksik analiz olarak raporlanır. Diske payload kopyası çıkarılmaz.
- Mevcut Sysmon XML olayları: process, loaded image, Java'ya process access/remote thread, stream, deletion ve process tampering. Sysmon kurulmaz, açılmaz veya yeniden yapılandırılmaz.
- SysMain/Prefetch/sechost bütünlük bağlamı; PSReadLine ve olay kayıtları; USN ham candidate satırları; seçili registry/LNK ve dosya metadata kaynakları.
- Bir Java hedefini, bellek yazma yeteneğini ve Oracle kullanım yolunu birlikte içeren dosyalarda `REVIEW` bağlamı. Dosyanın varlığı, çalıştırıldığını veya DoomsDay olduğunu kanıtlamaz.

Full kapsamı hız için daraltılmaz. Tekrar okumalar cache ile azaltılır; bağımsız VERIFY aşaması cache kullanmaz. Konsolda dosyalar alt alta yazılmaz: taranacak candidate toplamı ve güncellenen tek satır gösterilir. Süre dosya sayısına, boyutlarına, diske ve erişim izinlerine bağlıdır. Güvenlik limitleri 512 MiB toplam expanded bytes, 200.000 toplam entry, 1000:1 oran, 64 MiB tek embedded/class buffer ve 4 MiB metadata'dır. Limit nedeniyle tamamlanamayan analiz açıkça bildirilir. Ctrl+C taramayı keser; kesintiden sonra tamamlanmış rapor garantisi verilmez.

### Tek satır ilerleme ve Enter sorunu

1.2.1'de keşif çıktısı tüm dizin ağacını bellekte bekletmeden dosya dosya işlenir. Sayım sırasında `[INDEX] 16,182 files | Candidates: 120; counting` görünür; henüz bilinmeyen toplam yerine `/ 0` veya `%0` yazılmaz. İçerik incelemesi başlayınca gerçek toplam ve yüzde gösterilir. Mor satır yerinde güncellenir; bilinmeyen toplam aşamasında da ekran yazımı en fazla yaklaşık 150 ms'de bir yapılır. Sonuçlar ve uyarılar ayrı satırlardır. Disk/izin işlemi gerçekten bekliyorsa arayüz bağımsız bir ilerleme yüzdesi uydurmaz.

Taramanın içinde `Read-Host`, tuş veya Enter beklemesi yoktur. Eski Windows konsolundaki fareyle seçim duraklamasına karşı, yalnızca tarama boyunca QuickEdit kapatılır ve `finally` içinde önceki konsol modu geri yüklenir. Bu işlem PowerShell/.NET Reflection.Emit ile yalnızca `GetStdHandle`, `GetConsoleMode`, `SetConsoleMode` API'lerini bağlar; C# derlemez, kayıt defterine yazmaz ve CTRL+C davranışını korur. Konsol bulunmayan host'larda uygulanmaz; politika veya API hatasında uyarı verilir. Zorla süreç kapatılırsa geri yükleme garantisi yoktur. Menüdeki kullanıcı seçimi ve tarama sonrası menüye dönme istemi ayrı davranışlardır; `-Mode Full` bunları kullanmaz.

İlgili Windows davranışı: [SetConsoleMode](https://learn.microsoft.com/en-us/windows/console/setconsolemode), [konsol modunu geri yükleme](https://learn.microsoft.com/en-us/windows/console/console-modes). Eski sürüm zaten metin seçimiyle duraklatılmışsa önce Esc, ardından Ctrl+C ile durdurup yeni sürümü çalıştırın.

## İmzalar ve kararlar

`signatures/doomsday.json` ve tek dosya kullanımındaki gömülü veri, kaynak bağlantısı belirtilen **üç doğrulanmamış topluluk byte pattern'i** içerir. Bunlar `Verified=false` olarak işaretlidir ve örtüşen pattern'ler aynı bağımsızlık grubundadır. Hiçbiri `DETECTED` yetkisi vermez. Güncelleme yalnızca JSON indirir. Bakımcı onayı, JSON alanını `true` yapmakla bilimsel olarak sağlanmış olmaz: gerçek örnek analizi ve temiz corpus testi gerekir.

`DETECTED`: doğrulanmış aile SHA-256 imzası veya aynı artifact'ta en az iki doğrulanmış, yüksek özgüllüklü, bağımsız içerik grubu; ardından dosyanın bağımsız yeniden açılması, hash ve eşleşmelerin tekrar doğrulanması gerekir. Bilinen temiz hash ile çelişki bunu engeller.

`INFO`, `REVIEW`, `SUSPICIOUS`, `HIGH CONFIDENCE`, `DELETED TRACE`, `RUNTIME TRACE`, `INCONCLUSIVE` ve `NO EVIDENCE FOUND` diğer sonuçlardır. Confidence kanıt ağırlığıdır, istatistiksel olasılık değildir. 99 puan “%99 hile” demek değildir. İmzasız DLL, Java Agent, silinmiş dosya, ADS, Prefetch eksikliği veya obfuscation tek başına DoomsDay değildir.

Doğrulanmış imza yoksa veya kaynaklar eksikse genel sonuç `INCONCLUSIVE` olur. Kaynak isimlerinin raporda bulunması o kaynağın tüm içeriğinin parse edildiği anlamına gelmez.

## Silinmiş dosyalar ve korelasyon

Silinmiş payload byte'ları otomatik kurtarılmaz. Mevcut Sysmon deletion kaydındaki SHA-256 doğrulanmış aile hash'iyle eşleşirse `DELETED TRACE` üretilebilir; doğrulamanın geçmiş log kaydı için olduğu açıkça yazılır. Aynı yolda sonradan bulunan dosya eski dosya sayılmaz. Yalnızca ad benzerliğiyle kanıt zinciri kurulmaz; tam yol bağlamı veya tam SHA-256 ilişkisi belirtilir, bağlam puanı verdict'i yükseltmez.

## Raporlar ve gizlilik

Sonuçlar konsola, JSON ve TXT raporları scriptin yanındaki `Reports` klasörüne yazılır. Yazılamazsa belirtilen kullanıcı klasörüne geçilir. Raporlar tam yollar, komutlar, kullanıcı bilgileri ve URL'ler içerebilir; herkese açık Discord/GitHub'a yüklemeyin. İnceleme, cihaz sahibinin bilgisi ve izniyle yapılmalıdır.

“Read-only”, incelenen dosyaları, ADS'leri, registry'yi, servisleri ve logları değiştirmemeyi ifade eder. Rapor oluşturma ve kullanıcının başlattığı imza güncellemesi araç dosyalarına yazar; geçici konsol seçim modu yalnızca arayüz içindir. Windows çalıştırma/erişim izleri oluşturabilir; fiziksel olarak sıfır disk yazımı iddia edilmez.

## Testler ve sınırlamalar

```powershell
.\tests\Test-DoomsDayFinder.ps1
```

Sentetik fixture'lar çalıştırılmaz. Testler ayrı geçici dizinde üretilir ve sonuç dosyasıyla birlikte bırakılır. Geçmiş denemeler silinmez. Motor regresyonlarının geçmesi gerçek DoomsDay sensitivity ölçümü değildir. Windows PowerShell 5.1 ve PowerShell 7 için CI tanımı vardır; CI sonucunu ayrıca kontrol edin.

Henüz ölçülmeyenler: gerçek DoomsDay buildleri, bypass'lı örnekler ve OptiFine/Sodium/Lithium/Fabric API/Forge/NeoForge/Iris gibi temiz mod corpus'unda tespit oranı. Doğrulanmış özgün örnekler, kaynak URL/hash ve etiketli temiz corpus olmadan üretim güvenilirliği iddiası yapılmaz.

Tam olarak desteklenmeyenler: RAM içeriği/manual-map/kernel görünürlüğü, şifrelenmiş payload açma, PE içindeki arbitrary embedded container carving, sıkıştırılmış Prefetch içeriği, SQLite download tabloları, SRUM/Amcache/ShimCache kayıt parsing, FRN tabanlı USN rename zinciri, Jump List binary parsing, silinen içeriğin kurtarılması, runspace paralelleştirmesi ve eksiksiz forensic timeline. Bunların metadata'sı bazı collector'larda bulunabilir; tam çözümleme değildir. Windows PowerShell 5.1 dizin ADS'lerini bu provider ile enumerate edemez. Loglar varsayılan olarak son 30 gün ile sınırlıdır. Erişilemeyen kaynaklar, reparse noktaları ve parse limitleri raporlanır. PE magic, tam PE doğrulaması veya yürütülebilirlik ispatı değildir.

Araştırma ve doğrulama politikası: [docs/RESEARCH.md](docs/RESEARCH.md).
