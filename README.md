# Reveal ScreenShare — DoomsDay Finder

Windows 10/11 x64 için PowerShell tabanlı, kanıtları değiştirmeden okuyan inceleme aracı. Ana dosya `DoomsDayFinder.ps1`, sürüm 1.4.1.

**Araştırma sürümü: otomatik ban aracı değildir. Doğrulanmış DoomsDay örnek corpus'u ve ölçülmüş tespit oranı yoktur. “%100” veya “neredeyse %100” tespit iddiası yapılmaz.**

## Kullanım

Windows PowerShell 5.1 veya Windows üzerinde PowerShell 7 gerekir. Yönetici olmadan da çalışır; erişilemeyen kaynaklar kaydedilir. C#, Python, Node.js veya harici runtime gerekmez. Şüpheli dosyalar hiçbir zaman çalıştırılmaz.

İndirdiğiniz dosyayı masaüstüne kaydettikten sonra **PowerShell** içine yazın:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path ([Environment]::GetFolderPath('Desktop')) 'DoomsDayFinder.ps1') -Mode Fast
```

Bu, önceden indirdiğiniz yerel scripti çalıştırır; internetten kod indirip çalıştırmaz. ExecutionPolicy seçeneği yalnızca açılan süreç için geçerlidir. Dosyanın içeriğini inceleyin. Varsayılan mod artık **Fast**; tekrar tarama menüsü için `-Mode Menu` kullanın. Eski `-Mode Full` komutu geniş ve uzun taramayı çalıştırmaya devam eder.

```powershell
.\DoomsDayFinder.ps1 -Mode Fast
.\DoomsDayFinder.ps1 -Mode Fast -Path 'D:\CustomInstance\mods'
.\DoomsDayFinder.ps1 -Mode Menu
.\DoomsDayFinder.ps1 -Mode Quick
.\DoomsDayFinder.ps1 -Mode File -Path 'C:\Samples\example.jar'
.\DoomsDayFinder.ps1 -Mode Runtime
.\DoomsDayFinder.ps1 -Mode ADS -Path 'D:\SelectedFolder'
.\DoomsDayFinder.ps1 -Mode Update
.\DoomsDayFinder.ps1 -Mode SelfTest
```

Quick bilinen Minecraft/launcher köklerini; Full bunlara ek olarak geçerli kullanıcının Desktop, Downloads, Documents, Temp, LocalAppData ve Roaming dizinlerini inceler. Tüm diskler veya tüm kullanıcı hesapları otomatik taranmaz. Özel kurulumlar için Fast/File/ADS modunda açık yol verin. Menüden tekrar tekrar tarama yapılabilir; komut satırı modu sonuçları yazıp çağıran PowerShell'e döner.

### 1.4.1 — sade sonuç ekranı

Varsayılan sonuç ekranında sayaçlar, hash, bulgu tablosu ve uzun teknik açıklamalar yazılmaz. Doğrulanmış mevcut dosya bulunursa yalnızca:

```text
DOOMSDAY DETECTED
File: C:\...\performance.jar
```

Birden fazla doğrulanmış dosya varsa her tam yol bir kez listelenir. Kesin eşleşme yoksa yalnızca bir sonuç satırı gösterilir: `NO EVIDENCE FOUND`, `REVIEW REQUIRED` veya `INCONCLUSIVE`. Eksik kaynaklar veya doğrulanmamış imzalar temiz sonuç diye sunulmaz. Doğrulanmış bulgu yanında eksik tarama varsa bir ek kapsam uyarısı kalır. Bu yalnızca sunum değişikliğidir; kanıtlar, tespit mantığı ve tarama kapsamı değiştirilmedi.

JSON/TXT raporları otomatik olarak `Reports` klasörüne kaydedilir; başarılı otomatik kayıt konsola dosya linkleri basmaz. Raporlama başarısızsa kısa uyarı gösterilir. Eski ayrıntılı ekran isteğe bağlıdır:

```powershell
.\DoomsDayFinder.ps1 -Mode Fast -DetailedOutput
```

### 1.4.0 — hedefli Fast modu

Bu mod geniş forensic incelemenin yerine geçen bir tam disk taraması değildir. Tarama kapsamı konsolda ve JSON/TXT raporda açıkça yazılır:

- Önce Java süreçlerinin agent/classpath argümanları ve görülebilen yüklü modül **yolları** toplanır. RAM byte'ları okunmaz; modüllere Authenticode doğrulaması Fast içinde uygulanmaz. Bu seçim imzasız DLL'yi otomatik hile saymaz.
- Java/Javaw Prefetch kayıtları okunur. Windows'un XPRESS-Huffman açma işlevi PowerShell/.NET Reflection.Emit ile çağrılır; C# derlenmez ve ek EXE/Java runtime indirilmez. SCCA 26/30/31 filename ve volume tabloları, bilinen layout'larda run count ve Java son çalışma zamanları ayrıştırılır. 32 MiB input/expanded güvenlik sınırı vardır; bozuk/erişilemeyen kayıtlar eksik kaynak olarak raporlanır. MAM checksum varsa kontrol edilir.
- Volume serial bilgisi yalnızca **tek bir mevcut yerel sabit volume** ile eşleştiğinde dosya yolu çözülür. C: varsayılmaz, ağ paylaşımına bağlanılmaz. Kaldırılmış/silinmiş volume, çakışan serial, göreli yol, wildcard ve Java `@argfile` çözümlenmediğinde raporlanır. Volume serial eşleşmesi tarihsel dosya kimliğini kanıtlamaz.
- Prefetch referanslarının mevcut dosyaları, Java'nın işaret ettiği dosyalar ve bilinen launcher köklerinin doğrudan `mods`, `.minecraft\mods`, `minecraft\mods` klasörleri incelenir. Aktif JVM `--gameDir` mods klasörü ve açıkça verilen `-Path` da eklenir. Launcher'ın tüm instance ağacı/libraries dizini keşfedilmez; özel veya kapalı instance için `-Path` verin.
- Prefetch referanslarında farklı uzantılara da magic kontrolü yapılır. Adaylarda **30 class ve 200 KB–15 MB elemesi yoktur**. Kurulu imzalar yalnızca byte/hash/resource bilgisine ihtiyaç duyuyorsa constant-pool/ilişki ağacı gereksiz yere üretilmez; bütün class byte'ları yine okunur, hash'lenir ve imzalarla karşılaştırılır. Class/package/ClassShape imzası kuruluysa ayrıştırma otomatik açılır. Rapordaki `ClassParsing` ve `AnalysisProfile` bu ayrımı gösterir; bu profil tam class-format doğrulaması değildir.
- Nested arşiv, byte pattern, hash, metadata ve temiz hash çelişkisi korunur. **DETECTED öncesindeki bağımsız ikinci okuma her zaman ayrıntılı class ayrıştırmasını da yapar.** Doğrulanmamış topluluk pattern'i kesin tespit olarak sunulmaz.
- Yalnızca bu hedefli dosya kümesinin ADS'leri incelenir. Normal Zone.Identifier hile değildir. Tüm AppData ADS'leri taranmış sayılmaz.
- Varsayılan Fast; USN, tarayıcı geçmişi, olay kayıtları ve genel Desktop/AppData gezisi başlatmaz. Prefetch yoksa bunlara sessizce geçmez. Eksik kaynak eksik olarak kalır. Eksik tarihsel dosya `DELETED` sayılmaz; ad benzerliği varsa `REVIEW / UNKNOWN` olur.
- Mor tek satır gerçek aday toplamını ve aktif işçileri gösterir. Doğrulanmış sonuç varsayılan olarak tarama sonunda bir kez yazılır; `-DetailedOutput` seçilirse ara bulgular da gösterilir. Dosya sayısı, byte boyutu, disk ve Defender incelemesi süreyi etkiler: **30 saniye garantisi yoktur**.

[Örnek alınan topluluk scripti](https://github.com/zedoonvm1/powershell-scripts/blob/main/DoomsDayDetector.ps1) hedefli Prefetch toplaması yanında 30-class ve dosya-boyutu elemesi yapar. Bu eleme ve kesinlik mantığı alınmadı. Yeni Prefetch ayrıştırıcısı [libscca format belgesi](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc) ve [Windows decompression API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbufferex) temelinde yazıldı. Topluluk scriptinin hız/tespit oranı bağımsız olarak ölçülmedi.

### 1.3.0 paralel dosya ve ADS analizi

```powershell
.\DoomsDayFinder.ps1 -Mode Full -Workers 4
```

- Quick/Full dosya içerikleri ve ADS host dosyaları runspace havuzuyla eşzamanlı incelenir. Varsayılan işçi sayısı mantıksal işlemci sayısı ile 4'ün küçüğüdür; `-Workers 1` seri çalışma, 2–8 kontrollü paralellik seçer. Tek dosyalık File modunda arşivin içi ayrıca paralelleştirilmez.
- İşçiler aynı tarama motorunu kullanır; tüm class/entry byte'ları, nested arşivler, hash'ler, limitler, temiz hash çelişkisi ve bağımsız VERIFY korunur. Her işçinin imza snapshot'ı ve çalışma cache'i ayrıdır. İmza JSON'u ve dosya yolları kod olarak yorumlanmaz.
- Yalnızca ana iş parçacığı rapor sayaçlarını, bulguları ve mor konsol satırını birleştirir. `Active: 4/4`, dört dosyanın aynı anda incelendiğini gösterir. Tamamlanan ve aktif dosyalar karıştırılmaz.
- İşçi sayısı ve sonuç kuyruğu sınırlıdır (en fazla işçi sayısının iki katı bekleyen sonuç). Binlerce PowerShell süreci açılmaz. Class cache bütçesi işçi başınadır; paralellik toplam RAM/disk yükünü artırabilir.
- Ctrl+C sırasında tüm işçilere iptal gönderilir, runspace havuzu kapatılır. İçerik blokları ve arşiv/class döngüleri iptali kontrol eder; engellenmiş işletim sistemi I/O çağrısı hemen dönmeyebilir. İptal veya işçi başlatma hatası tamamlanmış/temiz sonuç olarak gösterilmez. Ayrı kalıcı arka plan süreçleri oluşturulmaz.
- İlk dizin keşfi ve USN, registry, olay kayıtları gibi diğer forensic collector aşamaları hâlâ sırayladır. Tüm aşamaların aynı anda çalıştığı iddia edilmez. Özellikle yavaş disk ve çok büyük kaynaklarda 10–15 dakika garantisi yoktur; hiçbir dosya zaman kazanmak için sessizce atlanmaz.

Regresyon testleri dört işçinin gerçekten zaman bakımından örtüşerek çalışmasını; seri/paralel hash, verdict ve 1847-class sonuçlarının eşitliğini; iptal/başlatma hatasında havuzun kapanmasını; ADS metadata ve doğrulanmış payload'ların korunmasını kontrol eder. Windows'ta iki PowerShell sürümünde test edilir. [Microsoft runspace havuzu modeli](https://learn.microsoft.com/en-us/powershell/scripting/developer/hosting/creating-multiple-runspaces).

## Tarama kapsamı

- Uzantı dışında magic bytes kontrolü; tarama köklerindeki farklı uzantılı dosyalarda da ZIP/PE/CLASS başlığı aranır.
- SHA-256, yeniden okuma ile doğrulama, ayrıntılı profilde class constant pool/ilişki indeksi, metadata ve manifest incelemesi.
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

### 1.2.2 performans değişiklikleri

- Java class ayrıştırıcısında her sabit alan için PowerShell fonksiyonu çağırma ve tüm `switch` koşullarını değerlendirme maliyeti kaldırıldı. Alanlar ve sınır kontrolleri korunur.
- İçerik eşleştirme planları arşiv başına hazırlanır; imza metadata'sı cache'ten eski haliyle alınmaz. Okuma tamponu küçük entry'lere göre küçülür, büyük dosyalarda 1 MiB olur; sınırdan geçen imzalar örtüşmeli okunur.
- Aynı SHA-256'ya sahip class içeriğinin ayrıştırılmış sonucu tekrar kullanılabilir. Her entry'nin tüm byte'ları yine okunur, hash ve imzaları kontrol edilir. Cache en fazla 8192 kayıt ve yaklaşık 64 MiB maliyet bütçesiyle sınırlıdır; gerçek süreç RAM sınırı değildir. Bağımsız VERIFY bu class cache'ini kullanmaz.
- Arşiv dışındaki dosyalarda hash, aile byte imzaları ve ek araç göstergeleri tek içerik geçişinde kontrol edilir. Ek araç göstergeleri aile imzası olarak puanlanmaz.
- ADS byte araması PowerShell'de byte başına döngü yerine aynı bloklu motoru kullanır; UTF-8/UTF-16 eşleşmeleri korunur.
- Full taramanın ilk keşif listesi ADS ve tarayıcı veritabanı konumlarında tekrar kullanılır; aynı dizinler tekrar gezilmez. Zone.Identifier tekrar okunmadan tarayıcı bağlamına dönüştürülür. Tarama sırasında sonradan oluşan dosyalar bu keşif anındaki listeye dahil değildir; gerekirse yeni tarama gerekir.
- Temiz arşivlerin ayrıntılı class/resource ağaçları sırf cache için tutulmaz; özet kanıt ve fingerprint'ler korunur. Açıkça ayrıntılı finding istenirse yeniden incelenir. Ana tarama bittiğinde çalışma cache'leri bırakılır.
- Mor satırda geçen süre; JSON/TXT raporda aşama süreleri ve cache sayaçları bulunur. Bu süreler bir sonraki darboğazı kanıtla belirlemek içindir.

Hedef 10–15 dakikaya yaklaşmaktır; **tüm bilgisayarlarda 15 dakikada tamamlama garantisi veya gizli süre kesintisi yoktur**. Kaynak kapsamı ve class sayısı sınırlandırılmaz. Özellikle büyük AppData dizinleri, yavaş disk, çok sayıda farklı class veya büyük USN journal daha uzun sürebilir.

Tekrarlanabilir sentetik benchmark (tespit başarısı ölçümü değildir):

```powershell
.\tests\Measure-DoomsDayFinder.ps1 -ClassCount 300 -ConstantsPerClass 1000
```

Benchmark ayrı geçici dizinde çalıştırılmayan JAR fixture'ları oluşturur, ilk analiz ve aynı içerikli başka isimdeki dosyanın analiz süresini; class sayısını ve fingerprint'leri yazdırır. Aynı parametrelerle önceki ve yeni sürüm kıyaslanabilir. Bu mikrobenchmark oranı tüm Full taramanın hızlanma oranı olarak kullanılamaz.

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

Tam olarak desteklenmeyenler: RAM içeriği/manual-map/kernel görünürlüğü, şifrelenmiş payload açma, PE içindeki arbitrary embedded container carving, tüm Prefetch sürümleri ve file-reference/MFT çözümlemesi, SQLite download tabloları, SRUM/Amcache/ShimCache kayıt parsing, FRN tabanlı USN rename zinciri, Jump List binary parsing, silinen içeriğin kurtarılması ve eksiksiz forensic timeline. Fast'ın yeni Java Prefetch parser'ı dışındaki eski Full collector'ı Prefetch için yalnızca metadata/bütünlük bilgisi verir. Bunların metadata'sı bazı collector'larda bulunabilir; tam çözümleme değildir. Windows PowerShell 5.1 dizin ADS'lerini bu provider ile enumerate edemez. Loglar varsayılan olarak son 30 gün ile sınırlıdır. Erişilemeyen kaynaklar, reparse noktaları ve parse limitleri raporlanır. PE magic, tam PE doğrulaması veya yürütülebilirlik ispatı değildir.

Araştırma ve doğrulama politikası: [docs/RESEARCH.md](docs/RESEARCH.md).
