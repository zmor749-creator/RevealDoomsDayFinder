# Araştırma notları — 1.2.0

Bu belge gözlemi, çıkarımı ve doğrulanmamış iddiayı ayırır. DoomsDay örnekleri veya bypass araçları bu çalışma sırasında çalıştırılmadı. Resmî site üzerinden payload edinme denemesi ortamın ağ erişim sınırında durdu; bu nedenle doğrulanmış örnek analizi yapıldığı iddia edilmez.

## Kaynaklardan çıkan uygulama kararları

| Kaynak / gözlem | Uygulama kararı | Kanıtlamadığı şey |
| --- | --- | --- |
| [DoomsDay sitesi](https://doomsdayclient.com/) dosya adı/boyutu randomizasyonu ve screenshare araçlarını bypass ettiğini iddia ediyor. | Dosya adına/tek hash'e bağlı kalmayan içerik, class ve embedded archive incelemesi. | Sitenin bypass reklamının bağımsız doğruluğu veya bizim yakalama oranımız. |
| [Oracle Java instrumentation](https://docs.oracle.com/en/java/javase/21/docs/api/java.instrument/java/lang/instrument/package-summary.html) başlangıç ve runtime agent mekanizmalarını tanımlıyor. | Premain-Class, Agent-Class, Launcher-Agent-Class ve JVM argümanları bağlam olarak kaydediliyor. | Agent kullanımı hile değildir; dinamik yüklenmiş her agent komut satırında görünmez. |
| [Oracle JVMTI](https://docs.oracle.com/en/java/javase/21/docs/specs/jvmti.html) native agent arayüzünü açıklıyor. | Native module ve agentpath/agentlib bağlamı; hiçbir agent başlatılmaz. | JNI/JVMTI tek başına DoomsDay göstergesi değildir. |
| [JVM class formatı](https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-4.html) constant pool ve member düzenini tanımlar. | Salt dosya adları yerine byte içeriğinden class isimleri/ilişkileri ve normalize member şekli çıkarılır. | Class shape bir aile kimliği değildir; tam bytecode verifier uygulanmış değildir. |
| [Microsoft ADS provider](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) named stream okumasını ve sürüm sınırlarını belgeliyor. | Dosya stream'leri read-only inceleniyor; normal Zone.Identifier otomatik şüpheli değil. | ADS varlığı veya Zone.Identifier yokluğu hile ispatı değildir. |
| [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) olay alanları, DLL/hash kayıtları, process access ve deletion olaylarını tanımlıyor. | Önceden var olan olaylar XML alanlarıyla toplanıyor; log/config değiştirilmez. | Event 10 bellek yazıldığını ispatlamaz; debugger/AV aynı olayı üretebilir. Event 15 hash'i yanlışlıkla ADS payload hash'i sayılmaz. |
| [Microsoft change journals](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journals) USN'nin değişiklik kayıtlarını ve yönetilebilirliğini anlatıyor. | Ham candidate CSV satırları saklanıyor; tam yol/rename reconstruction yapılmadığı raporlanıyor. | Ad benzerliği aynı dosya kimliğini veya silinen içeriği kanıtlamaz. |
| [Açık kaynak Java string cleaner](https://github.com/onlyxzkz/String-Cleaner-for-minecraft/blob/main/StringCleaner.py) Java belleğine yazma ve Oracle usage log dizinine ilişkin işlemler içeriyor. | Bu yeteneklerin aynı dosyada birlikte görünmesi `REVIEW`; mevcut loglardan ayrı bağlam toplanıyor. | Static string eşleşmesi çalıştırma, başarılı iz silme veya DoomsDay kullanma kanıtı değildir. |
| [Topluluk DoomsDayDetector kaynağı](https://github.com/zedoonvm1/powershell-scripts/blob/main/DoomsDayDetector.ps1) üç byte pattern ve kısa class isimleri kullanıyor. | Üç uzun byte pattern kaynağı belirtilerek **doğrulanmamış** araştırma girdisi; kısa/generic class isimleri alınmadı. Örtüşen pattern'ler bağımsız sayılmıyor. | Topluluk aracının etiketlemesi doğrulanmış DoomsDay ground truth değildir. |

## Neden %100 denmiyor?

Salt sonradan yapılan disk/log taraması, hiç kaydedilmemiş veya artık mevcut olmayan byte'ları garanti biçimde geri getiremez. Hedef kendi izlerini değiştirebilir; erişim izinleri, logging konfigürasyonu ve saklama süresi görünürlüğü sınırlar. Sistemin kernel tarafından yanlış veri döndürmesi bu aracın güven modelinin dışındadır. Çok sayıda zayıf göstergeyi toplamak bu sınırları çözmez.

## İmza kabul kriteri

1. Yetkili kaynaktan alınmış özgün örnek, edinme tarihi/URL'si ve SHA-256 ile kaydedilir; payload çalıştırılmaz.
2. Örneğin aile kimliği bağımsız statik analizle doğrulanır; sadece dosya adı veya sitenin reklamı kullanılmaz.
3. Göstergenin byte/class/resource konumu, hangi sürümlerde bulunduğu ve karşılaştırılan negatif örnekler tutulur.
4. Aynı class'ın package adı, string'i ve örtüşen byte dizileri ayrı bağımsız kanıt gibi sayılmaz.
5. Temiz mod corpus'unda herhangi bir `DETECTED`, imzayı kabul etmeyi engeller. Temiz corpus hash'leri yalnızca doğrulanmış kaynaktan eklenir.
6. Gerçek aile örnekleri eğitim ve holdout kümelerine ayrılır. Rename, farklı uzantı, repack, nested/ADS taşıma gibi varyantlar ayrıca değerlendirilir. Sadece türev kopyalar yeni bağımsız örnek gibi sayılmaz.
7. TP/FN/FP/TN, başarısız/eksik taramalar, sürüm başına sonuçlar ve test koşulları yayınlanır. Sensitivity = TP/(TP+FN), false-positive rate = FP/(FP+TN). Küçük örneklemde sıfır FP, gerçek dünyada sıfır FP garantisi değildir.

## Mevcut ölçümün sınırı

Sentetik testler motorun deterministik davranışını doğrular. Gerçek DoomsDay için TP/FN ölçülmedi. Temiz Minecraft mod corpus'u üzerinde FP/TN ölçülmedi. Bu nedenle üretim ban kararı için yeterli doğrulama sağlandığı söylenemez.
