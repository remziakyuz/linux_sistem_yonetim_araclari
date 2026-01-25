# Laptop Üzerinde İki USB Ethernet ile Yazılımsal Switch Oluşturma ve Paket Yakalama

Bu makalede, **bir laptopa takılı iki adet USB Ethernet adaptörü kullanarak yazılımsal bir Layer‑2 switch (bridge) oluşturmayı** 
ve bu köprü üzerinden geçen **tüm ağ paketlerini yakalamayı (packet capture)** adım adım, teknik ve detaylı şekilde ele alacağız.

Anlatım **Linux (Debian/Ubuntu tabanlı)** sistemler üzerinden yapılmıştır. 
Kavramlar ve yöntemler diğer Linux dağıtımlarına da büyük ölçüde aynen uygulanabilir.

---

## 1. Kullanım Senaryoları

Bu yaklaşım özellikle aşağıdaki durumlarda tercih edilir:

- 🔍 **Network troubleshooting** (paket analizi, gecikme, hatalı yapılandırma)
- 🧪 **Lab ortamlarında trafik gözlemi**
- 🔐 **IDS/IPS, firewall, DPI testleri**
- 🕵️‍♂️ **Man‑in‑the‑Middle (MITM) testleri** (yetkili ve etik kullanımda)
- 🧠 Eğitim ve öğretim amaçlı ağ analizi

Bu yapı, fiziksel bir managed switch + mirror port yerine **tamamen yazılımsal ve taşınabilir** bir çözüm sunar.

---

## 2. Donanım ve Yazılım Gereksinimleri

### Donanım

- 1 adet laptop / PC (Linux kurulu)
- 2 adet **USB Ethernet adaptörü** (ASIX, Realtek vb.)
- 2 adet Ethernet kablosu

### Yazılım

- Linux kernel (>= 4.x önerilir)
- `iproute2`
- `bridge-utils` veya `ip bridge`
- `tcpdump` veya `Wireshark`
- (Opsiyonel) `ethtool`, `ebtables`

---

## 3. Ağ Topolojisi

```
[ AĞ CİHAZI A ]
        |
        | eth0 (usb-eth1)
   [  LAPTOP  ]  <-- Yazılımsal Switch
        | eth1 (usb-eth2)
        |
[ AĞ CİHAZI B ]
```

Laptop, iki cihaz arasında **şeffaf bir Layer‑2 köprü** görevi görür. IP seviyesinde araya girmez (routing yapmaz).

---

## 4. USB Ethernet Adaptörlerinin Tanınması

Adaptörleri taktıktan sonra arayüzleri kontrol edin:

```bash
ip link show
```

Örnek çıktı:

```text
2: enx00e04c680001: <BROADCAST,MULTICAST,UP,LOWER_UP>
3: enx00e04c680002: <BROADCAST,MULTICAST,UP,LOWER_UP>
```

Bu makalede örnek olarak:

- `enx00e04c680001` → **ethA**
- `enx00e04c680002` → **ethB**

olarak ele alınacaktır.

---

## 5. Yazılımsal Switch (Linux Bridge) Oluşturma

### 5.1 Bridge Arayüzünü Oluşturma

```bash
sudo ip link add name br0 type bridge
```

### 5.2 Fiziksel Arayüzleri Bridge'e Ekleme

```bash
sudo ip link set enx00e04c680001 master br0
sudo ip link set enx00e04c680002 master br0
```

### 5.3 Arayüzleri Aktif Hale Getirme

```bash
sudo ip link set br0 up
sudo ip link set enx00e04c680001 up
sudo ip link set enx00e04c680002 up
```

Bu aşamadan sonra laptop, **tam işlevli bir Layer‑2 switch** gibi davranır.

> ⚠️ Bridge arayüzüne IP vermek zorunda değilsiniz. Trafik şeffaf akar.

---

## 6. Forwarding ve Kernel Ayarları

Layer‑2 bridge için IP forwarding zorunlu değildir, ancak bazı senaryolarda kapalı olması tercih edilir:

```bash
sudo sysctl -w net.ipv4.ip_forward=0
```

Bridge netfilter davranışını kontrol etmek için:

```bash
sysctl net.bridge.bridge-nf-call-iptables
```

Paketlerin iptables tarafından **etkilenmemesi** için genelde:

```bash
sudo sysctl -w net.bridge.bridge-nf-call-iptables=0
```

---

## 7. Paket Yakalama (Packet Capture)

### 7.1 Tüm Trafiği Bridge Üzerinden Yakalama

```bash
sudo tcpdump -i br0 -nn -e -w traffic.pcap
```

Bu yöntem:
- Her iki yöndeki trafiği
- MAC adresleri dahil
- Tek dosyada

yakalamanızı sağlar.

---

### 7.2 Fiziksel Arayüz Bazlı Yakalama

Ayrı ayrı görmek için:

```bash
sudo tcpdump -i enx00e04c680001 -nn -w sideA.pcap
sudo tcpdump -i enx00e04c680002 -nn -w sideB.pcap
```

Bu yöntem, **gelen / giden trafik ayrımı** yapmak için idealdir.

---

### 7.3 Wireshark ile Canlı Analiz

GUI ortamında:

```bash
sudo wireshark &
```

Ardından `br0` veya ilgili USB Ethernet arayüzünü seçebilirsiniz.

---

## 8. Performans ve Donanımsal Offload Konuları

USB Ethernet adaptörleri genellikle:

- Checksum offload
- TSO / GSO

gibi özellikler içerir. Paket analizinde **ham paket görmek** için bunları kapatmak önerilir:

```bash
sudo ethtool -K enx00e04c680001 gro off gso off tso off
sudo ethtool -K enx00e04c680002 gro off gso off tso off
```

---

## 9. Güvenlik ve Etik Uyarılar

⚠️ **Önemli:**

- Paket yakalama, **kişisel veri ve gizlilik** ihlallerine yol açabilir.
- Bu teknikler **yalnızca yetkili olduğunuz ağlarda** kullanılmalıdır.
- Kurumsal ortamlarda mutlaka yazılı izin alınmalıdır.

---

## 10. VLAN’lı (802.1Q) Trafik Yakalama

Kurumsal ağlarda trafik çoğunlukla **802.1Q VLAN etiketleri** ile taşınır. 
Linux bridge yapısı VLAN-aware olacak şekilde yapılandırılabilir ve VLAN etiketli trafik **etiketiyle birlikte** yakalanabilir.

### 10.1 VLAN Etiketlerinin Temel Mantığı

802.1Q standardında Ethernet frame içerisine **4 baytlık VLAN header** eklenir:

- VLAN ID (VID): 1–4094
- PCP (Priority Code Point): QoS önceliği
- DEI: Drop Eligible Indicator

Paket yakalama sırasında VLAN etiketlerini görebilmek için **link-layer bilgileriyle** capture yapılmalıdır.

---

### 10.2 Bridge’i VLAN-Aware Hale Getirme

Varsayılan Linux bridge VLAN-aware değildir. Aşağıdaki komut ile aktif edilir:

```bash
sudo ip link set br0 type bridge vlan_filtering 1
```

Durumu kontrol etmek için:

```bash
bridge vlan show
```

---

### 10.3 VLAN Trunk Port Yapılandırması

USB Ethernet adaptörlerinin trunk gibi davranmasını sağlamak için:

```bash
sudo bridge vlan add vid 10 dev enx00e04c680001
sudo bridge vlan add vid 20 dev enx00e04c680001
sudo bridge vlan add vid 10 dev enx00e04c680002
sudo bridge vlan add vid 20 dev enx00e04c680002
```

Bu yapı:
- VLAN 10 ve 20 trafiğinin
- Etiketleri korunarak
- Şeffaf biçimde karşı tarafa iletilmesini sağlar.

---

### 10.4 Native (Untagged) VLAN Tanımlama

Bir portta etiketlenmemiş trafiği belirli bir VLAN’a almak için:

```bash
sudo bridge vlan add vid 1 dev enx00e04c680001 pvid untagged
```

Bu ayar, klasik switch davranışını taklit eder.

---

### 10.5 VLAN Etiketli Trafik Yakalama (tcpdump)

#### Bridge Üzerinden

```bash
sudo tcpdump -i br0 -e -nn vlan
```

Örnek çıktı:

```text
12:01:10.123456 00:11:22:33:44:55 > 66:77:88:99:aa:bb, ethertype 802.1Q (0x8100), vlan 20, ethertype IPv4
```

#### Belirli VLAN’ı Filtrelemek

```bash
sudo tcpdump -i br0 -e -nn vlan 10
```

---

### 10.6 Wireshark ile VLAN Analizi

Wireshark otomatik olarak VLAN etiketlerini çözer:

- **VLAN ID**
- **Priority (PCP)**
- **Inner EtherType**

Filtre örnekleri:

- Sadece VLAN 20:
  ```
  vlan.id == 20
  ```

- VLAN + IP:
  ```
  vlan.id == 10 && ip
  ```

---

### 10.7 Offload ve VLAN Capture İlişkisi

Bazı NIC’lerde VLAN offload açıkken:
- VLAN etiketi kernel tarafından soyulabilir
- Capture sırasında görünmeyebilir

Bu durumda VLAN offload kapatılmalıdır:

```bash
sudo ethtool -K enx00e04c680001 rxvlan off txvlan off
sudo ethtool -K enx00e04c680002 rxvlan off txvlan off
```

---

### 10.8 VLAN Bazlı Ayrı Capture Dosyaları

Aynı anda farklı VLAN’ları ayrı dosyalara almak mümkündür:

```bash
sudo tcpdump -i br0 -e vlan 10 -w vlan10.pcap &
sudo tcpdump -i br0 -e vlan 20 -w vlan20.pcap &
```

Bu yöntem, büyük capture dosyalarını yönetilebilir hale getirir.

---

## 11. Gelişmiş Senaryolar (Opsiyonel)

- `ebtables` ile VLAN + MAC bazlı filtreleme
- `tc` ile VLAN başına trafik şekillendirme
- QinQ (802.1ad) analizleri
- IDS/IPS sistemlerinde VLAN-aware inspection

---
## 11. systemd ile Otomatik Bridge ve VLAN Kurulumu

Bu bölümde, sistem açılışında `br0` bridge arayüzünün ve bağlı USB Ethernet adaptörlerinin **otomatik olarak** yapılandırılmasını sağlayacağız.

### 11.1 systemd Unit Dosyası

Aşağıdaki unit dosyasını oluşturun:

```bash
sudo nano /etc/systemd/system/usb-bridge.service
```

İçerik:

```ini
[Unit]
Description=USB Ethernet Bridge (br0) with VLAN support
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/usb-bridge-up.sh
ExecStop=/usr/local/sbin/usb-bridge-down.sh

[Install]
WantedBy=multi-user.target
```

---

### 11.2 Bridge Up Script

```bash
sudo nano /usr/local/sbin/usb-bridge-up.sh
```

```bash
#!/bin/bash

ETH1=enx00e04c680001
ETH2=enx00e04c680002
BR=br0

ip link add name $BR type bridge vlan_filtering 1
ip link set $ETH1 master $BR
ip link set $ETH2 master $BR

ip link set $ETH1 up
ip link set $ETH2 up
ip link set $BR up

# VLAN trunk örneği
bridge vlan add vid 10 dev $ETH1
bridge vlan add vid 20 dev $ETH1
bridge vlan add vid 10 dev $ETH2
bridge vlan add vid 20 dev $ETH2
```

Yetkilendirme:

```bash
sudo chmod +x /usr/local/sbin/usb-bridge-up.sh
```

---

### 11.3 Bridge Down Script

```bash
sudo nano /usr/local/sbin/usb-bridge-down.sh
```

```bash
#!/bin/bash

BR=br0

ip link set $BR down
ip link delete $BR type bridge
```

```bash
sudo chmod +x /usr/local/sbin/usb-bridge-down.sh
```

---

### 11.4 Servisi Aktifleştirme

```bash
sudo systemctl daemon-reload
sudo systemctl enable usb-bridge.service
sudo systemctl start usb-bridge.service
```

Durum kontrolü:

```bash
systemctl status usb-bridge.service
```

---

## 12. NetworkManager ile Bridge Entegrasyonu

GUI veya CLI üzerinden yönetim isteniyorsa **NetworkManager** tercih edilebilir.

### 12.1 nmcli ile Bridge Oluşturma

```bash
nmcli connection add type bridge ifname br0 con-name br0
```

### 12.2 USB Ethernet Arayüzlerini Bridge’e Ekleme

```bash
nmcli connection add type ethernet ifname enx00e04c680001 master br0
nmcli connection add type ethernet ifname enx00e04c680002 master br0
```

### 12.3 VLAN Tanımları (NetworkManager)

```bash
nmcli connection add type vlan con-name vlan10 ifname br0.10 dev br0 id 10
nmcli connection add type vlan con-name vlan20 ifname br0.20 dev br0 id 20
```

### 12.4 Bağlantıları Aktif Etme

```bash
nmcli connection up br0
nmcli connection up vlan10
nmcli connection up vlan20
```

> ℹ️ NetworkManager, VLAN etiketlerini kernel seviyesinde yönetir; tcpdump ve Wireshark ile capture mümkündür.

---

## 13. systemd mi NetworkManager mı?

| Kriter | systemd Script | NetworkManager |
|------|---------------|----------------|
| Headless sunucu | ✅ | ⚠️ |
| GUI yönetim | ❌ | ✅ |
| Deterministik boot | ✅ | ⚠️ |
| Lab / taşınabilirlik | ✅ | ✅ |

---

## 14. Genel Değerlendirme

Bu makalede:

- Bir laptopun **iki USB Ethernet adaptörü ile yazılımsal switch** olarak nasıl çalıştırılacağını
- Bu switch üzerinden geçen **tüm trafiğin şeffaf biçimde nasıl yakalanacağını**
- Performans, güvenlik ve pratik ipuçlarını
- Açılışta otomatik kurulan
- VLAN-aware
- Paket yakalamaya hazır
- Taşınabilir ve profesyonel


detaylı olarak inceledik.

Bu yaklaşım, düşük maliyetli ama son derece güçlü bir **taşınabilir network analiz platformu** sunar.

---