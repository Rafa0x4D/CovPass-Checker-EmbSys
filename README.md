# CovPass-Checker-EmbSys
# Usage
- clone Buildroot repo
- move `overlay` folder from this repo to buildroot home dir
- replace `.config` from buildroot home dir with `.config`  from this repo
- compile the system 

OS-Creds:
- user: `root`
- pw: `Geheim!`

AP-Creds:
- SSID: `Team01`
- pw: `Embedded-Sys2`

AP-Info:
- AP-IP (Gateway): `10.1.0.1`
- DHCP range: `10.1.0.10` - `10.1.0.100`

---

# Voraussetzungen
Programme:
- git
- make
- dd (andere Möglichkeiten: Raspberry PI Imager; Rufus; Balena Etcher)
- todo

---

# Buildroot
Buildroot Repo klonen:
```bash
git clone git://git.buildroot.net/buildroot
```

zu Builtroot dir wechseln:
```bash
cd buildroot
```

Standard Konfig für RaspberryPi4 64 bit erstellen:
```bash
make raspberrypi4_defconfig
```

Die Konfiguration wird in die Datei `buildroot/.config` geschriebnen

aus dieser Konf-Datei ein Image erstellen (`-j8`: benutze 8 CPU Kerne):
```bash
make -j8
```

**ACHTUNG**: dieser Prozess kann beim erstem Mal etwa bis zu xy minuten dauern (36 min)

Das Image wird mit dem Namen `sdcard.img` in `buildroot/output/images` angelegt

Das image auf die SD-Karte schreiben:
```bash
sudo dd if=sdcard.img of=/dev/<dev-name> bs=1m
```

Login-Daten standard: user: root password: kein festgelegt

---

## Buildroot: menuconfig
### overlay aktivieren
es gibt mehrere Möglichkeiten das Root-Dateisystem zu bearbeiten, z.B. overlays  (`BR2_ROOTFS_OVERLAY`) oder Post-build skripte (`BR2_ROOTFS_POST_BUILD_SCRIPT`)

Overlay aktivieren:
```txt
System configuration -> Root filesystem overlay directories 
```
als Direktory den pfad oder Ordnername eingben `overlay` (`BR2_ROOTFS_OVERLAY=”overlay”`)

ordner `overlay` in `buildroot` erstellen

---

### Hostname ändern 
(`BR2_TARGET_GENERIC_HOSTNAME`)
```
System Configuration -> System hostname
```

---

### Root Passwort festlegen
```
System configuration -> Root password
```

---

### System Banner
```
System configuration -> System banner
```

---

### SSH aktivieren (dropbear)
kleiner und einfacher SSH-Server

```
Target Packages -> Networking applications -> dropbear
```

---

## WiFi aktivieren
Broadcom Wireless Treiber automatisch laden
(`BR2_ROOTFS_DEVICE_CREATION_DYNAMIC_MDEV = y`)
```
System configuration -> /dev management -> Dynamic using devtmpfs + mdev
```

RaspberryPi WiFi-Firmware aktivieren
(`BR2_PACKAGE_RPI_WIFI_FIRMWARE = y`)
```
Target packages -> Hardware handling -> Firmware -> rpi-wifi-firmware
```

WPA-Supplicant installieren, um sich mit WiFi verbinden zukönnen:
(`BR2_PACKAGE_WPA_SUPPLICANT = y`)
```
Target packages -> Networking applications -> wpa_supplicant
```

aktuellen Wireless API für Linux auswählen:
(`BR2_PACKAGE_WPA_SUPPLICANT_NL80211 = y`)
```
Target packages -> Networking applications -> wpa_supplicant -> Enable nl80211 support
```

Um es möglich zu machen sich auch mit anderen WiFi-Netzwerke zu verbinden muss WPA-Passphrase installiert werden:
(`BR2_PACKAGE_WPA_SUPPLICANT_PASSPHRASE = y`)
```
Target packages -> Networking applications -> wpa_supplicant -> Install wpa_passphrase binary
```

Eine Datei `interfaces` in `buildroot/overlay/etc/network/` mit folgendem Inhalt erstellen. Das ist eine Konfiguration für die Interfaces auf dem Raspi:
```
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet dhcp
    pre-up /etc/network/nfs_check
    wait-delay 15
auto wlan0
iface wlan0 inet dhcp
    pre-up wpa_supplicant -B -Dnl80211 -iwlan0 -c/etc/wpa_supplicant.conf
    post-down killall -q wpa_supplicant
    wait-delay 15
iface default inet dhcp
```

Eine andere Datei `wpa_supplicant.conf` für Passphrase in `buildroot/overlay/etc/network/` mit folgendem Inhalt erstellen:
```
network={
    ssid="<SSID>"
    psk="<Passwort>"
}
```

Folgenden Befehlen / Zeilen an der Datei `buildroot/board/raspberrypi/post-build.sh` anhängen:
```bash
cp package/busybox/S10mdev ${TARGET_DIR}/etc/init.d/S10mdev
chmod 755 ${TARGET_DIR}/etc/init.d/S10mdev
cp package/busybox/mdev.conf ${TARGET_DIR}/etc/mdev.conf
``` 

---

## WiFi Access-Point erstellen
Hardening Option RELRO zu Partial setzen:
(`BR2_RELRO_PARTIAL = y`)
```
Build options -> RELRO Protection -> Partial
```

alle Pakete die von BusyBox angeboten werden anzeigen
(`BR2_PACKAGE_BUSYBOX_SHOW_OTHERS = y`)
```
Target packages -> BusyBox -> Show packages that are also provided by busybox
```

Alle  DHCP Pakete installieren (server, client, relay, dhcpd) und delayed acknowledge feature aktivieren
(`BR2_PACKAGE_DHCP = y`)
(`BR2_PACKAGE_DHCP_SERVER = y`)
(`BR2_PACKAGE_DHCP_SERVER_DELAYED_ACK = y`)
(`BR2_PACKAGE_DHCP_CLIENT = y`)
(`BR2_PACKAGE_DHCPCD = y`)
```
Target packages -> Networking applications -> dhcp (ISC)
Target packages -> Networking applications -> dhcp (ISC) -> dhcp server
Target packages -> Networking applications -> dhcp (ISC) -> dhcp server -> Enable delayed ACK feature
Target packages -> Networking applications -> dhcp (ISC) -> dhcp client
Target packages -> Networking applications -> dhcpcd
```

um nftables compat aktivieren zu können muss folgender toolchain installiert werden:
```
Toolchain -> Enable WCHAR support
```

Iptables aktivieren (Firewall)
(`BR2_PACKAGE_IPTABLES = y`)
(`BR2_PACKAGE_IPTABLES_BPF_NFSYNPROXY = y`)
```
Target packages -> Networking applications -> iptables
Target packages -> Networking applications -> iptables -> bpfc and nfsynproxy
Target packages -> Networking applications -> iptables -> nftables compat
```

Access Point Mode aktivieren
(`BR2_PACKAGE_WPA_SUPPLICANT_AP_SUPPORT = y`)
```
Target packages -> Networking applications -> wpa_supplicant -> Enable AP mode
```

Die Interface-Einstellungen müssen manuell festgelegt werden. Die Datei `buildroot/overlay/etc/network/interfaces` wie folgt editieren:
```
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet dhcp
    pre-up /etc/network/nfs_check
    wait-delay 15
auto wlan0
iface wlan0 inet static
    address 10.1.0.1
    netmask 255.255.255.0
    network 10.1.0.0
    gateway 10.1.0.1
    pre-up wpa_supplicant -B -Dnl80211 -iwlan0 -c/etc/wpa_supplicant.conf
    post-down killall -q wpa_supplicant
    wait-delay 15
iface default inet dhcp
```

Die WPA-Supplicant-Einstellungen ändern. Die Datei `buildroot/overlay/etc/wpa_supplicant.conf` wie folgt ändern. `mode=2` ist Access Point mode:

**ACHTUNG**: Das Passwort (`psk`) muss mind. 8 Zeichen lang sein, sonst funktioniert der AP nicht

```
network={
    ssid="Team01"
    mode=2
    proto=RSN
    key_mgmt=WPA-PSK
    pairwise=CCMP TKIP
    group=CCMP TKIP
    psk="Embedded-Sys2"
}
```

für DHCP einstellungen die Datei `buildroot/overlay/etc/dhcp/dhcpd.conf` mit folgendem Inhalt anlegen:
```
ddns-update-style none;
default-lease-time 600;
max-lease-time 7200;
authoritative;
log-facility local7;

subnet 10.1.0.0 netmask 255.255.255.0 {
  range 10.1.0.10 10.1.0.100;
  option broadcast-address 10.1.0.255;
  option routers 10.1.0.1;
  default-lease-time 600;
  max-lease-time 7200;
  option domain-name "local";
  option domain-name-servers 8.8.8.8, 8.8.4.4;
}
```

Eine Datei `sysctl.conf` in `buildroot/overlay/etc/` mit folgendem Inhalt erstellen:
```
# Enable IP forwarding.
net.ipv4.ip_forward = 1
```

Um Sysctl nach jenden Boot und Shutdown automatisch einstellen zu können erstelle die Datei `S02procps` in `buildroot/overlay/etc/init.d`. Die Datei hat folgendem Inhalt. Das ist eine Ausführbarer Shell-Skript:

```sh
#! /bin/sh
if [ "$1" == "start" ]; then
    sysctl -p
fi
```

Um Firewall (iptables) zu konfigurieren, muss die Datei `S99firewall` in `buildroot/overlay/etc/init.d` des Images erstellt werden. Die Datei hat folgendem Inhalt. DAs ist eine Ausführbarer Shell-Skript. Um es nach jedem Boot-Operation automatisch starten zu können, muss es in den `/etc/init.d` ordner erstellt werden:

```sh
#! /bin/sh
if [ "$1" == "start" ]; then
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables -P FORWARD DROP
    iptables -A FORWARD -i eth0 -o wlan0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
    iptables -P INPUT DROP
    iptables -A INPUT -i eth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i wlan0 -j ACCEPT
fi
```
