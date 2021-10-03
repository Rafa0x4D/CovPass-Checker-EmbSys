# CovPass-Checker-EmbSys
# Usage
- clone Buildroot repo
- move `overlay` folder from this repo to buildroot home dir
- replace `.config` from buildroot home dir with `.config`  from this repo
- compile the system 

OS-Creds:
- user: `root`
- pw: `test`

AP-Creds:
- SSID: `Team01`
- pw: `Embedded-Sys2`

AP-Info:
- AP-IP (Gateway): `10.1.0.1`
- DHCP range: `10.1.0.2` - `10.1.0.254`

---

# Voraussetzungen
Programme:
- git
- make
- dd (andere Möglichkeiten: Raspberry PI Imager; Rufus; Balena Etcher)
- gcc
- g++
- unzip
- libncurses-dev

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

**HINWEIS**: um mit mehr als en Kern kompilieren zu können muss folgender Eintrag in `.config` gesetzt werden:
```txt
BR2_PER_PACKAGE_DIRECTORIES=y
```

**ACHTUNG**: dieser Prozess kann beim erstem Mal etwa bis zu xy minuten dauern (36 min)

Das Image wird mit dem Namen `sdcard.img` in `buildroot/output/images` angelegt

Das image auf die SD-Karte schreiben:
```bash
sudo dd if=sdcard.img of=/dev/<dev-name> bs=1m
```

Login-Daten standard: user: root password: test

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

### Root-Dateisystem vergrößern
```
BR2_TARGET_ROOTFS_EXT2_SIZE="3G"
```
---

### Toolchain
Toolchain -> cLibrary -> gLibc 

Um später opencv zu nutzen muss in der Toolchain gLibc ausgewählt werden. 

---

### erweiterte Firmware aktiviere
wird dann für die Nutzung der Kamera benötigt

target packaes -> hardware handling -> firmware -> rpi firmware -> firmware to boot -> extended

---

### SSH aktivieren (dropbear)
kleiner und einfacher SSH-Server

```
Target Packages -> Networking applications -> dropbear
```

---

# WiFi aktivieren

Wird mittels dnsmasq und hostapd umgesetzt. 

```
Target Packages -> Networking applications -> dnsmasq
```

```
Target Packages -> Networking applications -> hostapd
```

Für beide Pakete müssen im Overlay Ordner unter /etc/ Konfigurationsdateien abgelegt werden. 

``` 
dnsmasq.conf

interface=wlan0 # Listening interface
dhcp-range=10.1.0.2,10.1.0.254,255.255.255.0,24h 
domain=wlan0     
address=/gw.wlan/10.1.0.1
```

``` 
hostapd.conf

country_code=DE
interface=wlan0
ssid=Team01
hw_mode=g
channel=7
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=Embedded-Sys2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```
Zur Konfiguration der Netzwerk-Interfaces im Overlay Ordner unter /etc/network/interfaces folgende Datei ablegen

``` 
auto lo

auto eth0
iface eth0 inet dhcp
    wait-delay 15

auto wlan0
iface wlan0 inet static
    address 10.1.0.1
    netmask 255.255.255.0
    network 10.1.0.0
    gateway 10.1.0.1
iface default inet dhcp

```

Damit Hostapd beim booten automatisch startet muss ein init skript angelegt werden. Das Skript wird dann unter /etc/init.d/S90hostapd im Overlay Ordner angelegt. 

```sh
#!/bin/sh

start(){
        echo "Starting hostapd"
        hostapd -B /etc/hostapd.conf
        [ $? -eq 0 ] && echo "OK" || echo "Error"
}

stop(){
        echo "Stopping Hostapd"
        killall hostapd
        [ $? -eq 0 ] && echo "OK" || echo "Error"
}

restart(){
        stop
        start
}

case "$1" in
  start|stop|restart)
        "$1"
        ;;
  *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
esac

exit $?
```

Das Skript muss dann per chmod +x ausführbar gemacht werden. 

Zum schluss muss das post-build skript angepasst werden. 
buildroot/boards/raspberrypi/post-build.sh

Am ende des Skript anfügen


---

# Python aktivieren

make menuconfig
```
-> target packages -> Interpreter Languages und scripting -> python3
```

---

## zlib installieren
(`BR2_PACKAGE_PYTHON3_ZLIB=y`)

```
-> target packages -> Interpreter Languages und scripting -> python3 --> core python3 modules --> zlib module
```

---

## Cbor2 installieren
(`BR2_PACKAGE_PYTHON_CBOR2=y`)

```
-> target packages -> Interpreter Languages und scripting -> python3 --> External python modules --> python-cbor2
```

---

## Cbor2 installieren
(`BR2_PACKAGE_PYTHON_CRYPTOGRAPHY=y`)

```
-> target packages -> Interpreter Languages und scripting -> python3 --> External python modules --> python-cryptography
```

---

## Opencv und zbar (TODO)
Opencv kann ohne Probleme installiert werden allerdings wird für das Python Modul glibc benötigt. 

make menuconfig -> toolchain -> c library, glibc auswählen

WICHTIG: Wenn Optionen in der Toolchain geändert werden muss erst make clean ausgeführt werden. Das Image muss dann komplett von vorne neu gebaut werden. 

Für Opencv und zbar (c libarary für pyzbar):
make menuconfig:
target packages -> libraries -> graphics -> opencv3 -> python

target packages -> libraries -> graphics -> zbar

---

## Pyzbar Python Module installieren (TODO)

Das Modul kann per pip lokal installiert werden. Das Paket befindet sich dann unter (Kubuntu) .local/lib/python3.8/site-packages/pyzbar

Von dort kann das modul in den overlay Ordner kopiert werden. 

```sh
cp .local/lib/python3.8/site-packages/pyzbar buildroot/overlay/
```

Das kann so theoretisch auch mit allen anderen Modulen gemacht werden. 

Alternativ über ein venv probieren