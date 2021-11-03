# CovPass-Checker-EmbSys
# Infos
OS-Creds:
- user: `root`
- pw: `test`

WiFi-Creds:
- SSID: `Team01`
- pw: `Embedded-Sys2`

AP-Info:
- AP-IP (Gateway): `10.1.0.1`
- DHCP range: `10.1.0.2` - `10.1.0.254`

Video stream infos:
- Address `10.1.0.1:8080`
---

# Requiements
- git
- make
- gcc
- g++
- unzip
- libncurses-dev

---

# Usage
Clone Buildroot Repo:
```bash
git clone git://git.buildroot.net/buildroot
```

Checkout version Buildroot Version `2021.02.6`
```bash
cd buildroot
git checkout 2021.02.6
```

Copy `overlay` folder from this repo to Buildroot dir

Copy `post-build.sh`from this repo to Buildroot dir

Replace `.config` from Buildroot dir with `.config`  from this repo



Compile with xy-CPUs
```bash
make -j<cpu>
```

Compile with max available CPUs:
```bash
make -j$(nproc)
```

After successflly completed Build, the Image will be saved in `buildroot/output/images/sdcard.img`

write the image to a sdcard using `dd`:
```bash
sudo dd if=sdcard.img of=/dev/<dev-name> bs=1m
```