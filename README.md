# all-lpe-collection — Compiled & Annotated

Koleksi 44 exploit Linux LPE (2016–2026) + hasil compile lengkap di `bin/` (75 artefak, semua tervalidasi ELF).
Toolchain: Kali WSL2, GCC 15.2 / musl-gcc 1.2.5, target x86_64. Detail proses build: `SUMMARY.md`.

> **Tujuan:** pembelajaran & testing pada sistem yang Anda miliki otorisasi. Kernel exploit umumnya crash / panic — jangan jalankan di mesin produksi.

---

## Matriks Kernel per CVE

**Cara pakai:** jalankan `uname -r` di target, cocokkan kolom "Kernel affected". Kolom "Fix" = versi/commit pertama yang sudah aman. Kolom "Target PoC" = kernel yang dipakai penulis exploit (paling reliability).

### Kernel-exploit (bug ada di kernel Linux)

| CVE | Komponen | Kernel affected | Fixed sejak | Target PoC (teruji) | Prasyarat penting |
|-----|----------|-----------------|-------------|---------------------|-------------------|
| CVE-2016-0728 | keyring GC UAF | ~3.8 – 4.3 | Jan 2016 (4.4) | Ubuntu 14.04 3.13/3.16, Debian | — |
| CVE-2016-2384 | snd-usbmidi (USB) | semua ≤ fix Feb 2016 (4.5-rc) | 4.5.2+ | Ubuntu 14.04/16.04 | butuh **akses fisik USB** + device MIDI crafted |
| CVE-2016-4557 | keyctl/update_process_cred | 4.4 – 4.5.5 | 4.5.7+ | — | — |
| CVE-2016-4997 | netfilter (target off-by-one) | 4.4.0 (juga 4.5.x) | 4.7 (Jul 2016) | Ubuntu 16.04 4.4.0-21 | exploit decr + pwn dipisah di `bin/` |
| CVE-2016-5195 | Dirty Cow (mm) | **2.6.22 – 4.8.3** | 4.8.3 (Okt 2016) | luas, 10 tahun kernel | race; `dirty` pakai -lcrypt |
| CVE-2016-8655 | AF_PACKET race | Ubuntu 4.4.0 < 4.4.0-53.74; umum ≤ 4.9 pre-Nov-2016 | Nov 2016 | Ubuntu 14.04/16.04, Mint | KASLR+SMEP bypass; tanpa SMAP |
| CVE-2016-9793 | SO_BUSY_POLL BPF | ≤ 4.9 pre-Feb-2017 | 4.9.x (Feb 2017) | Ubuntu 16.04 | perlu `sysctl -w kernel.unprivileged_userns_clone=1` era lama |
| CVE-2017-1000112 | UFO check (net) | ≤ 4.13 pre-Okt-2017 | 4.13.x (Okt 2017) | Ubuntu 16.04/17.04 | — |
| CVE-2017-1000253 | stack expand down (PIE) | CentOS/RHEL 7: 3.10.0-514.21.2, 3.10.0-514.26.1 | Sep 2017 | CentOS 7 | binary `42887` sudah embed rootshell |
| CVE-2017-11176 | POSIX mq_notify UAF | ~4.9 – 4.11 (pre-Jun-2017) | 4.12-rc (Jun 2017) | kernel 4.10.7 | `-include signal.h` sudah di-flag build |
| CVE-2017-16939 | XFRM netlink UAF | ≤ 4.13/4.14-rc pre-Nov-2017 | 4.14-rc8 | Debian/Ubuntu era 4.10–4.13 | — |
| CVE-2017-16995 | eBPF 32-bit ALU | **4.4 – 4.14** | 4.14.x (Nov 2017) | Ubuntu 16.04.3 4.4.0-87, Debian 9 | sangat reliable di 4.4–4.10 |
| CVE-2017-5123 | waitid infoleek | **4.14.0-rc4+** (baru) | 4.14 (Nov 2017) | 4.14-rc | — |
| CVE-2017-6074 | DCCP UAF | ~2.6.18 – 4.9.10 | 4.9.10 (Feb 2017) | Ubuntu 12.04/14.04/16.04 | SMEP/SMAP bypass semi-reliable; `trigger` = helper crash-trigger |
| CVE-2017-7308 | AF_PACKET TPACKET_V3 | ~3.2 – 4.10.x pre-Apr-2017 | 4.11-rc (Apr 2017) | Ubuntu 16.04 4.8/4.10 | butuh CAP_NET_RAW di userns |
| CVE-2017-8890 | Phoenix Talon (inet sk race) | ~4.5 – 4.11 pre-May-2017 | 4.12-rc | Ubuntu 17.04 4.10 | 2 varian: ret2usr & smep |
| CVE-2018-5333 | RDS rds_atomic_free_op | ≤ 4.14.13 | 4.15-rc | Ubuntu 16.04 4.4.0-116 / 4.8.0-54 | modul `rds.ko` harus di-load (biasanya blacklisted) |
| CVE-2018-17182 | VMA cache UAF | **3.16 – 4.18.8** | 4.18.9 / 4.14.71 / 4.9.128 / 4.4.157 | Ubuntu 18.04 4.15.0-34 | suite: `vma_test` (cek), `puppeteer` (driver), `puppet` (nostdlib), `suidhelper` |
| CVE-2018-18955 | userns map_write | **4.15.x – 4.19.x < 4.19.2** | 4.19.2 (Nov 2018) | Ubuntu 18.04/18.10 | butuh uid/gid mapping (subuid); 5 vektor script |
| CVE-2019-13272 | PTRACE_TRACEME | **4.10 < 5.1.17** | 5.1.17 (Jul 2019) | Ubuntu 16.04/18.04 | butuh PolKit agent aktif; yama.ptrace_scope < 2 |
| CVE-2021-22555 | netfilter x_tables OOB | **2.6.19-rc1 – 5.12.x** | 5.13-rc (Jul 2021) | Ubuntu 20.04 (5.4), 21.04 (5.11) | KASLR+SMEP+SMAP bypass; butuh unprivileged userns |
| CVE-2021-27365 | iSCSI heap overflow | RHEL 8.1/8.2/8.3 (4.18.0-240.el8 era) | Mar 2021 | RHEL 8.x | `exploit` + `send_pdu_oob`; symbols per-kernel |
| CVE-2021-31440 | eBPF verifier (Pwn2Own) | **5.7 – 5.11.15** | 5.12-rc (Apr 2021) | Ubuntu 21.04 5.11 | 2 varian exploit |
| CVE-2021-3490 | eBPF alu32 bounds | Ubuntu 20.10: 5.8.0-25→52; 21.04: 5.11.0-16→17 | Ubuntu patch Jun 2021 | Ubuntu 20.10/21.04 | `exit` dulu dari root shell — kalau tidak → kernel panic |
| CVE-2021-3493 | overlayfs (Ubuntu-only) | Ubuntu 20.04/20.10/21.04 pre-Agu-2021 (5.4/5.8/5.11) | USN-5016-1 (Agu 2021) | Ubuntu 20.04+ | — |
| CVE-2021-41073 | io_uring (NOP) | **5.10 – 5.14.6** | 5.14.7 / 5.13.16 / 5.10.65 | Ubuntu 21.04/21.10 5.13 | butuh FUSE (`hello.c` di-link); exit bersih |
| CVE-2021-4154 | file userns refcount | lihat kolom target | patch kernel fix 3b04627 | CentOS 8 >4.18.0-305.el8; Debian 11 >5.10.0-8; Fedora 31/32/33 >5.3.7-301; Ubuntu 18/20 >5.4.0-84, >5.11.0-37.41 | 2 varian: exp & kctf_exp |
| CVE-2021-42008 | 6pack SLIP OOB | Debian 11: 5.10.0-8-amd64 (umum ≤5.14 pre-Okt-2021) | 5.14.13 / 5.10.70 | Debian 11 | butuh modul 6pack + CAP_NET_ADMIN di userns |
| CVE-2021-43267 | TIPC heap overflow | **5.10 – 5.15** | 5.15 / 5.14.15 (Nov 2021) | Ubuntu/Debian 5.15 | modul tipc (autoload); versi ini versi **remote**, LPE jika lokal |
| CVE-2022-2586 | nf_tables nft_object UAF | ~5.9 – 5.19.x | 5.19.9 / 5.15.68 (Sep 2022) | Ubuntu 22.04 5.15.x | unprivileged userns + nf_tables |
| CVE-2023-0386 | overlayfs copy_up | **5.11 – 6.2.2** (Mar 2023) | 6.2.2 / 6.1.10 / 5.15.94 | Ubuntu 22.04 5.15/5.19, Debian 6.1 | 2 terminal: `fuse` dulu, lalu `exp`; test suite ada |
| CVE-2024-1086 | nf_tables use-after-free | **v5.14 – v6.6** (kecuali patch: ≥5.15.149, ≥6.1.76, ≥6.6.15) | Feb 2024 | Debian/Ubuntu/KernelCTF | userns + nf_tables; TIDAK jalan jika `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` (Ubuntu 6.5); panic setelah sukses |
| CVE-2026-31431 | "Copy Fail" — AF_ALG authencesn + splice | **kernel build 2017 – Apr 2026** (commit 72548b093ee3 → fix a664bf3d603d) | mainline 1 Apr 2026; vendor update menyusul | Ubuntu 24.04 (6.17-aws), Amazon Linux 2023, RHEL 10.1, SUSE 16 | AF_ALG enabled (default semua distro); 4-byte page-cache write; container escape; Ubuntu 26.04+ aman |
| CVE-2026-43500 | "Dirty Frag" — RxRPC in-place decrypt | kernel ≥ commit 2dc334f1a63a (**2023-06-08 – 2026-05-10**) | aa54b1d27fe0 (10 Mei 2026) | distro dengan rxrpc.ko (default Ubuntu) | butuh rxrpc.ko; sering di-chain dengan CVE-2026-43284 (xfrm-ESP, kernel ≥2017-01-17, fix 8 Mei 2026, butuh userns) |

### App-level exploit (kernel TIDAK berpengaruh — cocokkan versi aplikasinya)

| CVE | Aplikasi | Versi affected | Catatan |
|-----|----------|----------------|---------|
| CVE-2016-1531 | Exim | < 4.86.2 | env expansion; script bash |
| CVE-2016-6662 | MySQL/MariaDB | MySQL ≤5.5.51/5.6.32/5.7.14, MariaDB, Percona | butuh akses sebagai user DB / SQLi ke mysql; `mysql_hookandroot` + `mysql_hookandroot_lib.so` + driver python `0ldSQL_*` |
| CVE-2017-7494 | Samba | **3.5.0 – 4.6.4/4.5.10/4.4.14** | remote RCE (load module via SMB); python+metasploit |
| CVE-2017-1000367 | sudo | 1.8.20 & 1.8.3p6 era (get_process_ttyname) | butuh SELinux-enabled + sudo build dengan dukungan selinux |
| CVE-2018-14665 | X.Org server | < 1.20.3 (Linux); OpenBSD 6.3/6.4 | modulepath/-logfile abuse; script |
| CVE-2018-1000001 | glibc ld.so | glibc < 2.26 | `RationalLove`; butuh unprivileged userns |
| CVE-2019-10149 | Exim | **4.87 – 4.91** | remote RCE via recipient; python |
| CVE-2021-3156 | sudo | **1.8.2 – 1.9.5p2** (Baron Samedit) | cek: `sudoedit -s Y`; `exploit` + payload `libnss_x/x.so.2` (harus tetap sefolder!) |
| CVE-2021-4034 | polkit pkexec | < 0.120 (PwnKit) | `pwnkit.so` = shared object payload — cara deploy lihat bawah |
| CVE-2025-32463 | sudo | **1.9.14 – 1.9.17p1** (chroot) | `sudo --chroot` + /etc/nsswitch; script |

---

## Cara cek target

```bash
uname -r                      # versi kernel
cat /etc/os-release           # distro
sysctl kernel.unprivileged_userns_clone 2>/dev/null   # buat exploit userns (2016-9793, 2021-22555, 2022-2586, 2024-1086)
sysctl kernel.yama.ptrace_scope                          # buat CVE-2019-13272 (harus < 2)
lsmod | grep -E "rds|tipc|rxrpc|6pack"                   # modul yang dibutuhkan beberapa exploit
ls /boot/System.map-$(uname -r) 2>/dev/null              # beberapa exploit butuh symbol
```

Kernel Debian/Ubuntu: `5.15.0-XX-generic` → patch-level `-XX` menentukan vulnerable atau tidak; cocokkan dengan kolom "Target PoC" / rentang patch di atas.

## Struktur bin/

- `bin/<CVE>/<nama>` — satu binary per entry-point exploit (static jika bisa).
- Nama `poc`, `exploit`, `exp` mengikuti nama asli repo masing-masing.
- CVE-2016-4997: file asli berisi 2 exploit digabung → di-split jadi `40049-decr` & `40049-pwn`.
- CVE-2021-3156: jalankan dari folder yang berisi `libnss_x/x.so.2` (payload) — jangan dipindah sendirian.
- CVE-2023-0386: dua terminal — `./fuse ./ovlcap/lower ./gc` lalu `./exp` (lihat README asli). `fuse` di-link dengan libfuse 2.9.9 custom (`/usr/local/lib/libfuse.so.2`).
- CVE-2021-4034: `pwnkit.so` BUKAN executable — deploy: buat dir `GCONV_PATH=.`, salin `pwnkit.so` → `pwnkit/gconv-modules` setup, trigger `pkexec` (lihat README asli PwnKit).
- CVE-2018-18955: `libsubuid.so` = payload preload; `subuid_shell`/`subshell` = driver; pilih 1 dari 5 script varian sesuai vektor.
- CVE-2017-1000253: `42887` sudah mengandung rootshell (embedded) — tidak butuh file lain.
- CVE-2018-17182: urutan: `vma_test` (verifikasi), `puppeteer` (eksploit), `suidhelper` (suid helper), `puppet` (raw stub).
- `vmacache_helper.c` (CVE-2018-17182) **tidak dcompile**: kernel module — butuh kernel headers target (`make -C /lib/modules/$(uname -r)/build M=$PWD`).

## Build scripts

| Script | Fungsi |
|--------|--------|
| `build_all.sh` | bulk build (musl static → fallback glibc) |
| `build_fix.sh` … `build_fix8.sh` | perbaikan bertahap (multi-file, split, stub header, C23 downgrade) |
| `build_full.sh` | audit komplet — helper, test suite, script varian |
| `build_fuse2.sh` | build libfuse 2.9.9 dari source (fuse3 tidak kompatibel) |
| `verify_bin.py` | validasi magic ELF + coverage |
| `build_results.csv` | log status semua attempt |

## Catatan umum

- GCC ≥ 14 default C23 → exploit lama butuh `-std=gnu11 -Wno-error=int-conversion -Wno-error=incompatible-pointer-types -Wno-error=return-mismatch`.
- Beberapa exploit lama (2016–2017) pakai hardcoded kernel symbol — cek header `.c` jika target berbeda dari "Target PoC".
- Kernel exploit bisa panic. Uji di VM snapshot.
- Referensi lengkap tiap CVE ada di `CVE-*/README.md` asli repo.
