// C STD lib includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <utmpx.h>
#include <pwd.h>
#include <dirent.h>

// C++ STD lib includes
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <sstream>

// APP includes
#include "common.h"
#include "collect.h"
#include "scan.h"
#include "hooks.h"

static std::string ReadSmallFile(const std::string &fname)
{
  std::string data;
  ReadWholeFile(fname, data);
  return Trim(data);
}

static std::string TimeText(long long t)
{
  time_t tt = (time_t)t;
  struct tm tmv;
  localtime_r(&tt, &tmv);
  char buf[64];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", &tmv);
  return buf;
}

int get_system_info(std::string &output)
{
  output.clear();
  std::map<std::string, std::string> os = ReadOsRelease();
  output += "os_name=" + QuoteValue(os["PRETTY_NAME"].empty() ? os["NAME"] : os["PRETTY_NAME"]) + "\n";
  output += "os_id=" + os["ID"] + "\n";
  output += "os_version=" + os["VERSION_ID"] + "\n";

  struct utsname u;
  if(uname(&u) == 0) {
    output += "kernel=" + std::string(u.release) + "\n";
    output += "arch=" + std::string(u.machine) + "\n";
  }

  char fqdn[256] = "";
  if(gethostname(fqdn, sizeof(fqdn)) == 0) {
    fqdn[sizeof(fqdn) - 1] = '\0';
    output += "hostname=" + std::string(fqdn) + "\n";
  }

  // Hardware from the DMI tables. product_serial is readable by root only.
  std::string vendor = ReadSmallFile("/sys/class/dmi/id/sys_vendor");
  std::string product = ReadSmallFile("/sys/class/dmi/id/product_name");
  std::string serial = ReadSmallFile("/sys/class/dmi/id/product_serial");
  std::string asset = ReadSmallFile("/sys/class/dmi/id/chassis_asset_tag");
  std::string bios = ReadSmallFile("/sys/class/dmi/id/bios_version");
  if(!vendor.empty()) output += "vendor=" + QuoteValue(vendor) + "\n";
  if(!product.empty()) output += "product=" + QuoteValue(product) + "\n";
  if(!serial.empty()) output += "serial_number=" + QuoteValue(serial) + "\n";
  if(!asset.empty()) output += "asset_tag=" + QuoteValue(asset) + "\n";
  if(!bios.empty()) output += "bios_version=" + QuoteValue(bios) + "\n";

  CommandResult r;
  std::string virt = FindProgram("systemd-detect-virt");
  if(!virt.empty()) {
    RunCommand({ virt }, 10, r);
    std::string v = Trim(r.out);
    output += "virtualization=" + (v.empty() ? std::string("none") : v) + "\n";
  }

  std::string machine_id = ReadSmallFile("/etc/machine-id");
  if(!machine_id.empty()) output += "machine_id=" + machine_id + "\n";

  // Time zone from the /etc/localtime link
  char link[512];
  ssize_t n = readlink("/etc/localtime", link, sizeof(link) - 1);
  if(n > 0) {
    link[n] = '\0';
    std::string tz = link;
    size_t p = tz.find("zoneinfo/");
    if(p != std::string::npos) tz = tz.substr(p + 9);
    output += "timezone=" + tz + "\n";
  }
  return 0;
}

int get_ip_addresses(std::string &output)
{
  output.clear();
  struct ifaddrs *ifa_list = NULL;
  if(getifaddrs(&ifa_list) != 0) {
    output = "ERROR - Could not list the network addresses\n";
    return 1;
  }
  for(struct ifaddrs *ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
    if(!ifa->ifa_addr || (ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP)) continue;
    int family = ifa->ifa_addr->sa_family;
    if(family != AF_INET && family != AF_INET6) continue;
    char host[NI_MAXHOST];
    socklen_t len = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    if(getnameinfo(ifa->ifa_addr, len, host, sizeof(host), NULL, 0, NI_NUMERICHOST) != 0) continue;
    std::string addr = host;
    size_t pct = addr.find('%');
    if(pct != std::string::npos) addr = addr.substr(0, pct);
    // Link local IPv6 addresses say nothing about where a host is
    if(family == AF_INET6 && StartsWith(ToLower(addr), "fe80:")) continue;
    output += "interface=" + std::string(ifa->ifa_name) + " family=" + (family == AF_INET ? "inet" : "inet6") +
      " address=" + addr + "\n";
  }
  freeifaddrs(ifa_list);
  return 0;
}

// cpu line of /proc/stat: user nice system idle iowait irq softirq steal
struct CpuTimes {
  unsigned long long v[8];
};

static bool ReadCpuTimes(CpuTimes &t)
{
  memset(&t, 0, sizeof(t));
  FILE *fp = fopen("/proc/stat", "r");
  if(!fp) return false;
  int n = fscanf(fp, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
		 &t.v[0], &t.v[1], &t.v[2], &t.v[3], &t.v[4], &t.v[5], &t.v[6], &t.v[7]);
  fclose(fp);
  return n >= 4;
}

static std::map<std::string, unsigned long long> ReadMeminfo()
{
  std::map<std::string, unsigned long long> m;
  std::string data;
  ReadWholeFile("/proc/meminfo", data);
  for(const std::string &line : Split(data, '\n')) {
    size_t c = line.find(':');
    if(c == std::string::npos) continue;
    m[line.substr(0, c)] = strtoull(line.c_str() + c + 1, NULL, 10); // kB
  }
  return m;
}

int get_performance(std::string &output, int cpu_sample_seconds)
{
  output.clear();
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
  output += "cpu_count=" + std::to_string(cpus) + "\n";

  // CPU use over the sample time from /proc/stat
  CpuTimes a, b;
  if(ReadCpuTimes(a)) {
    sleep((unsigned int)cpu_sample_seconds);
    if(ReadCpuTimes(b)) {
      unsigned long long d[8], total = 0;
      for(int i = 0; i < 8; i++) {
	d[i] = b.v[i] - a.v[i];
	total += d[i];
      }
      if(total > 0) {
	double idle = 100.0 * (double)(d[3] + d[4]) / (double)total;
	output += "cpu_used_pct=" + FormatPct(100.0 - idle) + "\n";
	output += "cpu_iowait_pct=" + FormatPct(100.0 * (double)d[4] / (double)total) + "\n";
	output += "cpu_steal_pct=" + FormatPct(100.0 * (double)d[7] / (double)total) + "\n";
      }
      output += "cpu_sample_seconds=" + std::to_string(cpu_sample_seconds) + "\n";
    }
  }

  double load[3];
  if(getloadavg(load, 3) == 3) {
    char buf[96];
    snprintf(buf, sizeof(buf), "load_1=%.2f\nload_5=%.2f\nload_15=%.2f\n", load[0], load[1], load[2]);
    output += buf;
  }

  std::map<std::string, unsigned long long> m = ReadMeminfo();
  unsigned long long total_mb = m["MemTotal"] / 1024;
  unsigned long long avail_mb = m["MemAvailable"] / 1024;
  output += "mem_total_mb=" + std::to_string(total_mb) + "\n";
  output += "mem_available_mb=" + std::to_string(avail_mb) + "\n";
  output += "mem_used_pct=" + FormatPct(total_mb ? 100.0 * (double)(total_mb - avail_mb) / (double)total_mb : 0.0) + "\n";
  unsigned long long swap_total_mb = m["SwapTotal"] / 1024;
  unsigned long long swap_used_mb = (m["SwapTotal"] - m["SwapFree"]) / 1024;
  output += "swap_total_mb=" + std::to_string(swap_total_mb) + "\n";
  output += "swap_used_mb=" + std::to_string(swap_used_mb) + "\n";
  output += "swap_used_pct=" + FormatPct(swap_total_mb ? 100.0 * (double)swap_used_mb / (double)swap_total_mb : 0.0) + "\n";

  // Processes: the numeric directories in /proc
  int procs = 0;
  DIR *dir = opendir("/proc");
  if(dir) {
    struct dirent *de;
    while((de = readdir(dir)) != NULL) {
      if(de->d_name[0] >= '0' && de->d_name[0] <= '9') procs++;
    }
    closedir(dir);
  }
  output += "process_count=" + std::to_string(procs) + "\n";

  std::string up = ReadSmallFile("/proc/uptime");
  if(!up.empty()) output += "uptime_seconds=" + std::to_string((long long)atof(up.c_str())) + "\n";
  return 0;
}

int get_disk_usage(std::string &output)
{
  output.clear();
  // Local disk file systems only: no network, memory or pseudo file systems
  static const std::set<std::string> local_fs = {
    "xfs", "ext2", "ext3", "ext4", "btrfs", "vfat", "zfs", "jfs", "reiserfs", "f2fs", "bcachefs"
  };
  std::string data;
  if(!ReadWholeFile("/proc/self/mounts", data)) {
    output = "ERROR - Could not read /proc/self/mounts\n";
    return 1;
  }
  std::set<std::string> seen_devices;
  for(const std::string &line : Split(data, '\n')) {
    std::istringstream in(line);
    std::string dev, mnt, fstype;
    if(!(in >> dev >> mnt >> fstype)) continue;
    if(local_fs.find(fstype) == local_fs.end()) continue;
    // Mount points have octal escapes for spaces (\040)
    std::string path;
    for(size_t i = 0; i < mnt.length(); i++) {
      if(mnt[i] == '\\' && i + 3 < mnt.length() + 0 && isdigit((unsigned char)mnt[i + 1])) {
	path += (char)strtol(mnt.substr(i + 1, 3).c_str(), NULL, 8);
	i += 3;
      }
      else {
	path += mnt[i];
      }
    }
    // A btrfs volume or bind mount shows up once per mount point, list each device once
    if(fstype != "btrfs" && !seen_devices.insert(dev).second) continue;
    struct statvfs sv;
    if(statvfs(path.c_str(), &sv) != 0 || sv.f_blocks == 0) continue;
    unsigned long long bs = sv.f_frsize ? sv.f_frsize : sv.f_bsize;
    unsigned long long size_mb = (unsigned long long)sv.f_blocks * bs / (1024 * 1024);
    unsigned long long free_mb = (unsigned long long)sv.f_bavail * bs / (1024 * 1024);
    unsigned long long used_mb = (unsigned long long)(sv.f_blocks - sv.f_bfree) * bs / (1024 * 1024);
    // Same rule as df: used / (used + available to users)
    double pct = (used_mb + free_mb) ? 100.0 * (double)used_mb / (double)(used_mb + free_mb) : 0.0;
    output += "mount=" + QuoteValue(path);
    output += " device=" + dev;
    output += " fstype=" + fstype;
    output += " size_mb=" + std::to_string(size_mb);
    output += " used_mb=" + std::to_string(used_mb);
    output += " free_mb=" + std::to_string(free_mb);
    output += " used_pct=" + FormatPct(pct);
    if(sv.f_files > 0) {
      double ipct = 100.0 * (double)(sv.f_files - sv.f_ffree) / (double)sv.f_files;
      output += " inodes_used_pct=" + FormatPct(ipct);
    }
    output += "\n";
  }
  return 0;
}

int get_network_stats(std::string &output)
{
  output.clear();
  std::string data;
  if(!ReadWholeFile("/proc/net/dev", data)) {
    output = "ERROR - Could not read /proc/net/dev\n";
    return 1;
  }
  // Interfaces that are up, without loopback. Counters are totals since
  // the interface came up; a monitor takes the difference between reports.
  for(const std::string &line : Split(data, '\n')) {
    size_t c = line.find(':');
    if(c == std::string::npos) continue;
    std::string nic = Trim(line.substr(0, c));
    if(nic == "lo" || nic.empty()) continue;
    std::string base = "/sys/class/net/" + nic;
    std::string oper = ReadSmallFile(base + "/operstate");
    if(oper != "up" && oper != "unknown") continue;
    std::istringstream in(line.substr(c + 1));
    unsigned long long v[16];
    int n = 0;
    while(n < 16 && (in >> v[n])) n++;
    if(n < 16) continue;
    // Skip idle virtual interfaces (container veths, bridges with no traffic)
    bool virt = !FileExists(base + "/device");
    if(virt && v[0] == 0 && v[8] == 0) continue;
    long speed = atol(ReadSmallFile(base + "/speed").c_str());
    if(speed < 0) speed = 0;
    output += "adapter=" + QuoteValue(nic);
    output += " speed_mbps=" + std::to_string(speed);
    output += " rx_bytes=" + std::to_string(v[0]);
    output += " tx_bytes=" + std::to_string(v[8]);
    output += " rx_packets=" + std::to_string(v[1]);
    output += " tx_packets=" + std::to_string(v[9]);
    output += " rx_errors=" + std::to_string(v[2]);
    output += " tx_errors=" + std::to_string(v[10]);
    output += " rx_discards=" + std::to_string(v[3]);
    output += " tx_discards=" + std::to_string(v[11]);
    output += " collisions=" + std::to_string(v[13]);
    output += std::string(" virtual=") + (virt ? "1" : "0") + "\n";
  }
  return 0;
}

int get_logged_in_users(std::string &output)
{
  output.clear();
  setutxent();
  struct utmpx *u;
  while((u = getutxent()) != NULL) {
    if(u->ut_type != USER_PROCESS) continue;
    std::string user(u->ut_user, strnlen(u->ut_user, sizeof(u->ut_user)));
    std::string tty(u->ut_line, strnlen(u->ut_line, sizeof(u->ut_line)));
    std::string from(u->ut_host, strnlen(u->ut_host, sizeof(u->ut_host)));
    output += "user=" + QuoteValue(user) + " tty=" + QuoteValue(tty) + " from=" + QuoteValue(from) +
      " login=" + std::to_string((long long)u->ut_tv.tv_sec) + "\n";
  }
  endutxent();
  return 0;
}

// Accounts people log in with: UID 1000 and up, or 0, with a login shell
int get_local_accounts(std::string &output)
{
  output.clear();
  setpwent();
  struct passwd *pw;
  while((pw = getpwent()) != NULL) {
    std::string shell = pw->pw_shell ? pw->pw_shell : "";
    if(shell.find("nologin") != std::string::npos || shell == "/bin/false" || shell == "/usr/bin/false") continue;
    if(pw->pw_uid != 0 && (pw->pw_uid < 1000 || pw->pw_uid == 65534)) continue;
    output += "account=" + QuoteValue(pw->pw_name) + " uid=" + std::to_string(pw->pw_uid) +
      " home=" + QuoteValue(pw->pw_dir ? pw->pw_dir : "") + " shell=" + shell + "\n";
  }
  endpwent();
  return 0;
}

std::string PackageManager()
{
  // Debian and Ubuntu can have rpm installed too, their database is dpkg's
  if(FileExists("/var/lib/dpkg/status") && !FindProgram("dpkg-query").empty()) return "dpkg";
  if(!FindProgram("rpm").empty()) return "rpm";
  return std::string();
}

std::string DnfProgram()
{
  std::string p = FindProgram("dnf");
  if(p.empty()) p = FindProgram("yum");
  return p;
}

//
// Purpose:
//   One line per installed package: name, epoch:version-release, arch
//   and install time. newest_install is the latest install time, which
//   tells how long ago the host was last updated.
//
int get_installed_packages(const AgentConfig &cfg, std::string &output, long long &newest_install)
{
  output.clear();
  newest_install = 0;
  std::string pm = PackageManager();
  CommandResult r;
  if(pm == "rpm") {
    RunCommand({ FindProgram("rpm"), "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\n" },
	       cfg.command_timeout_seconds, r);
    if(r.exit_code != 0) {
      output = "ERROR - rpm -qa failed: " + Trim(r.err) + "\n";
      return 1;
    }
    std::vector<std::string> lines;
    for(const std::string &line : Split(r.out, '\n')) {
      std::vector<std::string> f = Split(line, '\t');
      if(f.size() < 4 || f[0] == "gpg-pubkey") continue;
      long long t = atoll(f[3].c_str());
      if(t > newest_install) newest_install = t;
      lines.push_back("package=" + f[0] + " version=" + f[1] + " arch=" + f[2] + " installed=" + f[3] + "\n");
    }
    std::sort(lines.begin(), lines.end());
    for(const std::string &l : lines) output += l;
    return 0;
  }
  if(pm == "dpkg") {
    RunCommand({ FindProgram("dpkg-query"), "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n" },
	       cfg.command_timeout_seconds, r);
    if(r.exit_code != 0) {
      output = "ERROR - dpkg-query failed: " + Trim(r.err) + "\n";
      return 1;
    }
    for(const std::string &line : Split(r.out, '\n')) {
      std::vector<std::string> f = Split(line, '\t');
      if(f.size() < 4 || !StartsWith(f[0], "ii")) continue;
      output += "package=" + f[1] + " version=" + f[2] + " arch=" + f[3] + "\n";
    }
    newest_install = FileMtime("/var/lib/dpkg/status");
    return 0;
  }
  output = "ERROR - No rpm or dpkg package database found\n";
  return 1;
}

void RefreshPackageMetadata(const AgentConfig &cfg, std::string &output)
{
  std::string dnf = DnfProgram();
  if(dnf.empty() || cfg.updates_refresh_hours <= 0) return;
  std::string stamp = JoinPath(cfg.data_dir, "metadata_refresh.stamp");
  long long last = FileMtime(stamp);
  if(last > 0 && (long long)time(NULL) - last < (long long)cfg.updates_refresh_hours * 3600) return;
  CommandResult r;
  RunCommand({ dnf, "-q", "--setopt=skip_if_unavailable=True", "makecache" }, cfg.command_timeout_seconds * 2, r);
  if(r.exit_code != 0) {
    output += "WARNING - dnf makecache failed, update and vulnerability data may be old: " + Trim(r.err) + "\n";
  }
  // Retry on the next refresh interval either way, a broken repository
  // must not make every cycle slow
  WriteWholeFile(stamp, std::to_string((long long)time(NULL)) + "\n", 0600);
}

// Newest installed kernel package, as uname -r prints it
static std::string NewestKernel(const AgentConfig &cfg)
{
  CommandResult r;
  RunCommand({ FindProgram("rpm"), "-q", "--qf", "%{INSTALLTIME} %{VERSION}-%{RELEASE}.%{ARCH}\n", "kernel-core", "kernel" },
	     cfg.command_timeout_seconds, r);
  long long best_t = -1;
  std::string best;
  for(const std::string &line : Split(r.out, '\n')) {
    std::istringstream in(line);
    long long t;
    std::string ver;
    if(!(in >> t >> ver)) continue;
    if(t > best_t) {
      best_t = t;
      best = ver;
    }
  }
  return best;
}

int get_pending_updates(const AgentConfig &cfg, std::string &output, long long newest_install)
{
  output.clear();
  if(newest_install > 0) {
    output += "last_install_etime=" + std::to_string(newest_install) + "\n";
    output += "last_install=" + QuoteValue(TimeText(newest_install)) + "\n";
  }

  // Reboot needed: needs-restarting from dnf-utils, or a newer kernel
  // installed than the one running
  struct utsname u;
  uname(&u);
  output += "running_kernel=" + std::string(u.release) + "\n";
  if(PackageManager() == "rpm") {
    std::string newest = NewestKernel(cfg);
    if(!newest.empty()) output += "newest_kernel=" + newest + "\n";
    std::string nr = FindProgram("needs-restarting");
    std::string dnf = DnfProgram();
    CommandResult r;
    int reboot = -1;
    if(!nr.empty()) {
      RunCommand({ nr, "-r" }, cfg.command_timeout_seconds, r);
      if(r.exit_code == 0) reboot = 0;
      else if(r.exit_code == 1) reboot = 1;
    }
    if(reboot < 0 && !newest.empty()) reboot = (newest != u.release) ? 1 : 0;
    if(reboot >= 0) output += "reboot_required=" + std::to_string(reboot) + "\n";
  }
  else if(FileExists("/var/run/reboot-required") || FileExists("/run/reboot-required")) {
    output += "reboot_required=1\n";
  }

  if(!cfg.check_updates) {
    output += "check=disabled\n";
    return 0;
  }
  std::string dnf = DnfProgram();
  if(dnf.empty()) {
    output += "check=unsupported\n";
    return 0;
  }

  // From the metadata cache only, RefreshPackageMetadata keeps it current
  CommandResult r;
  RunCommand({ dnf, "-q", "-C", "--setopt=skip_if_unavailable=True", "check-update" }, cfg.command_timeout_seconds, r);
  // check-update exits 100 when updates are waiting, 0 when there are none
  if(r.exit_code != 0 && r.exit_code != 100) {
    output += "check=failed\n";
    output += "ERROR - " + dnf + " check-update failed: " + Trim(r.err) + "\n";
    return 1;
  }
  output += "check=ok\n";
  long long refreshed = FileMtime(JoinPath(cfg.data_dir, "metadata_refresh.stamp"));
  if(refreshed > 0) output += "metadata_etime=" + std::to_string(refreshed) + "\n";
  // One update per line: name.arch version repo. dnf wraps a long name
  // onto a line of its own, so collect words three at a time.
  std::vector<std::string> pending, words;
  for(const std::string &line : Split(r.out, '\n')) {
    // "Obsoleting Packages" lists replacements, not updates
    if(StartsWith(line, "Obsoleting") || StartsWith(line, "Security:") || StartsWith(line, "Last metadata")) {
      if(StartsWith(line, "Obsoleting")) break;
      continue;
    }
    std::istringstream in(line);
    std::string w;
    while(in >> w) words.push_back(w);
    while(words.size() >= 3) {
      pending.push_back("update package=" + words[0] + " version=" + words[1] + " repo=" + words[2] + "\n");
      words.erase(words.begin(), words.begin() + 3);
    }
  }
  output += "pending_count=" + std::to_string(pending.size()) + "\n";
  for(const std::string &p : pending) output += p;
  return 0;
}

static std::string SystemctlState(const std::string &unit)
{
  std::string sc = FindProgram("systemctl");
  if(sc.empty()) return "unknown";
  CommandResult r;
  RunCommand({ sc, "is-active", unit }, 15, r);
  std::string s = Trim(r.out);
  return s.empty() ? "unknown" : s;
}

int get_security_settings(const AgentConfig &cfg, std::string &output)
{
  output.clear();

  // SELinux
  std::string enforce = ReadSmallFile("/sys/fs/selinux/enforce");
  if(enforce == "1") output += "selinux=enforcing\n";
  else if(enforce == "0") output += "selinux=permissive\n";
  else output += "selinux=disabled\n";

  // Firewall: firewalld, or nftables/iptables rules when it is not used
  std::string fw = SystemctlState("firewalld");
  output += "firewalld=" + fw + "\n";
  if(fw == "active") {
    std::string fwc = FindProgram("firewall-cmd");
    if(!fwc.empty()) {
      CommandResult r;
      RunCommand({ fwc, "--get-default-zone" }, 30, r);
      if(r.exit_code == 0) output += "firewalld_default_zone=" + Trim(r.out) + "\n";
    }
  }
  else {
    std::string nft = FindProgram("nft");
    if(!nft.empty()) {
      CommandResult r;
      RunCommand({ nft, "list", "ruleset" }, 30, r);
      int rules = 0;
      for(const std::string &line : Split(r.out, '\n')) {
	std::string t = Trim(line);
	if(!t.empty() && !StartsWith(t, "table") && !StartsWith(t, "chain") && !StartsWith(t, "type") &&
	   t != "}" && t != "{") rules++;
      }
      output += "nftables_rules=" + std::to_string(rules) + "\n";
    }
  }

  output += "auditd=" + SystemctlState("auditd") + "\n";
  output += "sshd=" + SystemctlState("sshd") + "\n";
  std::string fips = ReadSmallFile("/proc/sys/crypto/fips_enabled");
  output += "fips=" + (fips.empty() ? std::string("0") : fips) + "\n";

  // SSH server settings that matter most over the internet
  std::string sshd = FindProgram("sshd");
  if(!sshd.empty()) {
    CommandResult r;
    RunCommand({ sshd, "-T" }, 30, r);
    if(r.exit_code == 0) {
      for(const std::string &line : Split(r.out, '\n')) {
	std::istringstream in(line);
	std::string k, v;
	if(!(in >> k >> v)) continue;
	if(k == "permitrootlogin" || k == "passwordauthentication" || k == "port" ||
	   k == "kbdinteractiveauthentication" || k == "permitemptypasswords") {
	  output += "sshd_" + k + "=" + v + "\n";
	}
      }
    }
  }

  // Automatic updates
  std::string ac = SystemctlState("dnf-automatic.timer");
  if(ac == "inactive" || ac == "unknown") ac = SystemctlState("dnf5-automatic.timer");
  output += "automatic_updates=" + ac + "\n";
  (void)cfg;
  return 0;
}

int get_failed_services(const AgentConfig &cfg, std::string &output)
{
  output.clear();
  std::string sc = FindProgram("systemctl");
  if(sc.empty()) return 0;
  CommandResult r;
  RunCommand({ sc, "list-units", "--failed", "--plain", "--no-legend", "--no-pager" }, cfg.command_timeout_seconds, r);
  for(const std::string &line : Split(r.out, '\n')) {
    std::istringstream in(line);
    std::string unit;
    if(!(in >> unit)) continue;
    if(unit == "\xe2\x97\x8f") in >> unit; // older systemd prints a bullet first
    output += "unit=" + unit + "\n";
  }
  return 0;
}

static void AddSection(std::string &report, const std::string &name, const std::string &body)
{
  report += name + ":\n";
  report += body;
  if(!body.empty() && body[body.length() - 1] != '\n') report += "\n";
  report += "END " + name + "\n\n";
}

//
// Purpose:
//   Builds the whole report. The section format matches the Windows
//   agent: a header, then "NAME:" ... "END NAME" blocks of name=value
//   lines, so the same server pages and DRSM tools read both.
//
std::string BuildReport(const AgentConfig &cfg, std::string &output)
{
  std::string hostname = GetAgentHostname();
  std::string report = "DataReel Reporting Agent report from host " + hostname + "\n";
  report += "VERSION: " AGENT_VERSION "\n";
  report += "PLATFORM: linux\n";
  report += "HOSTNAME: " + hostname + "\n";
  report += "ETIME: " + std::to_string((long long)time(NULL)) + "\n";
  report += "DATETIME: " + NowText() + "\n\n";

  std::string sbuf;
  get_system_info(sbuf);
  AddSection(report, "SYSTEM", sbuf);
  get_ip_addresses(sbuf);
  AddSection(report, "IP ADDRESS", sbuf);
  // Usage for trends (DRSM): CPU sampled over cpu_sample_seconds
  get_performance(sbuf, cfg.cpu_sample_seconds);
  AddSection(report, "PERFORMANCE", sbuf);
  get_disk_usage(sbuf);
  AddSection(report, "DISK USAGE", sbuf);
  get_network_stats(sbuf);
  AddSection(report, "NETWORK", sbuf);
  get_logged_in_users(sbuf);
  AddSection(report, "USERS", sbuf);
  get_local_accounts(sbuf);
  AddSection(report, "ACCOUNTS", sbuf);
  get_security_settings(cfg, sbuf);
  AddSection(report, "SECURITY", sbuf);
  get_failed_services(cfg, sbuf);
  AddSection(report, "FAILED SERVICES", sbuf);

  RefreshPackageMetadata(cfg, output);
  long long newest_install = 0;
  std::string packages;
  get_installed_packages(cfg, packages, newest_install);
  get_pending_updates(cfg, sbuf, newest_install);
  AddSection(report, "UPDATES", sbuf);

  // Results of the last vulnerability and compliance scan
  report += ScanReportSections(cfg);
  // Site checks from the report hooks
  report += HookReportSection(cfg, output);

  AddSection(report, "INSTALLED PACKAGES", packages);
  return report;
}
