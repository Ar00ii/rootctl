# rootctl

**Offline pentest output triage. No telemetry, no cloud.**

You ran your recon — nmap, gobuster, hashcat, sudo -l, BloodHound, whatever. Now you have 8 files of raw output, 200 lines of banners, and you want to know what to attack first. `rootctl analyze recon/*` gives you a colored list of attack chains sorted by severity, with the **exact next command** to run for each — pulled from a curated YAML catalog of **205 chains across 63 categories**.

Auto-detects the format of every input. **17 parsers built in:** nmap, gobuster, ffuf, feroxbuster, nuclei, smbmap, netexec, BloodHound, sudo -l, whoami /priv, find -perm -4000, LinPEAS, pspy, enum4linux, nikto, whatweb, hashcat / john --show. Extracts hashes, credentials and secrets and tells you the exact `hashcat -m XXXXX` mode to crack each one.

## Why rootctl

- **It's a triage tool, not a scanner.** rootctl never sends a packet. It eats your existing tool output and tells you what to do with it.
- **The intelligence is in the chains, not in code.** 205 hand-curated YAMLs covering CVE-2017-5638 → CVE-2025-29927, AD attack paths, container escapes, cloud post-exploit. Every step is copied verbatim from public sources; nothing is invented.
- **It's offline.** No telemetry, no cloud API, nothing leaves your box. Stdlib + Typer + Rich + PyYAML. Built for pentesters under NDA.
- **Deterministic.** Two runs over the same input produce byte-identical output.

## 30-second demo

```bash
$ rootctl analyze scan.xml          # nmap of a Metasploitable 2 box
╭───────────────────────────────────────────────────────╮
│ rootctl — 24 findings · 21 chain matches · 1 extracts │
│ CRITICAL: 7 · HIGH: 9 · MEDIUM: 4 · LOW: 1            │
╰───────────────────────────────────────────────────────╯

CRITICAL · distccd — CVE-2004-2687 unauth command execution via DIST_SLOTS protocol
  Triggered by: 10.0.2.4 3632/tcp distccd (distccd v1)
  Steps:
    1. nmap -sV -p 3632 10.0.2.4
    2. msfconsole -qx 'use exploit/unix/misc/distcc_exec; set RHOSTS 10.0.2.4; …'
    …

CRITICAL · vsftpd 2.3.4 — CVE-2011-2523 backdoor (smiley face) → root shell on 6200
  Triggered by: 10.0.2.4 21/tcp ftp (vsftpd 2.3.4)
  …

CRITICAL · UnrealIRCd 3.2.8.1 — CVE-2010-2075 source-tarball backdoor → unauth RCE
  Triggered by: 10.0.2.4 6667/tcp irc (UnrealIRCd 3.2.8.1)
  …
```

Filter by tag, severity, or top-N:

```bash
rootctl analyze scan.xml --tag ad --min-severity HIGH      # AD-only, HIGH+
rootctl analyze recon/*.xml --top 5 --quiet                 # top 5, no findings table
rootctl analyze recon/*.xml --json | jq '.matches[].chain_id'   # tooling-friendly
```

## Interactive console

Run `rootctl` with no arguments to drop into an msfconsole-style shell.
Tab-completion, history, and every subcommand work without a fresh process per
call — useful when you are bouncing between `chains --tag X`, `show <id>`, and
`analyze recon/*.xml` over and over.

```
$ rootctl

██████╗  ██████╗  ██████╗ ████████╗ ██████╗████████╗██╗
██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝╚══██╔══╝██║
██████╔╝██║   ██║██║   ██║   ██║   ██║        ██║   ██║
██╔══██╗██║   ██║██║   ██║   ██║   ██║        ██║   ██║
██║  ██║╚██████╔╝╚██████╔╝   ██║   ╚██████╗   ██║   ███████╗
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝   ╚═╝   ╚══════╝

       =[ rootctl v0.1.0
+ -- --=[ 205 chains across 63 categories
+ -- --=[ 17 parsers · 3 extractor categories
+ -- --=[ 0 telemetry · 0 cloud · 0 invented chain steps

rootctl > chains --tag ad --severity CRITICAL
rootctl > show esxi_cve_2024_37085_ad_esx_admins
rootctl > analyze recon/scan.xml recon/sudo_l.txt --top 5
rootctl > exit
```

Built-ins: `help`, `banner`, `clear`, `version`, `exit` / `quit` (Ctrl-D
also works). Anything else is dispatched through the same Typer command tree
the non-interactive CLI uses, so flags and `--help` work identically.

## Install

```bash
pipx install rootctl
```

From the repo (development):

```bash
git clone https://github.com/Ar00ii/rootctl.git
cd rootctl
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/rootctl --help
```

## Usage

```bash
# Triage one tool output (auto-detect the format)
rootctl analyze scan.xml

# Triage an entire engagement folder in one pass — every parser runs,
# every extractor runs, every chain matches, everything sorted by severity.
rootctl analyze recon/nmap.xml recon/gobuster.txt recon/sudo_l.txt creds/dump.txt

# Filters: --tag, --min-severity, --top N, --quiet
rootctl analyze recon/*.xml --min-severity HIGH --top 10
rootctl analyze recon/*.xml --tag wordpress

# Machine-readable output for tooling
rootctl analyze recon/*.xml --json | jq '.matches[].chain_id'

# Pull hashes / credentials / secrets out of a raw text file
rootctl extract dump.txt

# Catalog operations
rootctl chains                      # list every chain
rootctl chains --tag ad             # filter by tag
rootctl chains --severity CRITICAL  # filter by severity
rootctl show werkzeug_debug_pin_rce # one chain in full
rootctl show werkzeug_debug_pin_rce --markdown  # pipe-friendly
rootctl kinds                       # list every `kind:` referenced by chains
rootctl validate                    # schema-check every chain
```

## End-to-end example

```bash
# 1. Recon
nmap -sCV -p- -oX scan.xml $TARGET
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o gobuster.txt
sudo -l > sudo_l.txt   # after foothold
linpeas.sh > linpeas.out

# 2. Triage
rootctl analyze scan.xml gobuster.txt sudo_l.txt linpeas.out
# → 'Werkzeug/Flask debug console PIN to RCE' (CRITICAL)
# → 'Linux privesc — sudo binary abuse via GTFOBins' (CRITICAL)
# → 'Linux privesc — file capability abuse' (HIGH)
# → 'WordPress — wpscan enumeration to template-edit RCE' (HIGH)
```

## Supported parsers

| Format       | Auto-detect                                                  |
|--------------|--------------------------------------------------------------|
| `nmap`       | `.xml` extension + `nmaprun` in body                          |
| `gobuster`   | `Gobuster` banner or `(Status:` lines                         |
| `ffuf`       | `-of json` output (`commandline` + `results`)                 |
| `feroxbuster`| default text output (`--format` required)                     |
| `nuclei`     | `-jsonl` output OR bracketed plain text                       |
| `smbmap`     | `Disk` + `Permissions` + `[+] IP:` triple                     |
| `netexec`    | `PROTO IP PORT NAME [` row prefix                             |
| `bloodhound` | JSON files with `Properties` + `meta`                         |
| `sudo`       | `sudo -l` output                                              |
| `suid`       | `find / -perm -4000 -ls` or bare paths                        |
| `whoami`     | `whoami /priv` output                                         |
| `linpeas`    | LinPEAS section banners (╔ + ╣)                              |
| `pspy`       | `CMD: UID=` byte sequence                                     |
| `enum4linux` | `enum4linux` header                                           |
| `nikto`      | `Nikto v` header                                              |
| `whatweb`    | URL + `[NNN]` (HTTP status) header                            |
| _no match_   | falls through to extractors (hashes/creds/secrets)            |

## Built-in extractors

- **Hashes**: bcrypt, phpass, md5crypt, sha256crypt, sha512crypt, argon2,
  Kerberos AS-REP and TGS, Net-NTLMv2, JWT, MySQL 4.1+, LM:NTLM pairs,
  DCC2 (mscash2 — secretsdump), raw SHA-512 / SHA-256 / SHA-1, MD5/NTLM ambiguous.
- **Credentials**: `user:pass`, hydra hits, Basic-auth URLs, MySQL CLI, wp-config.
- **Secrets**: AWS access keys, Google API keys, GitHub / Slack / Stripe tokens,
  PEM private keys, JWT secrets, generic `.env` assignments.

## Chain catalog (categories)

205 chains across 63 categories at last count. Run `rootctl chains` for
the live list. Highlights:

```
chains/
  activemq/          # CVE-2023-46604 OpenWire RCE
  ad/                # BloodHound roast targets, ZeroLogon, ADCS ESC1/ESC4/ESC8,
                     #   Golden / Silver / Shadow Credentials, RBCD abuse,
                     #   unconstrained delegation, PetitPotam / PrinterBug /
                     #   DFSCoerce, GPP cpassword, SCCM NAA extraction,
                     #   kerberoast standalone, kerbrute flow
  apache/            # server-status disclosure, CVE-2021-41773 path traversal
  cloud_ssrf/        # AWS / GCP / Azure metadata via SSRF
  crypto/            # Hash cracking workflows (bcrypt, phpass, shadow,
                     #   id_rsa, AS-REP, kerberoast, NTLMv2, JWT, DCC2, ...)
  dns/               # AXFR / DNS recon
  docker/            # docker socket exposed, privileged container escape
  drupal/            # Drupalgeddon, Drupalgeddon2 (CVE-2018-7600)
  elasticsearch/     # 9200 anon dump
  ftp/               # anonymous + brute, vsftpd 2.3.4 backdoor, ProFTPD mod_copy
  gitlab/            # default-creds, ExifTool unauth RCE (CVE-2021-22205)
  grafana/           # default-creds → datasource leak
  imap_pop3/         # mailbox brute force
  jboss/             # JMX console deploy
  jenkins/           # /script Groovy console, CLI file-read (CVE-2024-23897)
  joomla/            # /administrator brute + template index.php RCE
  keycloak/          # default-creds admin takeover
  kibana/            # default-creds dashboard takeover
  kubernetes/        # API anonymous, kubelet read-only, hostPath pod escape
  ldap/              # Anonymous bind enumeration
  linux_privesc/     # GTFOBins (sudo + SUID), capabilities, PATH hijack,
                     #   cron writable, PwnKit, Sudo Baron Samedit,
                     #   Dirty Pipe, Looney Tunables, XZ backdoor
  memcached/         # 11211 cache dump
  mikrotik/          # RouterOS Winbox file-read (CVE-2018-14847)
  mongodb/           # 27017 anon dump
  mssql/             # Default creds, xp_cmdshell, Responder coercion
  mysql/             # Default creds + dump
  nexus/             # default-creds → repository takeover
  nfs/               # no_root_squash → SUID-bash drop
  nginx/             # alias misconfig path traversal
  phpmyadmin/        # default creds → SELECT INTO OUTFILE shell
  post_exploit/      # Credential reuse spray, NTLM PtH, admin pwn, SMB relay,
                     #   LLMNR/NBNS/mDNS poison-relay, cracked creds reuse,
                     #   DSN URL connect, S3 bucket check, AWS keys → STS
  postgres/          # COPY FROM PROGRAM RCE
  rdp/               # xfreerdp
  redis/             # Unauthenticated → SSH key write → RCE, Lua sandbox escape
  rsync/             # 873 module mirror
  smb/               # null-session enum, share loot/payload drop, MS17-010,
                     #   Samba 3.0.20 usermap script
  smtp/              # VRFY/EXPN/RCPT user enum, OpenSMTPD CVE-2020-7247
  snmp/              # Default community → MIB walk
  splunk/            # default-creds → script command RCE
  springboot/        # actuator exposure, Spring Cloud Function CVE-2022-22963
  ssh/               # Hydra brute force, id_rsa
  telnet/            # Banner grab + brute force
  tomcat/            # /manager default creds, PUT JSP (CVE-2017-12617),
                     #   Ghostcat AJP file-read (CVE-2020-1938)
  vnc/               # 5900 anon / weak password
  web/               # Werkzeug, WordPress, SQLi, login form, PHP webshell,
                     #   Shellshock, WebDAV PUT/MOVE, LFI→log poisoning, SSTI,
                     #   Log4Shell, Spring4Shell, Confluence OGNL, Struts2
                     #   Equifax, ProxyShell + ProxyLogon, ESXi OpenSLP,
                     #   ManageEngine ADSS, Cisco IOS XE 20198, Drupalgeddon2,
                     #   F5 BIG-IP 1388, vCenter 21972, Citrix Bleed, MOVEit,
                     #   Ivanti CS 46805+21887, WebLogic console, FortiOS 42475,
                     #   PaperCut 27350, Bitbucket 36804, Jira SSTI, ColdFusion
                     #   26360, PHP-CGI 4577, OFBiz 49070, .git/.env/web.config
                     #   exposure
  win_privesc/       # SeImpersonate / PrintSpoofer, SeBackup → SAM dump,
                     #   SeRestore, SeTakeOwnership, SeDebug → LSASS,
                     #   SeManageVolume → raw NTFS, PrintNightmare
  winrm/             # evil-winrm
```

## Hard rules (do not break)

- No external API calls. Ever.
- No third-party HTTP libraries. Stdlib only for any network code.
- No invented chain steps. If a step is not in the source notes, it does not go in.
- Do not simplify commands. If the source uses `nmap -p- --open -sCV -Pn -n --min-rate 5000`, keep it as-is.
- Performance: parsing nmap output for 100 hosts must complete in under 2 seconds (enforced by test_perf_nmap.py).

## License

MIT.
