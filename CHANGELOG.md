# Changelog

All user-visible changes to rootctl.

## Unreleased

### Added

- **Interactive console** (`rootctl` with no args): msfconsole-style banner
  with chain / parser / category counts, readline history + tab completion,
  built-ins (`help`, `banner`, `clear`, `version`, `exit`), and full
  Typer-subcommand dispatch on every line. Non-tty stdin falls back to
  `--help` so pipes / CI keep working.
- `rootctl --version` / `-V` flag.
- GitHub Actions: `ci.yml` (pytest on Python 3.10/3.11/3.12 + chain validate
  + wheel build + install sanity check) and `release.yml` (PyPI Trusted
  Publishing on `v*` tags + GitHub release).
- E2E fixture smoke test: every shipped fixture under `examples/` is now
  pumped through the full CLI pipeline (`pytest -k fixtures_smoke`).
- **11 new chains** → 205 across 63 categories:
  - `web/confluence_cve_2024_21683` — authenticated language-pack RCE.
  - `web/aspnet_viewstate_rce` — leaked MachineKey → ysoserial.net
    `TextFormattingRunProperties` gadget.
  - `web/ofbiz_cve_2024_45195` — view-override auth bypass + groovyProgram.
  - `hugegraph/cve_2024_27348_gremlin_rce` — unauth Gremlin reflection RCE.
  - `checkpoint/cve_2024_24919_quantum_file_read` — Mobile Access path
    traversal arbitrary file read.
  - `esxi/cve_2024_37085_ad_esx_admins` — AD "ESX Admins" group → host root
    (Akira / Black Basta).
  - `gitlab/cve_2024_0402_workspace_path_traversal` — workspace symlink →
    arbitrary file write → RCE.
  - `ollama/cve_2024_37032_probllama_path_traversal` — manifest digest
    traversal → file overwrite → RCE.
  - `solr/cve_2019_17558_velocity_ssti` — Velocity ResponseWriter SSTI.
  - `rdp/bluekeep_cve_2019_0708` — pre-auth wormable RDP RCE.
  - `smb/smbghost_cve_2020_0796` — SMBv3 compression header → kernel RCE.

## 0.1.0 — initial release

### Added

- **17 parsers**: nmap, gobuster, ffuf, feroxbuster, nuclei, smbmap, netexec,
  bloodhound, sudo_l, find_suid, whoami_priv, linpeas, pspy, enum4linux,
  nikto, whatweb, hashcat (john --show shares the same parser).
- **194 attack chains** across 58 categories:
  - **AD**: BloodHound roast targeting (asreproast / kerberoast /
    unconstrained delegation), kerberoast standalone, kerbrute flow from
    user list, GPP cpassword, ZeroLogon (CVE-2020-1472), AD CS ESC1 /
    ESC4 / ESC8, PetitPotam / PrinterBug / DFSCoerce coercion, Golden
    Ticket, Silver Ticket, Shadow Credentials (msDS-KeyCredentialLink),
    Resource-Based Constrained Delegation (RBCD), SCCM Network Access
    Account extraction, AS-REP roasting (standalone), DCSync, LAPS read,
    NoPac (CVE-2021-42278 + 42287), gMSA password read, mitm6 →
    ntlmrelayx coercion.
  - **Crypto**: bcrypt / phpass / md5crypt / sha256crypt / sha512crypt /
    md5_unsalted / Kerberos AS-REP & TGS / DCC2 / Net-NTLMv2 / JWT /
    id_rsa passphrase cracking workflows.
  - **DNS**: zone transfer (AXFR).
  - **FTP**: anonymous + brute force, vsftpd 2.3.4 backdoor (CVE-2011-2523),
    ProFTPD 1.3.5 mod_copy (CVE-2015-3306).
  - **Web (HTTP servers)**: Apache server-status disclosure, Apache 2.4.49/50
    path traversal (CVE-2021-41773 / 42013), Apache mod_rewrite RCE
    (CVE-2024-38475), nginx alias-misconfig traversal, Tomcat default
    creds → WAR, Tomcat PUT JSP (CVE-2017-12617), Tomcat Ghostcat AJP
    file-read (CVE-2020-1938), Jenkins /script Groovy console, Jenkins
    CLI file-read (CVE-2024-23897), JBoss JMX console deploy, Spring
    Boot actuator exposure, Spring Cloud Function SpEL RCE
    (CVE-2022-22963), Apache Struts 2 OGNL CVE-2023-50164 (S2-066).
  - **Web (CMS / apps)**: WordPress wpscan-to-RCE + xmlrpc brute, Drupal
    Drupalgeddon, Drupalgeddon2 (CVE-2018-7600), Joomla template-edit RCE,
    phpMyAdmin default-creds → SQL → RCE, Werkzeug debug-PIN, SQLi, login
    form brute force, PHP webshell upload, Shellshock (CVE-2014-6271),
    WebDAV PUT/MOVE, LFI → log poisoning, SSTI fingerprint+RCE, Log4Shell
    (CVE-2021-44228), Spring4Shell (CVE-2022-22965), Confluence OGNL
    (CVE-2022-26134), Confluence broken auth (CVE-2023-22518), Struts 2
    Equifax (CVE-2017-5638), Atlassian Jira SSTI (CVE-2019-11581),
    Atlassian Bitbucket CVE-2022-36804, Adobe ColdFusion CVE-2023-26360,
    PHP-CGI argument injection (CVE-2024-4577), Apache OFBiz CVE-2023-49070
    + CVE-2023-51467, Magento XXE-to-RCE (CVE-2022-24086), Liferay
    JSON-WS RCE (CVE-2020-7961), Roundcube command injection
    (CVE-2024-43770), Zimbra Collaboration RCE (CVE-2022-37042),
    Next.js authz bypass (CVE-2025-29927).
  - **Web exposure**: `.git/`, `.env`, IIS `web.config`.
  - **Appliances / enterprise**: Microsoft Exchange ProxyShell
    (CVE-2021-34473 + 34523 + 31207), Exchange ProxyLogon (CVE-2021-26855
    + 27065), VMware vCenter CVE-2021-21972, VMware ESXi OpenSLP
    CVE-2021-21974 (ESXiArgs), F5 BIG-IP iControl CVE-2022-1388, Citrix
    Bleed (CVE-2023-4966), Ivanti Connect Secure CVE-2023-46805 +
    CVE-2024-21887, FortiOS SSL-VPN CVE-2022-42475, Cisco IOS XE
    CVE-2023-20198 + CVE-2023-20273, Cisco ASA WebVPN, MikroTik RouterOS
    Winbox (CVE-2018-14847), MOVEit Transfer CVE-2023-34362, PaperCut
    MF/NG CVE-2023-27350, ManageEngine ADSelfService Plus
    CVE-2021-40539, GitLab ExifTool CVE-2021-22205, GitLab account
    takeover (CVE-2023-7028), Oracle WebLogic console CVE-2020-14882 +
    14883, Splunk default-creds → script command, Nexus Repository
    default-creds, Grafana / Kibana / Keycloak default-creds, CrushFTP
    auth bypass (CVE-2024-4040), GlobalProtect SSL-VPN
    (CVE-2024-3400), SonicWall SMA (CVE-2021-20016), SAP NetWeaver
    AS Java (CVE-2020-22536), ScreenConnect setup wizard
    (CVE-2024-1709), TeamCity auth bypass (CVE-2023-27198), Veeam
    Backup deserialization (CVE-2023-29849), Apache Druid Kafka JNDI
    (CVE-2023-25194).
  - **LDAP**: anonymous bind enumeration.
  - **Cloud SSRF**: AWS / GCP / Azure metadata service via SSRF.
  - **Linux privesc**: GTFOBins (sudo + SUID), capabilities, PATH hijack,
    cron writable, PwnKit (CVE-2021-4034), Sudo Baron Samedit
    (CVE-2021-3156), Dirty Pipe (CVE-2022-0847), Looney Tunables
    (CVE-2023-4911), XZ Utils backdoor (CVE-2024-3094).
  - **Windows privesc**: SeImpersonate / PrintSpoofer, SeBackup → SAM dump,
    SeRestore, SeTakeOwnership, SeDebug → LSASS dump, SeManageVolume
    → raw NTFS, PrintNightmare (CVE-2021-34527 / 1675).
  - **Containers / Kubernetes**: docker socket exposed → host root,
    privileged container escape via cgroup `release_agent`, Kubernetes
    API anonymous, kubelet read-only port, pod-escape via
    hostPath / hostPID / hostNetwork.
  - **Databases**: MySQL default creds + dump, MSSQL xp_cmdshell +
    Responder, PostgreSQL COPY FROM PROGRAM, MongoDB unauth, Redis
    no-auth → authorized_keys write, Redis Lua sandbox escape.
  - **Mail / messaging**: SMTP user enum (VRFY/EXPN/RCPT), OpenSMTPD
    CVE-2020-7247, IMAP/POP3 brute force, ActiveMQ OpenWire
    CVE-2023-46604.
  - **Search / NoSQL**: Elasticsearch unauth, memcached anon dump.
  - **Network services**: SMB null-session enum + RID cycle + spray, share
    enumeration / loot / payload drop, MS17-010 EternalBlue, NFS
    no_root_squash, VNC no auth, SNMP default community, telnet, rsync
    anonymous, Samba 3.0.20-25 usermap (CVE-2007-2447), distccd
    (CVE-2004-2687), Java RMI registry, ingreslock, UnrealIRCd 3.2.8.1
    (CVE-2010-2075), r-services (rexec/rlogin/rsh), MSSQL TRUSTWORTHY
    chain, Cassandra default no-auth, Oracle TNS poisoning,
    Android Debug Bridge unauth, ADCS ESC4.
  - **SSH**: dictionary attack, id_rsa, regreSSHion (CVE-2024-6387).
  - **Wi-Fi**: WPA2 PMKID + 4-way handshake crack, on-disk profile/key
    extraction.
  - **Cloud**: GCP service-account key impersonation, Chrome DPAPI
    cookies + passwords harvest, evilginx2 phishing pivot, PowerShell
    history harvest, KeePass DB extraction, Azure device-code phishing,
    GitHub Actions self-hosted runner takeover, IIS short-name
    enumeration.
  - **RDP / WinRM**: xfreerdp, evil-winrm.
  - **Post-exploit**: credential reuse spray, NTLM Pass-the-Hash, SMB
    Relay, LLMNR / NBT-NS / mDNS poison & relay (Responder + ntlmrelayx),
    DSN URL connect, admin (Pwn3d!) take-the-host, cracked-credential
    reuse, AWS access keys → STS / role enumeration → privesc, S3
    public-bucket check.
- **Extractors**:
  - **Hashes**: bcrypt, phpass, md5crypt/sha256crypt/sha512crypt, argon2,
    Kerberos AS-REP/TGS, Net-NTLMv2, JWT, MySQL 4.1+, LM:NTLM, DCC2, raw
    SHA hashes, MD5/NTLM ambiguous.
  - **Credentials**: user:pass, hydra hits, Basic-auth URLs, Basic-auth
    headers (decoded), Bearer tokens, MySQL CLI, wp-config, DSN URLs
    (postgres/mysql/mongo/redis/amqp).
  - **Secrets**: AWS access keys, S3 bucket URLs, GCP/GitHub/Slack/Stripe
    tokens, Kubernetes service-account tokens, PEM private keys, JWT
    signing-key env assignments, generic `.env`-style secret assignments,
    GPP cpassword, internal IPv4 (RFC 1918), email addresses.
- **CLI commands**: `analyze` (multi-file, --json, --tag, --min-severity,
  --top, --quiet), `chains` (--tag, --severity), `show` (--markdown),
  `extract`, `validate`, `kinds`, `tools`.
- Auto-detect for every parser by content sniff.
- Determinism: identical input always yields byte-identical output.
- Performance budgets: nmap parse 100 hosts under 2s; matcher 400 findings
  × 194 chains under 1s.

### Tests

- 113 tests covering parsers, chains, extractors, CLI surface, end-to-end
  multi-file engagement workflow, full-fixture smoke pass, perf budgets.
