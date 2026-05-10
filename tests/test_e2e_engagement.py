"""End-to-end test: hand rootctl a folder full of mixed outputs and
verify the chain catalog fires across every category in one pass.

This is the load-bearing test: if a refactor breaks the single-command
multi-file workflow, this fails and the rest of the suite is silent on
the regression.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from rootctl.cli import app

runner = CliRunner()


def test_full_engagement_fires_every_category(repo_root: Path) -> None:
    examples = repo_root / "examples"
    inputs = [
        examples / "test_werkzeug.xml",          # nmap → web (Werkzeug)
        examples / "multi_service.xml",          # nmap → ftp/ssh/smb/mysql/winrm/rdp
        examples / "test_more_services.xml",     # nmap → smtp/snmp/tomcat/jenkins
        examples / "test_multi_av.xml",          # nmap → dns/ldap/mssql/redis
        examples / "test_gobuster.txt",          # gobuster → wordpress/login/upload/sqli
        examples / "test_hashes.txt",            # hashes/creds → crypto + ntlm + reuse
        examples / "test_secretsdump.txt",       # secretsdump → DCC2 + NTLM
        examples / "test_sudo_l.txt",            # sudo -l → linux privesc
        examples / "test_whoami_priv.txt",       # whoami /priv → win privesc (4 privs)
        examples / "test_smbmap.txt",            # smbmap → smb share chains
        examples / "test_find_suid.txt",         # find -perm 4000 → SUID GTFOBins
        examples / "test_linpeas.txt",           # linpeas → SUID + capabilities
        examples / "test_pspy.txt",              # pspy → cron writable
        examples / "test_enum4linux.txt",        # enum4linux → AD users
        examples / "test_bloodhound_users.json", # bloodhound → roast targets
        examples / "test_netexec.txt",           # netexec → admin pwn + relay
    ]
    for p in inputs:
        assert p.exists(), f"missing fixture {p}"

    args = ["analyze", "--json", *[str(p) for p in inputs]]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.stdout

    import json
    payload = json.loads(result.stdout)
    fired = {m["chain_id"] for m in payload["matches"]}

    # One chain from every major category — proves the pipeline reaches
    # nmap/web/crypto/privesc/post-exploit/SMB without any single one
    # carrying the load.
    expected_floor = {
        # Core categories — one each
        "werkzeug_debug_pin_rce",
        "ssh_brute_force",
        "smb_enumeration_and_shares",
        "wordpress_enum_to_rce",
        "etc_shadow_crack",
        "ntlm_pass_the_hash",
        "credential_reuse",
        "sudo_gtfobins",
        "seimpersonate_printspoofer",
        "smb_share_loot",
        "smb_share_payload_drop",
        "suid_gtfobins",
        # Services
        "tomcat_manager_default",
        "jenkins_script_console",
        "snmp_default_community",
        "dns_zone_transfer",
        "ldap_anonymous_bind",
        "redis_no_auth",
        # Crypto
        "dcc2_crack",
        # Privesc additions
        "linux_capability_abuse",
        "cron_writable",
        "sebackup_dcsync",
        # AD
        "user_list_to_attacks",
        "bloodhound_asreproast_targeted",
        # Post-exploit
        "admin_cred_pwn",
        "smb_relay",
    }
    missing = expected_floor - fired
    assert not missing, f"engagement run missed: {missing}"

    # Severity ordering invariant — CRITICAL must come before HIGH must come
    # before MEDIUM in the matches list.
    severities = [m["severity"] for m in payload["matches"]]
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [rank[s] for s in severities]
    assert ranks == sorted(ranks), "matches must be severity-sorted"
