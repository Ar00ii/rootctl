"""Chain loading + matching against parsed findings.

Exercises the end-to-end pipeline: load the Werkzeug chain, parse the
matching nmap fixture, and assert the chain fires.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rootctl.engine.matcher import load_chains, match
from rootctl.models import Finding, Severity
from rootctl.parsers import gobuster as gobuster_parser
from rootctl.parsers import nmap as nmap_parser


def test_loads_werkzeug_chain(chains_dir: Path) -> None:
    chains = load_chains(chains_dir)
    by_id = {c.chain_id: c for c in chains}
    assert "werkzeug_debug_pin_rce" in by_id

    chain = by_id["werkzeug_debug_pin_rce"]
    assert chain.severity is Severity.CRITICAL
    assert "web" in chain.tags
    # Steps are copied verbatim from the source — keep the count stable so an
    # accidental edit to the YAML is caught.
    assert len(chain.steps) == 7
    assert chain.steps[0].id == 1
    assert chain.common_errors  # at least one entry
    assert any("https://" in r for r in chain.references)


def test_load_is_deterministic(chains_dir: Path) -> None:
    a = [c.chain_id for c in load_chains(chains_dir)]
    b = [c.chain_id for c in load_chains(chains_dir)]
    assert a == b == sorted(a)


def test_werkzeug_chain_matches_example(chains_dir: Path, examples_dir: Path) -> None:
    chains = load_chains(chains_dir)
    findings = nmap_parser.parse(examples_dir / "test_werkzeug.xml")
    matches = match(findings, chains)

    chain_ids = {m.chain_id for m in matches}
    assert "werkzeug_debug_pin_rce" in chain_ids

    werkzeug = next(m for m in matches if m.chain_id == "werkzeug_debug_pin_rce")
    triggered_ports = {f.port for f in werkzeug.findings}
    assert 8080 in triggered_ports


def test_trigger_does_not_fire_on_unrelated_finding(chains_dir: Path) -> None:
    chains = load_chains(chains_dir)
    finding = Finding(
        tool="nmap",
        host="1.2.3.4",
        port=22,
        protocol="tcp",
        service="ssh",
        product="OpenSSH",
        version="9.2p1",
        banner="OpenSSH 9.2p1",
    )
    matches = match([finding], chains)
    assert "werkzeug_debug_pin_rce" not in {m.chain_id for m in matches}


def test_multi_service_fixture_triggers_expected_chains(
    chains_dir: Path, examples_dir: Path
) -> None:
    """Smoke test for the service catalog: each port should fire its chain."""
    chains = load_chains(chains_dir)
    findings = nmap_parser.parse(examples_dir / "multi_service.xml")
    matches = match(findings, chains)
    fired = {m.chain_id for m in matches}

    expected = {
        "ftp_anonymous_and_brute",
        "ssh_brute_force",
        "smb_enumeration_and_shares",
        "mysql_open",
        "rdp_open",
        "winrm_login",
    }
    missing = expected - fired
    assert not missing, f"chains failed to fire: {missing}"


def test_dns_ldap_mssql_redis_fixtures(
    chains_dir: Path, examples_dir: Path
) -> None:
    """A box exposing 53/389/1433/6379 should fire each service-entry chain."""
    chains = load_chains(chains_dir)
    findings = nmap_parser.parse(examples_dir / "test_multi_av.xml")
    matches = match(findings, chains)
    fired = {m.chain_id for m in matches}

    expected = {
        "dns_zone_transfer",
        "ldap_anonymous_bind",
        "mssql_open",
        "redis_no_auth",
    }
    missing = expected - fired
    assert not missing, f"missed: {missing}"


def test_smtp_snmp_tomcat_jenkins_fixtures(
    chains_dir: Path, examples_dir: Path
) -> None:
    """SMTP/SNMP/Tomcat/Jenkins service-entry chains fire from nmap output."""
    chains = load_chains(chains_dir)
    findings = nmap_parser.parse(examples_dir / "test_more_services.xml")
    matches = match(findings, chains)
    fired = {m.chain_id for m in matches}

    expected = {
        "smtp_user_enum",
        "snmp_default_community",
        "tomcat_manager_default",
        "jenkins_script_console",
    }
    missing = expected - fired
    assert not missing, f"missed: {missing}"


def test_recent_appliance_chains_fire_and_dont_overshoot(
    chains_dir: Path, examples_dir: Path
) -> None:
    """A perimeter scan exposing 10 enterprise services should fire each
    matching CVE chain — and ONLY those. Catches over-broad triggers
    (e.g. Spring4Shell firing on any Tomcat banner)."""
    chains = load_chains(chains_dir)
    findings = nmap_parser.parse(examples_dir / "test_recent_appliances.xml")
    matches = match(findings, chains)
    fired = {m.chain_id for m in matches}

    expected = {
        "cisco_iosxe_cve_2023_20198",
        "citrix_bleed_cve_2023_4966",
        "esxi_openslp_cve_2021_21974",
        "fortios_cve_2022_42475",
        "manageengine_adss_cve_2021_40539",
        "mikrotik_winbox_cve_2018_14847",
        "papercut_cve_2023_27350",
        "tomcat_ghostcat_cve_2020_1938",
        "tomcat_manager_default",
        "tomcat_put_cve_2017_12617",
        "weblogic_console_cve_2020_14882",
    }
    missing = expected - fired
    assert not missing, f"missed: {missing}"

    # Guard against trigger drift: post-exploit chains and unrelated
    # service chains must NOT fire on a recon-only fixture.
    forbidden = {
        "silver_ticket",          # post-exploit, needs service_account_hash
        "sccm_naa_extraction",    # post-exploit, needs sccm fingerprint
        "adcs_esc4_template_write",  # post-exploit, AD CS-specific
        "k8s_hostpath_pod_escape",   # post-exploit, K8s-specific
        "spring4shell_cve_2022_22965",         # not Spring
        "spring_cloud_function_cve_2022_22963", # not Spring
        "kube_api_anonymous",     # no K8s here
        "keycloak_default_admin", # no Keycloak here
        "jenkins_cli_cve_2024_23897",  # no Jenkins here
    }
    overshoot = forbidden & fired
    assert not overshoot, f"chains fired on unrelated services: {overshoot}"


def test_recent_app_chains_fire_and_dont_overshoot(
    chains_dir: Path, examples_dir: Path
) -> None:
    """A scan exposing 7 enterprise apps (Veeam, Magento, Next.js, Zimbra,
    GlobalProtect, Liferay, Roundcube) should fire each matching chain
    and ONLY those. Catches port-only triggers (e.g. vCenter on 9443
    that Veeam shares, Grafana on 3000 that Next.js shares)."""
    chains = load_chains(chains_dir)
    findings = nmap_parser.parse(examples_dir / "test_recent_apps.xml")
    matches = match(findings, chains)
    fired = {m.chain_id for m in matches}

    expected = {
        "veeam_cve_2024_29849",
        "magento_cve_2022_24086",
        "nextjs_middleware_cve_2025_29927",
        "zimbra_cve_2022_37042",
        "globalprotect_cve_2024_3400",
        "liferay_cve_2020_7961",
        "roundcube_cve_2023_43770",
    }
    missing = expected - fired
    assert not missing, f"missed: {missing}"

    forbidden = {
        "vcenter_cve_2021_21972",   # 9443 is Veeam here, not vCenter
        "fortios_cve_2022_42475",   # 8443 is Zimbra here, not Fortinet
        "grafana_default_creds",    # 3000 is Next.js here, not Grafana
        "nopac_cve_2021_42278_42287",  # post-exploit, no AD here
    }
    overshoot = forbidden & fired
    assert not overshoot, f"chains fired on unrelated services: {overshoot}"


def test_ci_appliance_chains_fire(chains_dir: Path, examples_dir: Path) -> None:
    """ScreenConnect / TeamCity / SonicWall SMA / IIS — each on its own port,
    each must fire exactly once."""
    chains = load_chains(chains_dir)
    findings = nmap_parser.parse(examples_dir / "test_ci_appliances.xml")
    fired = {m.chain_id for m in match(findings, chains)}

    expected = {
        "screenconnect_cve_2024_1709",
        "teamcity_cve_2024_27198",
        "sonicwall_sma_cve_2021_20016",
        "iis_shortname_enum",
    }
    missing = expected - fired
    assert not missing, f"missed: {missing}"

    forbidden = {
        "github_actions_self_hosted_runner_takeover",  # post-exploit
        "azure_device_code_phishing",                  # post-exploit
    }
    overshoot = forbidden & fired
    assert not overshoot, f"post-exploit chains overshot: {overshoot}"


def test_metasploitable2_full_engagement(
    chains_dir: Path, examples_dir: Path
) -> None:
    """Canonical Metasploitable 2 nmap (21 services) — every service-entry
    chain that maps to a real Metasploitable bug must fire, and AD /
    Windows / Linux-supply-chain chains must NOT fire on this Linux host.

    This fixture is the live-verification target: the same XML can be
    captured from a real `nmap -sCV -p- 10.0.2.4` and fed back here."""
    chains = load_chains(chains_dir)
    findings = nmap_parser.parse(examples_dir / "test_metasploitable2.xml")
    fired = {m.chain_id for m in match(findings, chains)}

    expected = {
        "vsftpd_2_3_4_backdoor",
        "ftp_anonymous_and_brute",
        "ssh_brute_force",
        "telnet_open",
        "smtp_user_enum",
        "dns_zone_transfer",
        "smb_enumeration_and_shares",
        "smb_null_session_enum",
        "rsh_rlogin_rexec_weak_auth",
        "java_rmi_registry_rce",
        "ingreslock_backdoor_1524",
        "nfs_no_squash",
        "mysql_open",
        "distccd_cve_2004_2687",
        "postgres_open_to_rce",
        "vnc_no_auth",
        "unrealircd_cve_2010_2075",
        "tomcat_manager_default",
        "tomcat_ghostcat_cve_2020_1938",
        "webdav_put_to_rce",
    }
    missing = expected - fired
    assert not missing, f"missed: {missing}"

    # Coercion / AD / Windows-only / xz-backdoor chains must stay silent
    # — Metasploitable is a standalone Linux box, not domain-joined.
    forbidden = {
        "dfscoerce_ms_dfsnm",
        "petitpotam_coercion",
        "printerbug_coercion",
        "rbcd_abuse",
        "printnightmare_cve_2021_34527",
        "llmnr_nbns_poison_relay",
        "mitm6_ipv6_dns_takeover",
        "opensmtpd_cve_2020_7247",  # Postfix, not OpenSMTPD
        "regresshion_cve_2024_6387",  # OpenSSH 4.7 not in vuln range
        "xz_backdoor_cve_2024_3094",  # OpenSSH 4.7 not in vuln range
    }
    overshoot = forbidden & fired
    assert not overshoot, f"chains fired on unrelated host: {overshoot}"


def test_modern_appliance_chains_fire_and_dont_overshoot(
    chains_dir: Path, examples_dir: Path
) -> None:
    """CrushFTP / GitLab / Confluence / Cisco ASA — each must fire its
    matching CVE chains. Bitbucket and Jira chains must NOT fire just
    because the target is Atlassian (broad-banner false positives)."""
    chains = load_chains(chains_dir)
    findings = nmap_parser.parse(examples_dir / "test_modern_appliances.xml")
    fired = {m.chain_id for m in match(findings, chains)}

    expected = {
        "crushftp_cve_2024_4040",
        "gitlab_password_reset_cve_2023_7028",
        "confluence_cve_2023_22518",
        "cisco_asa_webvpn_cve_2018_0101",
    }
    missing = expected - fired
    assert not missing, f"missed: {missing}"

    forbidden = {
        "bitbucket_cve_2022_36804",   # not Bitbucket — Confluence
        "jira_ssti_cve_2019_11581",   # not Jira — Confluence
        "asreproast_standalone",      # no Kerberos here
        "dcsync_replication_rights",  # post-exploit
        "laps_password_read",         # post-exploit
        "wifi_profile_extraction",    # post-exploit
    }
    overshoot = forbidden & fired
    assert not overshoot, f"chains fired on unrelated services: {overshoot}"


def test_chain_severity_sort_critical_first(
    chains_dir: Path, examples_dir: Path
) -> None:
    chains = load_chains(chains_dir)
    findings = nmap_parser.parse(examples_dir / "multi_service.xml")
    matches = match(findings, chains)
    severities = [m.severity.rank for m in matches]
    assert severities == sorted(severities)


def test_gobuster_fixture_triggers_web_chains(
    chains_dir: Path, examples_dir: Path
) -> None:
    """Web chains should fire on the right gobuster paths."""
    chains = load_chains(chains_dir)
    findings = gobuster_parser.parse(examples_dir / "test_gobuster.txt")
    matches = match(findings, chains)
    fired = {m.chain_id for m in matches}

    expected_web = {
        "wordpress_enum_to_rce",
        "login_form_brute_force",
        "php_webshell_upload",
        "sqli_with_sqlmap",
    }
    missing = expected_web - fired
    assert not missing, f"web chains failed to fire: {missing}"


def test_crypto_fixture_triggers_expected_chains(
    chains_dir: Path, examples_dir: Path
) -> None:
    """Hash extracts from a mixed dump should fire the right crypto chains."""
    from rootctl.extractors import extract_all, extracts_to_findings

    chains = load_chains(chains_dir)
    text = (examples_dir / "test_hashes.txt").read_text(encoding="utf-8")
    findings = extracts_to_findings(extract_all(text))
    matches = match(findings, chains)
    fired = {m.chain_id for m in matches}

    expected = {
        "etc_shadow_crack",
        "phpass_wordpress_crack",
        "bcrypt_crack",
        "kerberos_asrep_roast",
        "md5_unsalted_crack",
        "idrsa_passphrase_crack",
        "ntlm_pass_the_hash",
        "credential_reuse",
    }
    missing = expected - fired
    assert not missing, f"crypto chains failed to fire: {missing}"


def test_path_pattern_does_not_match_unrelated_paths(chains_dir: Path) -> None:
    chains = load_chains(chains_dir)
    finding = Finding(
        tool="gobuster",
        host="example.com",
        port=80,
        service="http",
        path="/static/style.css",
        status_code=200,
    )
    fired = {m.chain_id for m in match([finding], chains)}
    # Static assets must not light up wordpress / login / upload chains.
    assert fired.isdisjoint({
        "wordpress_enum_to_rce",
        "login_form_brute_force",
        "php_webshell_upload",
    })


def test_unknown_trigger_key_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "chain_id: bad\n"
        "title: Bad chain\n"
        "severity: LOW\n"
        "trigger:\n"
        "  not_a_real_field: foo\n"
        "description: x\n"
        "steps:\n"
        "  - id: 1\n"
        "    title: noop\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown trigger keys"):
        load_chains(tmp_path)


def test_invalid_regex_in_trigger_is_rejected(tmp_path: Path) -> None:
    """A malformed regex must fail at load time, not at first match."""
    bad = tmp_path / "bad_regex.yaml"
    bad.write_text(
        "chain_id: bad_regex\n"
        "title: Bad regex chain\n"
        "severity: LOW\n"
        "trigger:\n"
        "  path_pattern: '(invalid['\n"
        "description: x\n"
        "steps:\n"
        "  - id: 1\n"
        "    title: noop\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid regex"):
        load_chains(tmp_path)
