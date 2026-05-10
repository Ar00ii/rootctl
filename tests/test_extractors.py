"""Extractor coverage: hashes, credentials, secrets."""

from __future__ import annotations

from rootctl.extractors import extract_all
from rootctl.extractors.credentials import extract as extract_credentials
from rootctl.extractors.hashes import extract as extract_hashes
from rootctl.extractors.secrets import extract as extract_secrets
from rootctl.models import Severity


def _kinds(items) -> set[str]:
    return {i.kind for i in items}


def test_hashes_bcrypt_and_md5crypt() -> None:
    text = (
        "user1: $2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy\n"
        "user2: $1$abcd1234$ABCDEFGHIJKLMNOPQRSTU.\n"
    )
    found = extract_hashes(text)
    assert "bcrypt" in _kinds(found)
    assert "md5crypt" in _kinds(found)
    bcrypt = next(i for i in found if i.kind == "bcrypt")
    assert bcrypt.next_command and "hashcat -m 3200" in bcrypt.next_command


def test_hashes_ntlm_pair_and_kerberos() -> None:
    ntlm = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    asrep = (
        "$krb5asrep$23$alice@HTB.LOCAL:abcdef0123456789abcdef0123456789$"
        "0123456789abcdef0123456789abcdef0123456789"
    )
    found = extract_hashes(ntlm + "\n" + asrep)
    kinds = _kinds(found)
    assert "lm:ntlm" in kinds
    assert "kerberos-asrep" in kinds


def test_hashes_dcc2_from_secretsdump() -> None:
    text = "ALPHA.LAB/admin:$DCC2$10240#admin#abcdef0123456789abcdef0123456789\n"
    found = extract_hashes(text)
    assert any(i.kind == "dcc2" for i in found)
    dcc2 = next(i for i in found if i.kind == "dcc2")
    assert dcc2.next_command and "hashcat -m 2100" in dcc2.next_command


def test_hashes_md5_or_ntlm_emits_dual_command() -> None:
    text = "5f4dcc3b5aa765d61d8327deb882cf99"
    found = extract_hashes(text)
    assert any(i.kind == "md5_or_ntlm" for i in found)
    md = next(i for i in found if i.kind == "md5_or_ntlm")
    assert md.next_command and "hashcat -m 0" in md.next_command and "hashcat -m 1000" in md.next_command


def test_credentials_userpass_and_hydra_line() -> None:
    text = (
        "alice:Sup3rSecret\n"
        "[22][ssh] host: 10.10.10.10   login: bob   password: l3tm3in!\n"
    )
    found = extract_credentials(text)
    kinds = _kinds(found)
    assert "user:pass" in kinds
    assert "hydra-cred" in kinds
    hydra = next(i for i in found if i.kind == "hydra-cred")
    assert hydra.severity is Severity.CRITICAL


def test_credentials_dsn_url() -> None:
    text = (
        "DATABASE_URL=postgres://app:s3cret@db.internal:5432/myapp\n"
        "REDIS_URL=redis://:hunter2@cache:6379/\n"
        "MONGO_URL=mongodb://root:toor@mongo.lan:27017/\n"
    )
    found = extract_credentials(text)
    kinds = _kinds(found)
    assert "dsn-url" in kinds
    dsns = [i for i in found if i.kind == "dsn-url"]
    schemes = {d.value.split("://", 1)[0] for d in dsns}
    assert {"postgres", "redis", "mongodb"} <= schemes
    assert all(i.severity is Severity.CRITICAL for i in dsns)


def test_credentials_authorization_headers() -> None:
    text = (
        "Authorization: Basic YWxpY2U6c2VjcmV0\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.PAYLOAD.SIG\n"
    )
    found = extract_credentials(text)
    kinds = _kinds(found)
    assert "basic-auth-header" in kinds
    assert "bearer-token" in kinds
    basic = next(i for i in found if i.kind == "basic-auth-header")
    assert basic.value == "alice:secret"
    assert basic.severity is Severity.CRITICAL


def test_credentials_filters_protocol_noise() -> None:
    text = "https://example.com/path\n"
    found = extract_credentials(text)
    # The "https" prefix should not be extracted as a user:pass pair.
    assert all(":example" not in i.value for i in found if i.kind == "user:pass")
    assert "user:pass" not in _kinds(found) or all(
        i.value.split(":")[0].lower() not in {"http", "https"} for i in found if i.kind == "user:pass"
    )


def test_secrets_aws_and_github_and_pem() -> None:
    text = (
        "AKIAIOSFODNN7EXAMPLE\n"
        "ghp_" + "a" * 40 + "\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA...\n"
    )
    found = extract_secrets(text)
    kinds = _kinds(found)
    assert "aws-access-key-id" in kinds
    assert "github-token" in kinds
    assert "private-key" in kinds
    assert all(i.severity is Severity.CRITICAL for i in found if i.kind in {"aws-access-key-id", "github-token", "private-key"})


def test_secrets_env_assignment() -> None:
    text = 'API_TOKEN="sk-supersecret-12345678"\n'
    found = extract_secrets(text)
    assert "env-secret" in _kinds(found)


def test_secrets_s3_bucket_urls() -> None:
    text = (
        "config: s3://my-data-bucket/key\n"
        "asset url: https://uploads.s3.amazonaws.com/file.png\n"
        "https://s3.amazonaws.com/legacy-bucket/index.html\n"
    )
    found = extract_secrets(text)
    s3 = [i for i in found if i.kind == "aws-s3-bucket"]
    assert len(s3) >= 2
    assert all(i.severity is Severity.MEDIUM for i in s3)


def test_secrets_gpp_cpassword() -> None:
    text = '<Properties><Groups><User cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"/></Groups></Properties>'
    found = extract_secrets(text)
    gpp = [i for i in found if i.kind == "gpp-cpassword"]
    assert len(gpp) == 1
    assert gpp[0].severity is Severity.CRITICAL
    assert "gpp-decrypt" in (gpp[0].next_command or "")


def test_secrets_internal_ip_and_email() -> None:
    text = (
        "Connecting to 10.0.5.42 via SSH...\n"
        "Backend: 192.168.10.5, fallback 172.20.30.40\n"
        "Public: 8.8.8.8 (must NOT match)\n"
        "Contact: alice@victim.lab and bob@example.com\n"
    )
    found = extract_secrets(text)
    kinds = _kinds(found)
    assert "internal-ipv4" in kinds
    assert "email-address" in kinds
    ips = {i.value for i in found if i.kind == "internal-ipv4"}
    assert "10.0.5.42" in ips
    assert "192.168.10.5" in ips
    assert "172.20.30.40" in ips
    assert "8.8.8.8" not in ips


def test_extract_all_dedupes_across_modules() -> None:
    text = "AKIAIOSFODNN7EXAMPLE\nAKIAIOSFODNN7EXAMPLE\n"
    items = extract_all(text)
    aws = [i for i in items if i.kind == "aws-access-key-id"]
    assert len(aws) == 1
