"""Spec Section 4.5 / 13.1: every masking rule must have a unit test
against a redacted real-world sample."""
from app.services.sanitizer import sanitize_raw_config


def test_cisco_type5_secret_masked():
    out = sanitize_raw_config("enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0")
    assert "$1$mERr" not in out
    assert "<MASKED_SECRET>" in out


def test_cisco_type7_password_masked():
    out = sanitize_raw_config("password 7 0822455D0A16544541")
    assert "0822455D0A16544541" not in out


def test_cisco_username_line_masked():
    out = sanitize_raw_config("username admin secret 5 $1$abcd$efghijklmnop")
    assert "admin" not in out
    assert "<MASKED_USER>" in out and "<MASKED_SECRET>" in out


def test_snmp_community_masked():
    out = sanitize_raw_config("snmp-server community S3cr3tRO RO")
    assert "S3cr3tRO" not in out
    assert "<MASKED_COMMUNITY>" in out


def test_snmpv3_auth_priv_keys_masked():
    cfg = "snmp-server user nms grp v3 auth sha AuthPass123 priv aes 128"
    out = sanitize_raw_config(cfg)
    assert "AuthPass123" not in out
    assert "<MASKED_AUTH_KEY>" in out


def test_tacacs_radius_keys_masked():
    out = sanitize_raw_config("tacacs-server key MyTacacsKey99\nradius-server key MyRadiusKey01")
    assert "MyTacacsKey99" not in out and "MyRadiusKey01" not in out
    assert out.count("<MASKED_AAA_KEY>") == 2


def test_ipsec_psk_masked():
    out = sanitize_raw_config("crypto isakmp key pre-shared-key VpnPsk2024! address 10.0.0.1")
    assert "VpnPsk2024!" not in out
    assert "<MASKED_PSK>" in out


def test_fortinet_secrets_masked():
    cfg = 'set passwd ENC XXYYZZ==\nset psksecret fortipsk123\nset private-key "-----KEY-----"'
    out = sanitize_raw_config(cfg)
    assert "ENC" not in out or "XXYYZZ" not in out
    assert "fortipsk123" not in out
    assert out.count("<MASKED_SECRET>") >= 2


def test_juniper_quoted_secret_masked():
    out = sanitize_raw_config('authentication-key "$9$juniperhash/xyz";')
    assert "$9$juniperhash" not in out
    assert '"<MASKED_SECRET>"' in out


def test_private_key_block_masked():
    cfg = (
        "interface Loopback0\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA7cmiWvC0Yr\nQIDAQAB\n"
        "-----END RSA PRIVATE KEY-----\n"
        "ip ssh version 2"
    )
    out = sanitize_raw_config(cfg)
    assert "MIIEpAIBAAKCAQEA" not in out
    assert "<MASKED_PRIVATE_KEY_BLOCK>" in out
    assert "ip ssh version 2" in out  # surrounding config preserved


def test_non_secret_lines_untouched():
    cfg = "hostname CORE-SW-01\ninterface GigabitEthernet0/1\n description uplink"
    assert sanitize_raw_config(cfg) == cfg
