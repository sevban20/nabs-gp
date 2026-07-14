"""Secret Sanitization Engine (Spec Section 4.5, multi-vendor).

Every rule here MUST have a matching unit test using a redacted real
sample --- see tests/test_sanitizer.py. A failing rule here means a
plaintext secret reaches version control.
"""
import re

_PATTERNS = [
    # Cisco IOS / IOS-XE
    # NOTE: username rule must run BEFORE the bare password/secret rules,
    # otherwise the inner secret gets masked first and the username survives.
    (r"username \S+ (password|secret) \d+ \S+", r"username <MASKED_USER> \1 <MASKED_SECRET>"),
    # '$' added vs. spec draft: real type-5/8/9 hashes are '$1$..$..' shaped.
    (r"password \d+ [a-zA-Z0-9\.\/\+\$]+", "password <MASKED_SECRET>"),
    (r"secret \d+ [a-zA-Z0-9\.\/\+\$]+", "secret <MASKED_SECRET>"),
    (r"community [a-zA-Z0-9_\-]+", "community <MASKED_COMMUNITY>"),
    # SNMPv3 auth/priv keys
    (r"(auth (md5|sha)) \S+", r"\1 <MASKED_AUTH_KEY>"),
    (r"(priv (des|aes)) \S+", r"\1 <MASKED_PRIV_KEY>"),
    # TACACS+ / RADIUS shared keys
    (r"(tacacs-server|radius-server) key \S+", r"\1 key <MASKED_AAA_KEY>"),
    # IPSec / IKE pre-shared keys
    (r"pre-shared-key \S+", "pre-shared-key <MASKED_PSK>"),
    # Fortinet
    (r"set (passwd|psksecret|private-key) \S+", r"set \1 <MASKED_SECRET>"),
    # Juniper (quoted secrets)
    (r'(authentication-key|secret) "[^"]+"', r'\1 "<MASKED_SECRET>"'),
    # Huawei VRP (cipher/irreversible-cipher parolalar, snmp cipher community)
    (r"(password (?:cipher|irreversible-cipher)) \S+", r"\1 <MASKED_SECRET>"),
    (r"(authentication-mode \S+) cipher \S+", r"\1 cipher <MASKED_SECRET>"),
    (r"(community) (?:cipher )?%[\^~][^\s]+", r"\1 <MASKED_COMMUNITY>"),
    # OpenWrt / UCI (uci export: option key/password/psk '...')
    (r"(option (?:key|password|passphrase|psk|_key|auth_secret|nasid|wpa_key)) '[^']*'",
     r"\1 '<MASKED_SECRET>'"),
    (r"(option (?:key|password|passphrase|psk)) \"[^\"]*\"", r'\1 "<MASKED_SECRET>"'),
    # MikroTik RouterOS (password=, wpa-pre-shared-key=)
    (r"((?:password|wpa-pre-shared-key|wpa2-pre-shared-key)=)\"?\S+\"?", r"\1<MASKED_SECRET>"),
    # Embedded SSH/TLS private key blocks (any vendor export)
    (r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----.*?-----END \1-----",
     "<MASKED_PRIVATE_KEY_BLOCK>"),
]


def sanitize_raw_config(config: str) -> str:
    """Applies the full multi-vendor masking rule set before any Git commit."""
    result = config
    for pattern, replacement in _PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE | re.DOTALL)
    return result
