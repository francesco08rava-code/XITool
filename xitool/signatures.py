"""Firme versionabili; nessuna credenziale viene convalidata o utilizzata."""
CATALOG_VERSION = "2026-10-18.1"
SIGNATURES = {
    "github_token_shape": r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
    "github_fine_grained_shape": r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "aws_access_key_shape": r"\bAKIA[0-9A-Z]{16}\b",
    "secret_assignment": r'''(?i)(?:api[_-]?key|secret|access_token)\s*[=:]\s*["'][A-Za-z0-9_/-]{20,}["']''',
}
