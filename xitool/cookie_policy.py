"""Attributi cookie condivisi senza nomi, valori o date originali."""
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import re


def attributes(headers):
    result = []
    for cookie in headers.get("set-cookie", "").splitlines()[:100]:
        values = {part.strip().partition("=")[0].lower(): part.strip().partition("=")[2] for part in cookie.split(";")[1:]}
        same_site = values.get("samesite", "").lower()
        max_age = values.get("max-age", "")
        age = int(max_age) if re.fullmatch(r"-?\d{1,10}", max_age) else None
        expiry = "NOT_SET"
        if "expires" in values:
            try:
                date = parsedate_to_datetime(values["expires"])
                if date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
                expiry = "EXPIRED" if date <= datetime.now(timezone.utc) else "FUTURE"
            except (ValueError, TypeError, OverflowError):
                expiry = "INVALID"
        result.append({"secure": "secure" in values, "httponly": "httponly" in values, "samesite": "samesite" in values,
                       "samesite_policy": same_site if same_site in ("lax", "strict", "none") else "UNKNOWN",
                       "samesite_none_without_secure": same_site == "none" and "secure" not in values,
                       "expires_present": "expires" in values, "max_age_seconds": age,
                       "expiry_observed": expiry, "deletion_cookie_observed": age is not None and age <= 0})
    return result
