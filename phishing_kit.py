"""
PhishGuard CLI — phishing_kit.py
==================================
Phishing Kit Simulator — For security research, CTF, and awareness training only.

This module demonstrates HOW phishing kits are built so defenders can:
  • Recognise them in the wild
  • Build better detection rules
  • Understand attacker infrastructure

   DO NOT deploy generated pages against real users.
    Use only in isolated lab / CTF environments.

    Authors are not responsible for misuse.
"""

import hashlib
import datetime
import base64
from urllib.parse import urlparse
from pathlib import Path

#  CONSTANTS

LOOT_FILE   = Path("phishkit_loot.json")
LOG_FILE    = Path("phishkit_log.txt")
PAGES_DIR   = Path("phishkit_pages")
KIT_BANNER  = "[bold red]⚠  PHISHGUARD — PHISHING KIT SIMULATOR  ⚠[/bold red]"

BRAND_TEMPLATES = {
    "1": "Google",
    "2": "Microsoft / Office 365",
    "3": "PayPal",
    "4": "Facebook",
    "5": "Generic Corporate SSO",
    "6": "Bank (Generic)",
    "7": "Custom",
}

#  LURE EMAIL GENERATOR

LURE_TEMPLATES = {
    "Credential Reset": {
        "subject": "Action Required: Your {brand} password will expire in 24 hours",
        "body": (
            "Dear User,\n\n"
            "Our security systems have detected that your {brand} account password "
            "is due to expire within the next 24 hours.\n\n"
            "To avoid losing access to your account, please verify your identity "
            "and set a new password immediately:\n\n"
            "    👉 {link}\n\n"
            "If you do not act within 24 hours, your account will be temporarily "
            "suspended for security reasons.\n\n"
            "Regards,\n{brand} Security Team\n\n"
            "---\n"
            "This is an automated message. Please do not reply."
        ),
        "red_flags": [
            "Artificial urgency ('24 hours', 'immediately')",
            "Threat of account suspension",
            "Unsolicited password reset",
            "Generic greeting 'Dear User'",
            "Link does not go to official domain",
        ],
    },
    "Suspicious Login Alert": {
        "subject": "⚠ New sign-in to your {brand} account from an unrecognised device",
        "body": (
            "Hello,\n\n"
            "We noticed a new sign-in to your {brand} account from:\n\n"
            "  Device:   Windows 10\n"
            "  Location: Moscow, Russia\n"
            "  Time:     {time} UTC\n\n"
            "If this was you, you can ignore this email.\n\n"
            "If this was NOT you, your account may be compromised. "
            "Secure it now:\n\n"
            "    👉 {link}\n\n"
            "Act quickly to protect your account.\n\n"
            "{brand} Support"
        ),
        "red_flags": [
            "Fear trigger ('Moscow, Russia' — chosen to alarm)",
            "Binary choice: ignore OR click — no middle ground",
            "Fake specificity (device, location, time) to appear legitimate",
            "Urgency pressure: 'Act quickly'",
        ],
    },
    "Package / Delivery": {
        "subject": "Your {brand} package could not be delivered — action required",
        "body": (
            "Dear Customer,\n\n"
            "We attempted to deliver your parcel today but were unable to "
            "complete the delivery.\n\n"
            "To reschedule your delivery and avoid the parcel being returned, "
            "please confirm your delivery address and pay a small redelivery "
            "fee of £1.99:\n\n"
            "    👉 {link}\n\n"
            "This link expires in 48 hours.\n\n"
            "Reference: PKG-{ref}\n\n"
            "{brand} Delivery Services"
        ),
        "red_flags": [
            "Payment for 'small fee' — card harvesting technique",
            "Time pressure ('expires in 48 hours')",
            "Fake tracking reference adds false legitimacy",
            "Generic 'Dear Customer'",
        ],
    },
    "Invoice / Finance": {
        "subject": "Invoice #{ref} from {brand} — Payment due",
        "body": (
            "Dear Accounts Team,\n\n"
            "Please find attached Invoice #{ref} for services rendered.\n\n"
            "Amount Due: $4,850.00\n"
            "Due Date:   {date}\n\n"
            "To review and process this invoice, please log in to our "
            "secure billing portal:\n\n"
            "    👉 {link}\n\n"
            "If you have any questions, please do not reply to this email — "
            "contact billing@{brand_lower}-invoices.net\n\n"
            "Thank you for your business.\n\n"
            "{brand} Billing Department"
        ),
        "red_flags": [
            "Unexpected invoice — business email compromise (BEC) pattern",
            "Contact address on a lookalike domain",
            "Targets accounts/finance staff who process payments",
            "Instruction not to reply (prevents verification)",
        ],
    },
}


def generate_lure_email(brand: str, link: str, template_name: str) -> dict:
    """Return a rendered phishing lure email with red flag annotations."""
    template = LURE_TEMPLATES[template_name]
    now = datetime.datetime.utcnow()
    ref = hashlib.md5(f"{brand}{now}".encode()).hexdigest()[:8].upper()

    subject = template["subject"].format(brand=brand)
    body = template["body"].format(
        brand=brand,
        brand_lower=brand.lower().replace(" ", ""),
        link=link,
        time=now.strftime("%H:%M"),
        date=(now + datetime.timedelta(days=7)).strftime("%d %b %Y"),
        ref=ref,
    )
    return {
        "from":     f"noreply@{brand.lower().replace(' ','')}-security.com",
        "subject":  subject,
        "body":     body,
        "red_flags": template["red_flags"],
    }


#  OBFUSCATION TECHNIQUES DEMONSTRATOR


def demonstrate_obfuscation(url: str):
    """Show various URL obfuscation techniques attackers use."""
    parsed = urlparse(url if "://" in url else "https://" + url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    path   = parsed.path if parsed.netloc else ""

    techniques = []

    # 1. Base64 encode the whole URL
    b64 = base64.urlsafe_b64encode(url.encode()).decode()
    techniques.append({
        "name":    "Base64 encoding",
        "result":  f"https://decode-b64.run/?q={b64}",
        "purpose": "Hides the actual URL from email scanners and human inspection",
    })

    # 2. URL percent-encoding
    encoded = "https://" + "".join(
        f"%{ord(c):02X}" if c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_~" else c
        for c in domain
    ) + path
    techniques.append({
        "name":    "Percent-encoding (URL encoding)",
        "result":  encoded,
        "purpose": "Domain looks scrambled but browsers decode it transparently",
    })

    # 3. Open redirect abuse
    techniques.append({
        "name":    "Open redirect (Google)",
        "result":  f"https://www.google.com/url?sa=t&url={url}",
        "purpose": "Link passes as google.com; victim lands on attacker site",
    })

    # 4. Shortener simulation
    short_hash = hashlib.md5(url.encode()).hexdigest()[:6]
    techniques.append({
        "name":    "URL shortener simulation",
        "result":  f"https://bit.ly/{short_hash}",
        "purpose": "Completely hides destination; bypasses reputation filters",
    })

    # 5. Data URI (for email HTML)
    data_uri = f"data:text/html;base64,{base64.b64encode(b'<html><body>Redirecting...</body></html>').decode()}"
    techniques.append({
        "name":    "Data URI redirect",
        "result":  data_uri[:80] + "...",
        "purpose": "Embedded HTML in the URL itself — no domain to block",
    })

    # 6. Subdomain spoofing
    techniques.append({
        "name":    "Subdomain spoofing",
        "result":  f"https://{domain}.attacker-server.com{path}",
        "purpose": "Victim sees legitimate brand at the start; real domain is attacker-server.com",
    })

    # 7. Homoglyph (Cyrillic substitute for 'a' and 'e')
    homoglyph_domain = domain.replace("a", "а").replace("e", "е")
    techniques.append({
        "name":    "Homoglyph / IDN homograph",
        "result":  f"https://{homoglyph_domain}{path}",
        "purpose": "Visually identical to original; different Unicode code points",
    })

    return techniques