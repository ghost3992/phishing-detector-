from flask import Flask, request, render_template
import socket
import whois
import requests
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)

# ─── Whitelisted legitimate domains ───────────────────────────────────────────
# These are expanded to prevent false positives from PhishTank's old records
WHITELIST = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "microsoft.com", "apple.com", "amazon.com", "wikipedia.org", "reddit.com",
    "paypal.com", "ebay.com", "netflix.com", "linkedin.com", "github.com",
    "stackoverflow.com", "twitch.tv", "discord.com", "spotify.com", "zoom.us",
    "dropbox.com", "adobe.com", "salesforce.com", "shopify.com", "stripe.com",
    "allegro.pl", "olx.pl", "walmart.com", "flipkart.com", "snapdeal.com",
]

# ─── High-risk TLDs commonly used for phishing ────────────────────────────────
SUSPICIOUS_TLDS = {
    ".cyou", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
    ".click", ".loan", ".work", ".date", ".faith", ".review",
    ".stream", ".gdn", ".racing", ".win", ".download", ".accountant",
    ".cricket", ".science", ".party", ".trade", ".webcam",
}

# ─── Brand names that phishing sites often impersonate ────────────────────────
BRAND_KEYWORDS = [
    "paypal", "amazon", "google", "apple", "microsoft", "netflix",
    "facebook", "instagram", "twitter", "ebay", "allegro", "walmart",
    "steam", "discord", "snapchat", "tiktok", "linkedin", "whatsapp",
    "bank", "secure", "login", "signin", "account", "verify", "update",
    "coinbase", "binance", "crypto", "blockchain",
]


def is_whitelisted(url):
    try:
        hostname = urlparse(url).hostname or ""
        return any(hostname == d or hostname.endswith("." + d) for d in WHITELIST)
    except:
        return False


def domain_resolves(url):
    """Returns True if the domain resolves to a valid IP."""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        socket.setdefaulttimeout(5)
        socket.gethostbyname(hostname)
        return True
    except (socket.gaierror, socket.timeout):
        return False


def is_safe_for_network(url):
    """Checks if a URL is safe to contact (avoids SSRF)."""
    try:
        hostname = urlparse(url).hostname
        if not hostname: return False
        if hostname == 'localhost': return True # We have special logic for this
        
        # Resolve and check IP
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        
        if (ip.is_loopback or ip.is_private or ip.is_multicast or 
            ip.is_link_local or ip.is_reserved or ip.is_unspecified):
            return False
        return True
    except:
        return False


def normalize_url(url):
    """Converts a URL to its standard ASCII (Punycode) form."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname: return url
        
        # Convert hostname to IDNA (Punycode)
        ascii_hostname = hostname.encode('idna').decode('ascii')
        
        # Reconstruct URL
        return url.replace(hostname, ascii_hostname)
    except:
        return url


def get_redirect_destination(url):
    """Follows redirects to find the final landing page (Short link bypass)."""
    try:
        # Use HEAD to avoid downloading large bodies, follow redirects
        # Strict timeout to avoid DoS
        response = requests.head(url, allow_redirects=True, timeout=5, headers={"User-Agent": "phishing-detector/1.0"})
        return response.url
    except:
        return url


def is_local_address(url):
    """Returns True if the URL refers to localhost or a private IP range."""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return True  # Assume local if no hostname (e.g. relative path)

        if hostname == 'localhost':
            return True

        # Check if it's an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_loopback or ip.is_private
        except ValueError:
            # Not a direct IP, try resolving it (with a short timeout)
            try:
                socket.setdefaulttimeout(1)
                ip_str = socket.gethostbyname(hostname)
                ip = ipaddress.ip_address(ip_str)
                return ip.is_loopback or ip.is_private
            except (socket.gaierror, socket.timeout):
                return False
    except:
        return False


def check_suspicious_tld(url):
    """Returns True if the domain uses a high-risk TLD."""
    try:
        hostname = urlparse(url).hostname or ""
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                return True, tld
    except:
        pass
    return False, ""


def check_brand_impersonation(url):
    """Returns True if the domain contains brand names (potentially fuzzy) but isn't the real domain."""
    try:
        hostname = urlparse(url).hostname or ""
        hostname_lower = hostname.lower()
        
        # Clean hostname for fuzzy matching
        hostname_cleaned = hostname_lower
        for char in ['-', '_', '.', ' ']:
            hostname_cleaned = hostname_cleaned.replace(char, '')

        for brand in BRAND_KEYWORDS:
            if brand in hostname_cleaned:
                # Check it's not the actual brand domain
                # e.g. "paypal.com" is fine, "paypal.secure-login.xyz" is not
                if not (hostname_lower == f"{brand}.com" or
                        hostname_lower.endswith(f".{brand}.com") or
                        hostname_lower == f"{brand}.pl" or
                        hostname_lower.endswith(f".{brand}.pl") or
                        hostname_lower == f"{brand}.in" or
                        hostname_lower.endswith(f".{brand}.in") or
                        hostname_lower == f"{brand}.co.in" or
                        hostname_lower.endswith(f".{brand}.co.in")):
                    return True, brand
    except:
        pass
    return False, ""


def check_whois(url):
    """Returns: 'no_exist', 'new', 'old', or 'unknown'"""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return 'no_exist'
        
        parts = hostname.split('.')
        if len(parts) >= 3:
            # Common multi-level TLDs
            multi_level_suffixes = {
                'co.in', 'com.in', 'org.in', 'net.in', 'res.in', 'ac.in', 'gov.in', 'nic.in', 'ind.in',
                'co.uk', 'com.au', 'com.br', 'com.cn'
            }
            last_two = '.'.join(parts[-2:])
            if last_two in multi_level_suffixes:
                root = '.'.join(parts[-3:])
            else:
                root = '.'.join(parts[-2:])
        else:
            root = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

        w = whois.whois(root)
        if not w or not w.domain_name:
            return 'no_exist'
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if cd is None:
            return 'unknown'
        if cd.tzinfo is not None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.now()
        age_days = (now - cd).days
        return 'new' if age_days < 365 else 'old'
    except Exception as e:
        err = str(e).lower()
        if 'no match' in err or 'not found' in err or 'no data' in err:
            return 'no_exist'
        if 'returned no output' in err:
            return 'not_applicable'
        return 'unknown'


def check_phishtank_live(url):
    """Check if URL is in PhishTank database (LIVE).
    Flags any URL found in the database (in_database=True),
    regardless of 'valid' status — because even taken-down phishing
    domains are still dangerous."""
    try:
        url_encoded = base64.b64encode(url.encode()).decode()
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url": url_encoded,
                "format": "json",
                "app_key": ""  # Optional: add your free PhishTank API key here
            },
            headers={"User-Agent": "phishtank/phishing_detector"},
            timeout=8
        )
        print(f"  PhishTank status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", {})
            print(f"  PhishTank result: in_database={results.get('in_database')}, valid={results.get('valid')}")
            # Flag if PhishTank has EVER recorded this URL as phishing
            if results.get("in_database"):
                return True
    except Exception as e:
        print(f"  PhishTank error: {e}")
    return False


# ─── OpenPhish feed cache ──────────────────────────────────────────────────────
_openphish_feed = set()
_openphish_loaded = False


def load_openphish_feed():
    """Download the free OpenPhish feed (no API key needed)."""
    global _openphish_feed, _openphish_loaded
    try:
        response = requests.get(
            "https://openphish.com/feed.txt",
            timeout=10,
            headers={"User-Agent": "phishing-detector/1.0"}
        )
        if response.status_code == 200:
            urls = set(line.strip() for line in response.text.splitlines() if line.strip())
            _openphish_feed = urls
            _openphish_loaded = True
            print(f"  [OK] OpenPhish feed loaded: {len(urls)} URLs")
            return True
    except Exception as e:
        print(f"  OpenPhish feed load error: {e}")
    return False


@app.after_request
def add_security_headers(response):
    """Sets fundamental security headers for every response."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


def check_openphish(url):
    """Check URL against OpenPhish free feed (no API key required)."""
    global _openphish_loaded
    if not _openphish_loaded:
        load_openphish_feed()
    url_stripped = url.strip().rstrip('/')
    return url in _openphish_feed or url_stripped in _openphish_feed


# ─── Main Route ───────────────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        input_url = request.form["url"].strip()
        print(f"\n[SEARCH] Checking URL: {input_url}")

        detection_steps = []
        
        # ── Step 0: Normalization & SSRF Check ────────────────────────────────
        url = normalize_url(input_url)
        if url != input_url:
            detection_steps.append(("⚠ Internationalized Domain", f"URL normalized to Punycode: {url}"))
        
        # ── Step 0.1: Local Address Check (User Requirement: Phishing) ───────
        if is_local_address(url):
            print("[FAIL] Local/Private address detected")
            detection_steps.append(("✗ Local Address", "Personal/Local network addresses are restricted for security"))
            result = "phishing"
            return render_template("index.html", result=result, steps=detection_steps)

        # ── Step 0.2: Redirect Tracing ───────────────────────────────────────
        final_url = get_redirect_destination(url)
        if final_url != url:
            print(f"  [INFO] Redirect detected: {url} -> {final_url}")
            detection_steps.append(("⚠ URL Redirect Detected", f"Following shortener/redirect to: {urlparse(final_url).hostname}"))
            url = final_url # Analyze the landing page instead
            
        # ── Whitelist check ──────────────────────────────────────────────────
        if is_whitelisted(url):
            print("[OK] Whitelisted domain")
            detection_steps.append(("✓ Whitelisted Domain", "This domain is a known legitimate site"))
            result = "legitimate"

        else:
            detection_steps.append(("⚠ Not on whitelist", "Running full security checks..."))

            # ── Step 1: Brand Impersonation Check ───────────────────────────
            is_impersonating, brand_found = check_brand_impersonation(url)
            if is_impersonating:
                print(f"[FAIL] Brand impersonation detected: {brand_found}")
                detection_steps.append(("✗ Brand Impersonation", f"Domain impersonates '{brand_found}' but is not the real site"))
                result = "phishing"
                return render_template("index.html", result=result, steps=detection_steps)
            else:
                print("[OK] No brand impersonation detected")
                detection_steps.append(("✓ Brand Check", "No known brand impersonation detected"))

            # ── Step 2: SSRF/Network Safety ────────────────────────────────────
            if not is_safe_for_network(url):
                print("[FAIL] SSRF risk detected")
                detection_steps.append(("✗ Network Security", "Targeting disallowed internal IP range"))
                result = "phishing"
                return render_template("index.html", result=result, steps=detection_steps)

            # ── Step 3: DNS Resolution ───────────────────────────────────────
            dns_ok = domain_resolves(url)
            if dns_ok:
                print("[OK] DNS check passed")
                detection_steps.append(("✓ DNS Resolution", "Domain resolves to a valid IP"))
            else:
                print("[FAIL] DNS check failed")
                detection_steps.append(("✗ DNS Resolution", "Domain doesn't resolve — likely a fake/dead site"))
                result = "phishing"
                return render_template("index.html", result=result, steps=detection_steps)

            # ── Step 2: PhishTank database ───────────────────────────────────
            phishtank_check = check_phishtank_live(url)
            if phishtank_check:
                print("[FAIL] Found in PhishTank database")
                detection_steps.append(("✗ PhishTank Database", "URL is recorded in PhishTank's phishing database"))
                result = "phishing"
                return render_template("index.html", result=result, steps=detection_steps)
            else:
                print("[OK] Not in PhishTank")
                detection_steps.append(("✓ PhishTank Check", "Not found in PhishTank database"))

            # ── Step 3: OpenPhish feed ───────────────────────────────────────
            openphish_check = check_openphish(url)
            if openphish_check:
                print("[FAIL] Found in OpenPhish feed")
                detection_steps.append(("✗ OpenPhish Database", "URL found in active phishing feed"))
                result = "phishing"
                return render_template("index.html", result=result, steps=detection_steps)
            else:
                print("[OK] Not in OpenPhish")
                detection_steps.append(("✓ OpenPhish Check", "Not found in OpenPhish phishing feed"))

            # ── Step 4: Suspicious TLD check ────────────────────────────────
            is_bad_tld, tld_found = check_suspicious_tld(url)
            if is_bad_tld:
                print(f"[FAIL] Suspicious TLD detected: {tld_found}")
                detection_steps.append(("✗ Suspicious TLD", f"Domain uses high-risk TLD: {tld_found}"))
                result = "phishing"
                return render_template("index.html", result=result, steps=detection_steps)
            else:
                print("[OK] TLD looks normal")
                detection_steps.append(("✓ TLD Check", "Domain extension is not high-risk"))

            # ── Step 3: Domain type check ────────────────────────────────────
            hostname = urlparse(url).hostname or ""
            is_trusted_tld = any(hostname.endswith(ext) for ext in ['.gov', '.edu', '.gov.in', '.ac.in', '.nic.in'])

            if is_trusted_tld:
                print(f"[OK] Trusted government/education domain")
                detection_steps.append(("✓ Domain Type", f"Trusted government/education TLD"))
                result = "legitimate"
            else:
                # ── Step 7: WHOIS age check ──────────────────────────────────
                whois_status = check_whois(url)
                print(f"[INFO] WHOIS status: {whois_status}")

                if whois_status == 'new':
                    print("[FAIL] Domain is brand new (< 1 year old)")
                    detection_steps.append(("✗ Domain Age", "Domain registered < 1 year ago — highly suspicious"))
                    result = "phishing"
                elif whois_status == 'no_exist':
                    print("[FAIL] No WHOIS record found")
                    detection_steps.append(("✗ Domain Age", "No WHOIS record — domain may be fake or unregistered"))
                    result = "phishing"
                else:
                    print(f"[OK] Domain age OK ({whois_status})")
                    if whois_status == 'old':
                        detection_steps.append(("✓ Domain Age", "Domain is established (1+ years old)"))
                    else:
                        detection_steps.append(("✓ Domain Status", f"Domain status: {whois_status}"))
                    result = "legitimate"

        print(f"[RESULT] Result: {result}\n")
        return render_template("index.html", result=result, steps=detection_steps)
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
