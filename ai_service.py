import re
import hashlib
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# PhishGuard - Balanced rule-based spam / phishing / scam / fraud detector
# No external API - works 100% offline
# Key principle: require MULTIPLE strong signals before flagging as risky
# ---------------------------------------------------------------------------


# ==========================================================================
# PATTERN DATABASES
# ==========================================================================

# -- Urgency / Pressure (only phrases that are clearly manipulative) --
URGENCY_PHRASES = [
    "act now", "act immediately", "action required", "immediate action",
    "urgently", "right away", "within 24 hours",
    "within 48 hours", "limited time", "expires today",
    "last chance", "final warning", "final notice", "don't delay",
    "respond immediately", "time sensitive", "time is running out",
    "before it's too late",
    "your account will be", "will be suspended", "will be closed",
    "will be terminated", "will be deactivated", "will be locked",
    "has been compromised", "has been suspended", "has been limited",
    "unauthorized activity", "unusual activity", "suspicious activity",
    "security alert", "security warning", "security notice",
    "hours left", "minutes left",
]

# -- Credential / Personal Info Harvesting --
CREDENTIAL_PHRASES = [
    "verify your account", "verify your identity", "confirm your identity",
    "update your information", "update your details", "update your account",
    "click here to login", "click here to verify", "click below to verify",
    "enter your password", "enter your credentials", "enter your pin",
    "confirm your password", "reset your password",
    "social security number", "ssn", "mother's maiden",
    "cvv", "card number", "card details",
    "account number", "routing number", "iban", "swift code",
    "username and password", "login credentials",
    "aadhar", "aadhaar", "pan card", "pan number",
    "complete kyc", "update kyc", "kyc verification", "kyc expired",
    "link your bank", "link your upi", "link your card",
]

# -- Financial Scam Red Flags (only scammy phrases, not normal banking words) --
FINANCIAL_SCAM_PHRASES = [
    "wire transfer", "western union", "moneygram",
    "gift card", "itunes card", "google play card", "amazon gift card",
    "send money", "transfer money",
    "processing fee", "advance fee", "upfront payment", "registration fee",
    "handling fee", "customs fee",
    "guaranteed returns", "double your money",
    "risk free", "risk-free",
    "forex trading", "binary options",
]

# -- Prize / Lottery / Giveaway --
PRIZE_LOTTERY_PHRASES = [
    "you have won", "you've won", "you won",
    "you are a winner", "you have been selected", "you've been selected",
    "lucky winner", "lucky draw", "lucky customer",
    "prize winner", "claim your prize", "claim your reward",
    "claim your winnings", "collect your prize",
    "lottery winner", "lottery notification", "lottery result",
    "free iphone", "free samsung", "free laptop",
    "million dollars", "million pounds", "million euros",
    "cash prize", "grand prize",
    "spin the wheel", "scratch card", "scratch & win", "spin & win",
]

# -- Threat / Blackmail --
THREAT_PHRASES = [
    "legal action", "arrest", "criminal charges", "prosecution",
    "warrant", "jail", "prison",
    "your account has been hacked", "your data has been stolen",
    "we have your password", "we recorded you",
    "send bitcoin or", "pay or we will", "pay or else",
    "compromising photos", "compromising video",
    "we will release", "we will share", "we will expose",
]

# -- Gambling / Betting --
GAMBLING_PHRASES = [
    "rummycircle", "teen patti", "teenpatti",
    "casino", "jackpot", "betting",
    "bet now", "place bet", "wagering",
    "dream11", "dream 11", "my11circle",
    "parimatch", "1xbet", "betway", "bet365",
    "play & win", "play and win", "play now & win",
    "win real cash", "win cash", "win money",
    "real money", "real cash", "play for cash",
    "deposit bonus", "welcome bonus", "signup bonus",
    "satta", "matka", "satta matka",
]

# -- Job Scam --
JOB_SCAM_PHRASES = [
    "easy money", "earn money fast", "make money online",
    "get paid daily", "no experience needed",
    "no experience required", "no skills required",
    "data entry job", "typing job", "copy paste job",
    "earn Rs", "earn $", "earn up to", "earn upto",
    "daily income", "weekly income", "monthly income guaranteed",
    "telegram job", "whatsapp job",
    "income per day", "income per month",
    "no interview", "direct joining", "spot offer",
]

# -- Romance Scam --
ROMANCE_SCAM_PHRASES = [
    "i'm a soldier", "deployed overseas", "military deployment",
    "fell in love with your profile",
    "i need financial help", "send me money for ticket",
    "i'm stuck", "stranded", "need money to visit you",
    "i have a large inheritance", "help me move money",
]

# -- Delivery / Package Scam --
DELIVERY_SCAM_PHRASES = [
    "delivery attempt failed", "delivery failed",
    "reschedule delivery", "update delivery address",
    "confirm delivery address", "schedule redelivery",
    "pay delivery fee", "held at customs", "import duty",
]

# -- Tech Support Scam --
TECH_SUPPORT_PHRASES = [
    "virus detected", "virus found", "malware detected",
    "computer infected", "your pc is infected",
    "call this number", "call immediately", "call our tech support",
    "your ip has been flagged",
    "firewall alert", "trojan detected",
]

# -- Suspicious TLDs --
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz",
    ".click", ".pw", ".cc", ".ws", ".bid", ".stream",
    ".racing", ".download", ".win", ".loan", ".date",
    ".faith", ".review", ".science", ".party",
    ".trade", ".webcam", ".cricket", ".accountant",
    ".icu", ".monster", ".rest", ".surf", ".quest",
]

# -- URL Shorteners --
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "bc.vc", "v.gd",
    "surl.li", "s.id", "rebrand.ly", "bl.ink", "short.io",
    "lnk.to", "dub.sh", "shrtco.de",
    "mcaf.ee", "cli.re",
]

# -- Known-safe domains (never penalize these) --
TRUSTED_DOMAINS = {
    # Dev / Hosting
    "v0.app", "vercel.com", "vercel.app", "netlify.app", "netlify.com",
    "github.com", "github.io", "gitlab.com", "bitbucket.org",
    "heroku.com", "herokuapp.com", "railway.app", "render.com",
    "supabase.com", "supabase.co", "firebase.google.com", "firebaseapp.com",
    "pages.dev", "workers.dev", "fly.io", "replit.com", "repl.co",
    "stackblitz.com", "codesandbox.io", "codepen.io",
    # Major sites
    "google.com", "google.co.in", "google.co.uk", "googleapis.com",
    "youtube.com", "youtu.be",
    "facebook.com", "fb.com", "instagram.com", "threads.net",
    "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "pinterest.com", "tumblr.com",
    "tiktok.com", "snapchat.com", "discord.com", "discord.gg",
    "whatsapp.com", "telegram.org", "t.me", "signal.org",
    "amazon.com", "amazon.in", "amazon.co.uk", "amzn.to",
    "apple.com", "icloud.com", "microsoft.com", "live.com",
    "outlook.com", "office.com", "office365.com",
    "netflix.com", "spotify.com", "hulu.com", "disneyplus.com",
    "zoom.us", "meet.google.com", "teams.microsoft.com",
    "dropbox.com", "drive.google.com", "onedrive.live.com",
    "paypal.com", "stripe.com", "razorpay.com",
    "stackoverflow.com", "stackexchange.com",
    "wikipedia.org", "wikimedia.org",
    "medium.com", "substack.com", "hashnode.dev",
    "npmjs.com", "pypi.org", "crates.io",
    "cloudflare.com", "aws.amazon.com", "azure.microsoft.com",
    "docs.google.com", "forms.google.com", "sheets.google.com",
    # News
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com",
    "theguardian.com", "reuters.com", "bloomberg.com",
    "washingtonpost.com", "wsj.com", "forbes.com",
    "techcrunch.com", "theverge.com", "wired.com", "arstechnica.com",
    # Education
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    # Indian sites
    "flipkart.com", "myntra.com", "swiggy.com", "zomato.com",
    "paytm.com", "phonepe.com", "gpay.google.com",
    "hdfc.com", "hdfcbank.com", "icicibank.com", "sbi.co.in",
    "irctc.co.in", "uidai.gov.in",
    # Misc
    "notion.so", "figma.com", "canva.com", "trello.com",
    "slack.com", "asana.com", "jira.atlassian.com",
    "shopify.com", "wordpress.com", "wordpress.org",
    "wix.com", "squarespace.com",
    "twitch.tv", "vimeo.com", "dailymotion.com",
}

# -- Domain Typosquatting --
BRAND_TYPOS = {
    "paypa1": "PayPal", "paypall": "PayPal", "paypal-secure": "PayPal",
    "paypal-login": "PayPal", "paypal-verify": "PayPal",
    "amaz0n": "Amazon", "amazonn": "Amazon", "amazon-verify": "Amazon",
    "amazon-login": "Amazon",
    "micros0ft": "Microsoft", "microsft": "Microsoft",
    "microsoft-verify": "Microsoft",
    "app1e": "Apple", "appleid-verify": "Apple", "apple-support": "Apple",
    "netfl1x": "Netflix", "netflix-billing": "Netflix",
    "netflix-login": "Netflix",
    "faceb00k": "Facebook", "fb-security": "Facebook",
    "facebook-login": "Facebook",
    "googIe": "Google", "g00gle": "Google", "google-verify": "Google",
    "whatsaap": "WhatsApp", "whatsapp-verify": "WhatsApp",
    "1nstagram": "Instagram", "instagam": "Instagram",
}

# -- Brand Impersonation (only flag when combined with phishing indicators) --
IMPERSONATION_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon",
    "netflix", "facebook", "instagram", "whatsapp", "telegram",
    "wells fargo", "chase bank", "bank of america", "citibank",
    "hsbc", "barclays", "state bank of india", "sbi", "icici",
    "hdfc", "axis bank", "kotak",
    "usps", "fedex", "dhl", "ups", "india post",
    "flipkart", "uber", "zomato", "swiggy",
    "phonepe", "paytm", "google pay", "gpay",
]

# -- Known Scam Pattern Database --
KNOWN_SCAM_PATTERNS = [
    {
        "keywords": ["nigerian", "prince", "inheritance", "million dollars", "diplomat", "barrister"],
        "min_matches": 3,
        "title": "Nigerian Prince / Advance Fee Fraud (419 Scam)",
        "source": "FBI IC3, FTC",
        "date": "1990s-present",
        "category": "lottery_scam",
    },
    {
        "keywords": ["you have won", "lottery", "claim your prize", "lucky draw"],
        "min_matches": 2,
        "title": "Lottery / Prize Scam",
        "source": "FTC Consumer Alerts",
        "date": "2000s-present",
        "category": "lottery_scam",
    },
    {
        "keywords": ["your package", "delivery failed", "customs fee", "pay delivery fee"],
        "min_matches": 2,
        "title": "Package Delivery Notification Scam",
        "source": "USPS / FTC Alerts",
        "date": "2019-present",
        "category": "sms_scam",
    },
    {
        "keywords": ["verify your", "suspended", "click here to login", "update your account"],
        "min_matches": 2,
        "title": "Account Verification Phishing",
        "source": "Anti-Phishing Working Group (APWG)",
        "date": "2005-present",
        "category": "phishing_email",
    },
    {
        "keywords": ["easy money", "earn daily", "no experience", "work from home", "data entry job"],
        "min_matches": 2,
        "title": "Work-From-Home / Job Scam",
        "source": "FTC, BBB Scam Tracker",
        "date": "2015-present",
        "category": "job_scam",
    },
    {
        "keywords": ["bitcoin", "cryptocurrency", "guaranteed returns", "invest now", "double your money"],
        "min_matches": 2,
        "title": "Cryptocurrency / Investment Scam",
        "source": "SEC Investor Alerts, FTC",
        "date": "2017-present",
        "category": "investment_scam",
    },
    {
        "keywords": ["virus detected", "computer infected", "call", "tech support"],
        "min_matches": 2,
        "title": "Tech Support Scam",
        "source": "Microsoft Safety, FTC",
        "date": "2010-present",
        "category": "tech_support_scam",
    },
    {
        "keywords": ["otp", "verification code", "share this code", "do not share"],
        "min_matches": 2,
        "title": "OTP / Verification Code Interception",
        "source": "CERT-In, Cybercrime.gov.in",
        "date": "2018-present",
        "category": "sms_scam",
    },
    {
        "keywords": ["update kyc", "pan card", "aadhar", "link your bank"],
        "min_matches": 2,
        "title": "KYC Update Scam (India)",
        "source": "RBI Alerts, CERT-In",
        "date": "2020-present",
        "category": "sms_scam",
    },
    {
        "keywords": ["we recorded you", "compromising", "webcam", "send bitcoin"],
        "min_matches": 2,
        "title": "Sextortion / Blackmail Email Scam",
        "source": "FBI IC3, NCSC",
        "date": "2018-present",
        "category": "phishing_email",
    },
    {
        "keywords": ["soldier", "deployed", "military", "send money", "stranded"],
        "min_matches": 2,
        "title": "Romance / Military Impersonation Scam",
        "source": "FTC Romance Scam Report",
        "date": "2010-present",
        "category": "romance_scam",
    },
    {
        "keywords": ["gift card", "itunes", "google play", "buy gift card", "send the code"],
        "min_matches": 2,
        "title": "Gift Card Payment Scam",
        "source": "FTC Consumer Alerts",
        "date": "2016-present",
        "category": "impersonation",
    },
]


# ==========================================================================
# HELPER FUNCTIONS
# ==========================================================================

def _count_phrase_matches(content_lower, phrases):
    matched = []
    for phrase in phrases:
        if phrase in content_lower:
            matched.append(phrase)
    return len(matched), matched


def _is_trusted(domain):
    if domain in TRUSTED_DOMAINS:
        return True
    for td in TRUSTED_DOMAINS:
        if domain.endswith("." + td):
            return True
    return False


def _analyze_urls(content):
    score = 0
    reasons = []
    domains = []

    urls = re.findall(r'https?://[^\s<>"\']+', content, re.IGNORECASE)
    raw_domains = re.findall(
        r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(?:/\S*)?',
        content
    )

    all_domains = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                all_domains.add(parsed.hostname.lower())
        except Exception:
            pass
    for d in raw_domains:
        all_domains.add(d.lower())

    has_suspicious = False

    for domain in all_domains:
        domains.append(domain)

        if _is_trusted(domain):
            continue

        matched_this = False

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 15
                reasons.append(f"Suspicious domain TLD: {domain}")
                has_suspicious = True
                matched_this = True
                break

        if not matched_this:
            for shortener in URL_SHORTENERS:
                if shortener in domain or domain == shortener:
                    score += 15
                    reasons.append(f"URL shortener (hides real destination): {domain}")
                    has_suspicious = True
                    matched_this = True
                    break

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            score += 20
            reasons.append(f"IP address as URL (hides real domain): {domain}")
            has_suspicious = True

        parts = domain.split('.')
        if len(parts) > 4:
            score += 10
            reasons.append(f"Excessive subdomains (possible phishing): {domain}")
            has_suspicious = True

        for typo, brand in BRAND_TYPOS.items():
            if typo in domain:
                score += 25
                reasons.append(f"Domain impersonates {brand}: {domain}")
                has_suspicious = True
                break

    return score, reasons, domains, has_suspicious


def _detect_source_category(content_lower, matched_patterns, flags):
    if matched_patterns:
        return matched_patterns[0].get("category", "unknown")
    if flags.get("gambling", 0) >= 2:
        return "sms_scam"
    if flags.get("prize", 0) >= 2:
        return "lottery_scam"
    if flags.get("job", 0) >= 2:
        return "job_scam"
    if flags.get("threat", 0) >= 2:
        return "phishing_email"
    if flags.get("cred", 0) >= 2:
        return "phishing_email"
    if flags.get("romance", 0) >= 2:
        return "romance_scam"
    if flags.get("tech", 0) >= 2:
        return "tech_support_scam"
    if flags.get("delivery", 0) >= 2:
        return "sms_scam"
    return "unknown"


def _determine_probable_source(content_lower, content_type, matched_brands, matched_scam_names, category, flags):
    parts = []
    if matched_scam_names:
        parts.append(f"Matches known pattern: {matched_scam_names[0]}")
    if matched_brands:
        brands_str = ", ".join(b.title() for b in matched_brands[:3])
        parts.append(f"Mentions/impersonates {brands_str}")
    if flags.get("gambling", 0) >= 2:
        parts.append("Unsolicited gambling/real-money gaming promotion")

    category_labels = {
        "phishing_email": "Phishing email designed to steal credentials",
        "sms_scam": "Spam/scam SMS message (likely bulk sent)",
        "fake_website": "Fake website mimicking a legitimate service",
        "impersonation": "Brand/authority impersonation scam",
        "malware_link": "Message containing potentially dangerous links",
        "lottery_scam": "Lottery/prize scam (advance fee fraud)",
        "job_scam": "Fake job/work-from-home scam",
        "romance_scam": "Romance/dating scam",
        "tech_support_scam": "Fake tech support scam",
        "investment_scam": "Fake investment/crypto scam",
    }
    if category in category_labels and not any(category_labels[category] in p for p in parts):
        parts.append(category_labels[category])
    if content_type == "sms":
        parts.append("Delivered via SMS")
    elif content_type == "email":
        parts.append("Delivered via email")
    return ". ".join(parts) if parts else "Automated analysis complete"


# ==========================================================================
# MAIN ANALYSIS ENGINE
# ==========================================================================

async def analyze_content(content_type, content):
    return advanced_rule_analysis(content_type, content)


def advanced_rule_analysis(content_type, content):
    score = 0
    reasons = []
    content_lower = content.lower()
    flags = {}
    active_categories = 0

    # 1. Urgency / Pressure
    urgency_count, urgency_matched = _count_phrase_matches(content_lower, URGENCY_PHRASES)
    flags["urgency"] = urgency_count
    if urgency_count >= 3:
        score += 20
        reasons.append(f"Multiple urgency/pressure tactics ({urgency_count} found: {', '.join(urgency_matched[:3])})")
        active_categories += 1
    elif urgency_count >= 2:
        score += 10
        reasons.append(f"Urgency language: {', '.join(urgency_matched[:2])}")
        active_categories += 1
    elif urgency_count == 1:
        score += 4
        reasons.append(f"Urgency language: '{urgency_matched[0]}'")

    # 2. Credential Phishing
    cred_count, cred_matched = _count_phrase_matches(content_lower, CREDENTIAL_PHRASES)
    flags["cred"] = cred_count
    if cred_count >= 3:
        score += 30
        reasons.append(f"Requests sensitive personal/financial info ({', '.join(cred_matched[:3])})")
        active_categories += 1
    elif cred_count >= 2:
        score += 20
        reasons.append(f"Asks for sensitive information: {', '.join(cred_matched[:2])}")
        active_categories += 1
    elif cred_count == 1:
        score += 6
        reasons.append(f"Sensitive info keyword: '{cred_matched[0]}'")

    # 3. Financial Scam Phrases
    fin_count, fin_matched = _count_phrase_matches(content_lower, FINANCIAL_SCAM_PHRASES)
    flags["financial"] = fin_count
    if fin_count >= 3:
        score += 25
        reasons.append(f"Multiple financial scam phrases ({', '.join(fin_matched[:3])})")
        active_categories += 1
    elif fin_count >= 2:
        score += 15
        reasons.append(f"Financial scam indicators: {', '.join(fin_matched[:2])}")
        active_categories += 1
    elif fin_count == 1:
        score += 5
        reasons.append(f"Financial keyword: '{fin_matched[0]}'")

    # 4. Prize / Lottery
    prize_count, prize_matched = _count_phrase_matches(content_lower, PRIZE_LOTTERY_PHRASES)
    flags["prize"] = prize_count
    if prize_count >= 2:
        score += 30
        reasons.append(f"Lottery/prize scam indicators ({', '.join(prize_matched[:3])})")
        active_categories += 1
    elif prize_count == 1:
        score += 8
        reasons.append(f"Prize/lottery language: '{prize_matched[0]}'")

    # 5. Threats / Blackmail
    threat_count, threat_matched = _count_phrase_matches(content_lower, THREAT_PHRASES)
    flags["threat"] = threat_count
    if threat_count >= 2:
        score += 30
        reasons.append(f"Threatening/blackmail language ({', '.join(threat_matched[:3])})")
        active_categories += 1
    elif threat_count == 1:
        score += 10
        reasons.append(f"Threatening language: '{threat_matched[0]}'")

    # 6. Gambling / Betting
    gambling_count, gambling_matched = _count_phrase_matches(content_lower, GAMBLING_PHRASES)
    flags["gambling"] = gambling_count
    if gambling_count >= 3:
        score += 35
        reasons.append(f"Gambling/betting spam ({', '.join(gambling_matched[:3])})")
        active_categories += 1
    elif gambling_count >= 2:
        score += 20
        reasons.append(f"Gambling/betting content: {', '.join(gambling_matched[:2])}")
        active_categories += 1
    elif gambling_count == 1:
        score += 5
        reasons.append(f"Gambling keyword: '{gambling_matched[0]}'")

    # 7. Job Scam
    job_count, job_matched = _count_phrase_matches(content_lower, JOB_SCAM_PHRASES)
    flags["job"] = job_count
    if job_count >= 3:
        score += 28
        reasons.append(f"Job scam indicators ({', '.join(job_matched[:3])})")
        active_categories += 1
    elif job_count >= 2:
        score += 18
        reasons.append(f"Potential job scam: {', '.join(job_matched[:2])}")
        active_categories += 1
    elif job_count == 1:
        score += 4
        reasons.append(f"Job-related phrase: '{job_matched[0]}'")

    # 8. Romance Scam
    romance_count, romance_matched = _count_phrase_matches(content_lower, ROMANCE_SCAM_PHRASES)
    flags["romance"] = romance_count
    if romance_count >= 2:
        score += 30
        reasons.append(f"Romance scam indicators ({', '.join(romance_matched[:3])})")
        active_categories += 1
    elif romance_count == 1:
        score += 8
        reasons.append(f"Romance scam signal: '{romance_matched[0]}'")

    # 9. Delivery / Package Scam
    delivery_count, delivery_matched = _count_phrase_matches(content_lower, DELIVERY_SCAM_PHRASES)
    flags["delivery"] = delivery_count
    if delivery_count >= 2:
        score += 25
        reasons.append(f"Fake delivery notification ({', '.join(delivery_matched[:3])})")
        active_categories += 1
    elif delivery_count == 1:
        score += 5
        reasons.append(f"Delivery-related phrase: '{delivery_matched[0]}'")

    # 10. Tech Support Scam
    tech_count, tech_matched = _count_phrase_matches(content_lower, TECH_SUPPORT_PHRASES)
    flags["tech"] = tech_count
    if tech_count >= 2:
        score += 28
        reasons.append(f"Tech support scam ({', '.join(tech_matched[:3])})")
        active_categories += 1
    elif tech_count == 1:
        score += 8
        reasons.append(f"Tech support scam signal: '{tech_matched[0]}'")

    # 11. Brand Impersonation (only flag with OTHER indicators)
    matched_brands = []
    for brand in IMPERSONATION_BRANDS:
        if brand in content_lower:
            matched_brands.append(brand)
    if matched_brands and (urgency_count >= 2 or cred_count >= 2 or threat_count >= 1):
        score += 15
        reasons.append(f"Possible brand impersonation: {', '.join(b.title() for b in matched_brands[:3])}")

    # 12. URL Analysis
    url_score, url_reasons, domains, has_suspicious_url = _analyze_urls(content)
    score += url_score
    reasons.extend(url_reasons)
    if has_suspicious_url:
        active_categories += 1

    # 13. Scam grammar patterns
    generic_greeting = re.search(
        r'\bdear\s+(?:valued\s+)?(?:customer|user|member|sir/?madam|beneficiary|account\s*holder)\b',
        content_lower
    )
    if generic_greeting and (urgency_count > 0 or cred_count > 0):
        score += 8
        reasons.append("Generic greeting ('Dear Customer') combined with pressure tactics")

    click_here = re.search(r'\bclick\s+(?:here|below|the\s+link|on\s+the)\b', content_lower)
    if click_here and (cred_count > 0 or urgency_count > 0):
        score += 6
        reasons.append("Directs user to click a link in suspicious context")

    # 14. Match Known Scam Patterns
    matched_scam_patterns = []
    for pattern in KNOWN_SCAM_PATTERNS:
        keyword_matches = sum(1 for kw in pattern["keywords"] if kw in content_lower)
        min_required = pattern.get("min_matches", 2)
        if keyword_matches >= min_required:
            similarity = min(keyword_matches / len(pattern["keywords"]), 1.0)
            matched_scam_patterns.append({
                "title": pattern["title"],
                "similarity": round(similarity, 2),
                "source": pattern["source"],
                "date": pattern["date"],
                "category": pattern.get("category", "unknown"),
            })
            score += 10

    matched_scam_patterns.sort(key=lambda x: x["similarity"], reverse=True)
    matched_scam_patterns = matched_scam_patterns[:5]
    matched_scam_output = [
        {"title": p["title"], "similarity": p["similarity"], "source": p["source"], "date": p["date"]}
        for p in matched_scam_patterns
    ]

    # 15. Content-type specific
    if content_type == "sms" and has_suspicious_url:
        score += 8
        reasons.append("SMS containing suspicious link (smishing risk)")

    # === FINAL SCORING ===
    score = min(score, 100)

    if active_categories >= 4:
        score = max(score, 80)
    elif active_categories >= 3:
        score = max(score, 60)
    elif active_categories >= 2:
        score = max(score, 40)

    if score < 20:
        risk_level = "safe"
    elif score < 35:
        risk_level = "low"
    elif score < 55:
        risk_level = "medium"
    elif score < 75:
        risk_level = "high"
    else:
        risk_level = "critical"

    is_spam = score >= 35

    source_category = _detect_source_category(content_lower, matched_scam_patterns, flags)
    matched_scam_names = [p["title"] for p in matched_scam_patterns]
    probable_source = _determine_probable_source(
        content_lower, content_type, matched_brands, matched_scam_names, source_category, flags
    )
    if not is_spam:
        source_category = "legitimate"

    if score >= 75:
        verdict = "CRITICAL - Almost certainly a scam or phishing attempt"
    elif score >= 55:
        verdict = "HIGH RISK - Strong scam/phishing indicators detected"
    elif score >= 35:
        verdict = "SUSPICIOUS - Multiple warning signs found"
    elif score >= 20:
        verdict = "LOW RISK - Minor concerns, but likely safe"
    else:
        verdict = "SAFE - No significant threat indicators found"

    recommendations = []
    if score >= 55:
        recommendations.extend([
            "Do NOT click any links in this message",
            "Do NOT share any personal or financial information",
            "Block and report the sender immediately",
            "If it claims to be from a company, contact them directly via their official app/website",
            "Report to cybercrime helpline (1930 in India, ic3.gov in US)",
        ])
    elif score >= 35:
        recommendations.extend([
            "Be cautious - verify the sender's identity before taking action",
            "Do not click links from unknown senders",
            "If it mentions a company, verify via their official website",
        ])
    elif score >= 20:
        recommendations.extend([
            "Content appears mostly safe but stay vigilant",
            "Verify sender identity if this is unexpected",
        ])
    else:
        recommendations.append("No action needed - content appears legitimate and safe")

    if matched_brands and score >= 35:
        recommendations.append(
            f"If this claims to be from {matched_brands[0].title()}, verify via their official app/website"
        )

    if active_categories >= 4:
        confidence = 0.95
    elif active_categories >= 3:
        confidence = 0.88
    elif active_categories >= 2:
        confidence = 0.80
    elif len(reasons) >= 2:
        confidence = 0.65
    elif len(reasons) >= 1:
        confidence = 0.50
    else:
        confidence = 0.85

    # === ADVISORIES (cautionary info even for safe content) ===
    advisories = []

    # Bank-related advisory: ALWAYS show if banking keywords are found
    bank_keywords = [
        "bank", "otp", "upi", "neft", "imps", "rtgs", "credit card",
        "debit card", "atm", "pin", "cvv", "account number", "ifsc",
        "net banking", "netbanking", "mobile banking", "internet banking",
        "transaction", "transfer", "emi", "loan", "sbi", "hdfc", "icici",
        "axis", "kotak", "pnb", "bob", "canara", "union bank",
        "rbi", "reserve bank", "banking", "card number", "16 digit",
        "card details", "expiry date", "card expiry", "verification code",
        "phonepe", "google pay", "gpay", "paytm", "bhim",
    ]
    is_bank_related = any(kw in content_lower for kw in bank_keywords)
    if is_bank_related:
        advisories.append({
            "type": "bank_safety",
            "severity": "critical",
            "title": "Banking Safety Warning",
            "message": (
                "NEVER share your OTP, PIN, CVV, 16-digit card number, "
                "UPI PIN, net banking password, or any verification code "
                "with anyone — not even bank officials. "
                "No bank or payment app will ever ask for these details "
                "via call, SMS, or email. If someone asks, it is a SCAM."
            ),
        })

    # Promotional / marketing advisory for safe-looking content
    promo_keywords = [
        "% off", "percent off", "discount", "coupon", "promo code",
        "use code", "offer", "sale", "free shipping", "limited offer",
        "deal", "cashback", "cash back", "buy now", "order now",
        "shop now", "exclusive offer", "special offer",
    ]
    has_promo = any(kw in content_lower for kw in promo_keywords)
    if has_promo and score < 35:
        advisories.append({
            "type": "promo_caution",
            "severity": "info",
            "title": "Promotional Message Notice",
            "message": (
                "This looks like a promotional/marketing message. "
                "Legitimate brands with domains like .com, .in, .org are usually real, "
                "but keep in mind — most reputable brands do NOT contact you via "
                "unsolicited SMS or email unless you have signed up or shared your "
                "information with them. If you did not subscribe, treat this with caution."
            ),
        })

    # Unsolicited contact advisory for SMS/email from unknown sources
    if content_type in ("sms", "email") and score < 35 and not has_promo:
        has_link = bool(re.findall(r'https?://[^\s]+', content))
        if has_link:
            advisories.append({
                "type": "unsolicited_link",
                "severity": "warning",
                "title": "Link in Message",
                "message": (
                    "This message contains a link. Even if the content looks safe, "
                    "be cautious clicking links from unknown senders. "
                    "Verify the sender before visiting any URL."
                ),
            })

    return {
        "is_spam": is_spam,
        "risk_score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "reasons": reasons if reasons else ["No threat indicators detected - this content looks safe"],
        "probable_source": probable_source,
        "source_category": source_category,
        "matched_scam_patterns": matched_scam_output,
        "recommendations": recommendations,
        "confidence": confidence,
        "advisories": advisories,
    }


def compute_content_hash(content):
    return hashlib.sha256(content.strip().lower().encode()).hexdigest()
