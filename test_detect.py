from ai_service import advanced_rule_analysis

tests = [
    ("sms", "Upto Rs.10,000* Bonus is credited to your RummyCircle A/c Play Now & Win Real Cash! T&C Apply OptOut gmg.im/r", "RummyCircle spam"),
    ("sms", "Applications Open for B.Tech at MAHE Manipal. Highest CTC 69.25 LPA. NIRF Ranked. Apply Now rml.fm/xxx", "MAHE Manipal spam"),
    ("sms", "Hi, are we still meeting for coffee at 3pm today?", "Legitimate message"),
    ("email", "Dear Customer, Your account has been compromised. Click here to verify your identity immediately or your account will be suspended. https://paypal-secure.xyz/login", "Phishing email"),
    ("sms", "You have won Rs 50,00,000 in Jio Lucky Draw! Claim now: bit.ly/xyz", "Lottery scam SMS"),
]

for i, (ctype, text, label) in enumerate(tests, 1):
    r = advanced_rule_analysis(ctype, text)
    print(f"=== TEST {i}: {label} ===")
    print(f"  is_spam={r['is_spam']}  score={r['risk_score']}  level={r['risk_level']}")
    print(f"  verdict: {r['verdict']}")
    for reason in r['reasons']:
        print(f"    - {reason}")
    print()
