import random

import pandas as pd

random.seed(42)

BRANDS = ["PayPal", "Amazon", "Netflix", "Microsoft", "Apple", "Google", "HDFC Bank", "SBI", "Facebook", "Instagram", "DHL", "FedEx"]
FAKE_DOMAINS = [
    "secure-{b}-verify.com", "{b}-login-update.net", "account-{b}.xyz", "{b}-support-center.info",
    "verify-{b}.top", "{b}-billing-alert.ru", "update-{b}-security.click", "{b}.confirm-identity.biz",
]
FAKE_IPS = ["http://192.168.{a}.{b}/login", "http://45.{a}.{b}.12/verify", "http://103.{a}.{b}.77/secure"]
REAL_DOMAINS = [
    "https://www.paypal.com", "https://www.amazon.com", "https://www.netflix.com", "https://www.microsoft.com",
    "https://www.apple.com", "https://www.google.com", "https://github.com", "https://www.linkedin.com",
    "https://docs.python.org", "https://www.wikipedia.org", "https://www.coursera.org", "https://www.nytimes.com",
]

PHISH_TEMPLATES = [
    "Urgent: Your {brand} account has been suspended. Verify your identity immediately at {url} or your account will be permanently closed.",
    "Dear customer, we detected unusual activity on your {brand} account. Click here to confirm your password: {url}",
    "Final notice! Your {brand} payment failed. Update your billing information now: {url} to avoid service termination.",
    "Congratulations! You have won a $1000 {brand} gift card. Claim your prize now by logging in at {url}",
    "Security alert: someone tried to sign in to your {brand} account. Verify your account within 24 hours {url}",
    "Your {brand} package could not be delivered. Confirm your address and pay a small fee here: {url}",
    "Action required: Your {brand} password expires today. Click {url} to keep your password and avoid losing access.",
    "We have limited your {brand} account. Please submit your card number and OTP at {url} to restore access immediately.",
    "Dear user, your mailbox is full. Login at {url} to increase your storage quota or lose important emails.",
    "Refund pending! {brand} owes you a refund of $349.99. Provide your bank details at {url} to receive payment.",
]

SAFE_TEMPLATES = [
    "Hi team, please find attached the agenda for tomorrow's meeting at 10 AM. Let me know if you want to add anything.",
    "Your {brand} order has shipped and will arrive on Friday. You can track it from your account at {url}",
    "Thanks for attending the workshop yesterday. Slides and recordings are available at {url}",
    "Reminder: the project submission deadline is next Monday. Please upload your report to the course portal.",
    "Hey, are we still on for lunch on Saturday? Let me know what time works for you.",
    "Your monthly statement from {brand} is now available. You can view it by signing in at {url}",
    "Welcome to {brand}! Here are a few tips to get started with your new account: {url}",
    "Please review the attached pull request and share your feedback before the weekend.",
    "Class notes for Data Structures are uploaded. The next lab will cover binary search trees and hashing.",
    "Happy birthday! Wishing you a wonderful year ahead. Let's catch up soon over coffee.",
    "Your receipt for the payment of $24.99 to {brand} is attached. Thank you for your purchase.",
    "The library book you requested is ready for pickup at the front desk until Thursday.",
]


def phishing_url():
    if random.random() < 0.3:
        return random.choice(FAKE_IPS).format(a=random.randint(1, 250), b=random.randint(1, 250))
    brand = random.choice(BRANDS).lower().replace(" ", "")
    domain = random.choice(FAKE_DOMAINS).format(b=brand)
    path = random.choice(["/login", "/verify?id=" + str(random.randint(1000, 9999)), "/update/account", "/secure@auth", ""])
    scheme = random.choice(["http://", "http://", "https://"])
    return scheme + domain + path


def safe_url():
    return random.choice(REAL_DOMAINS) + random.choice(["", "/account", "/help", "/orders"])


def make_row(label):
    brand = random.choice(BRANDS)
    if label == 1:
        template = random.choice(PHISH_TEMPLATES)
        text = template.format(brand=brand, url=phishing_url())
    else:
        template = random.choice(SAFE_TEMPLATES)
        text = template.format(brand=brand, url=safe_url())
    if random.random() < 0.15:
        text = text.upper() if random.random() < 0.3 else text + " Thanks."
    return text, label


def main(rows_per_class=500, output="emails.csv"):
    rows = [make_row(1) for _ in range(rows_per_class)] + [make_row(0) for _ in range(rows_per_class)]
    random.shuffle(rows)
    pd.DataFrame(rows, columns=["text", "label"]).to_csv(output, index=False)
    print(f"Saved {len(rows)} emails to {output}")


if __name__ == "__main__":
    main()
