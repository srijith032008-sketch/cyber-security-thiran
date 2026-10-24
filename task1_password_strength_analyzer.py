import getpass
import hashlib
import math
import os
import re
import secrets
import sqlite3
import string

DB_FILE = "password_history.db"

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "696969", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321", "superman",
    "1qaz2wsx", "7777777", "121212", "000000", "qazwsx", "123qwe", "killer",
    "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
    "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
    "starwars", "klaster", "112233", "george", "computer", "michelle", "jessica",
    "pepper", "1111", "zxcvbn", "555555", "11111111", "131313", "freedom",
    "777777", "pass", "maggie", "159753", "aaaaaa", "ginger", "princess",
    "joshua", "cheese", "amanda", "summer", "love", "ashley", "nicole",
    "chelsea", "biteme", "matthew", "access", "yankees", "987654321", "dallas",
    "austin", "thunder", "taylor", "matrix", "admin", "welcome", "login",
    "passw0rd", "password1", "p@ssw0rd", "admin123", "welcome1", "qwerty123",
}

KEYBOARD_SEQUENCES = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz"]

LEET_MAP = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"})


def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS password_history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT NOT NULL,"
        "salt BLOB NOT NULL,"
        "hash BLOB NOT NULL)"
    )
    conn.commit()
    return conn


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)


def is_reused(conn, username, password):
    rows = conn.execute("SELECT salt, hash FROM password_history WHERE username = ?", (username,)).fetchall()
    for salt, stored in rows:
        if secrets.compare_digest(hash_password(password, salt), stored):
            return True
    return False


def store_password(conn, username, password):
    salt = os.urandom(16)
    conn.execute(
        "INSERT INTO password_history (username, salt, hash) VALUES (?, ?, ?)",
        (username, salt, hash_password(password, salt)),
    )
    conn.commit()


def charset_size(password):
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 32
    return size


def entropy_bits(password):
    size = charset_size(password)
    if size == 0:
        return 0.0
    return len(password) * math.log2(size)


def has_sequence(password, length=4):
    lowered = password.lower()
    for seq in KEYBOARD_SEQUENCES:
        for i in range(len(seq) - length + 1):
            chunk = seq[i:i + length]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def has_repeats(password, count=3):
    return re.search(r"(.)\1{%d,}" % (count - 1), password) is not None


def is_common(password):
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        return True
    return lowered.translate(LEET_MAP) in COMMON_PASSWORDS


def analyze(password, conn=None, username=None):
    score = 0
    issues = []
    length = len(password)

    if length >= 16:
        score += 30
    elif length >= 12:
        score += 22
    elif length >= 8:
        score += 12
    else:
        issues.append("Use at least 12 characters")

    checks = [
        (r"[a-z]", "Add lowercase letters"),
        (r"[A-Z]", "Add uppercase letters"),
        (r"\d", "Add digits"),
        (r"[^a-zA-Z0-9]", "Add special characters"),
    ]
    for pattern, message in checks:
        if re.search(pattern, password):
            score += 10
        else:
            issues.append(message)

    bits = entropy_bits(password)
    score += min(30, int(bits / 4))

    if is_common(password):
        score = min(score, 10)
        issues.append("This is a very common password")
    if has_sequence(password):
        score -= 10
        issues.append("Avoid keyboard or alphabet sequences")
    if has_repeats(password):
        score -= 10
        issues.append("Avoid repeated characters")
    if len(set(password)) < max(4, length // 2):
        score -= 10
        issues.append("Use more unique characters")

    reused = False
    if conn is not None and username:
        reused = is_reused(conn, username, password)
        if reused:
            score = min(score, 5)
            issues.append("You have used this password before")

    score = max(0, min(100, score))

    if score >= 80:
        rating = "Very Strong"
    elif score >= 60:
        rating = "Strong"
    elif score >= 40:
        rating = "Moderate"
    elif score >= 20:
        rating = "Weak"
    else:
        rating = "Very Weak"

    return {
        "length": length,
        "entropy": round(bits, 1),
        "score": score,
        "rating": rating,
        "issues": issues,
        "reused": reused,
    }


def generate_password(length=16):
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+[]{};:,.?"]
    chars = [secrets.choice(pool) for pool in pools]
    allowed = "".join(pools)
    chars += [secrets.choice(allowed) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words=4):
    wordlist = [
        "falcon", "river", "marble", "orbit", "ember", "cactus", "violet", "harbor",
        "pixel", "thunder", "meadow", "quartz", "lantern", "glacier", "comet", "saffron",
        "bridge", "velvet", "anchor", "willow", "jungle", "copper", "nebula", "puzzle",
    ]
    chosen = [secrets.choice(wordlist).capitalize() for _ in range(words)]
    return "-".join(chosen) + "-" + str(secrets.randbelow(900) + 100) + secrets.choice("!@#$%")


def suggest_alternatives(count=3):
    suggestions = [generate_password(16) for _ in range(count - 1)]
    suggestions.append(generate_passphrase())
    return suggestions


def print_report(result):
    print("\n----- Password Report -----")
    print(f"Length   : {result['length']}")
    print(f"Entropy  : {result['entropy']} bits")
    print(f"Score    : {result['score']}/100")
    print(f"Rating   : {result['rating']}")
    if result["issues"]:
        print("Suggestions:")
        for issue in result["issues"]:
            print(f"  - {issue}")
    else:
        print("No issues found")


def main():
    conn = init_db()
    print("=== Password Strength Analyzer ===")
    username = input("Username (leave blank to skip history check): ").strip()

    while True:
        password = getpass.getpass("Enter password (blank to quit): ")
        if not password:
            break

        result = analyze(password, conn, username or None)
        print_report(result)

        if result["score"] < 60:
            print("\nStronger alternatives:")
            for item in suggest_alternatives():
                print(f"  {item}")

        if username and result["score"] >= 60 and not result["reused"]:
            choice = input("\nSave this password to history to prevent reuse? (y/n): ").strip().lower()
            if choice == "y":
                store_password(conn, username, password)
                print("Password hash saved")

    conn.close()


if __name__ == "__main__":
    main()
