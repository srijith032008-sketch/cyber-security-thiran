import argparse
import re
import sys

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import ConfusionMatrixDisplay, accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

URL_PATTERN = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)", re.IGNORECASE)
IP_URL_PATTERN = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")
SUSPICIOUS_TLDS = (".xyz", ".top", ".click", ".ru", ".info", ".biz", ".tk", ".ml", ".gq", ".cf")
KEYWORDS = [
    "urgent", "verify", "suspended", "password", "confirm", "login", "account", "click",
    "immediately", "bank", "otp", "limited", "security", "update", "winner", "prize",
    "refund", "billing", "expire", "alert", "credit card", "ssn", "invoice", "gift card",
]

FEATURE_NAMES = [
    "num_urls", "has_ip_url", "has_http_only", "max_url_length", "num_at_symbols_in_urls",
    "num_hyphens_in_urls", "num_dots_in_urls", "suspicious_tld", "keyword_count",
    "exclamation_count", "uppercase_ratio", "text_length", "digit_ratio",
]


def extract_features(text):
    text = str(text)
    urls = URL_PATTERN.findall(text)
    lowered = text.lower()
    letters = [c for c in text if c.isalpha()]
    return [
        len(urls),
        1 if IP_URL_PATTERN.search(text) else 0,
        1 if any(u.lower().startswith("http://") for u in urls) else 0,
        max((len(u) for u in urls), default=0),
        sum(u.count("@") for u in urls),
        sum(u.count("-") for u in urls),
        sum(u.count(".") for u in urls),
        1 if any(tld in u.lower() for u in urls for tld in SUSPICIOUS_TLDS) else 0,
        sum(lowered.count(k) for k in KEYWORDS),
        text.count("!"),
        sum(1 for c in letters if c.isupper()) / len(letters) if letters else 0,
        len(text),
        sum(c.isdigit() for c in text) / len(text) if text else 0,
    ]


def clean_text(text):
    text = URL_PATTERN.sub(" urltoken ", str(text).lower())
    text = re.sub(r"\d+", " ", text)
    return re.sub(r"[^a-z\s]", " ", text)


def build_matrix(texts, vectorizer, scaler, fit=False):
    cleaned = [clean_text(t) for t in texts]
    handcrafted = np.array([extract_features(t) for t in texts], dtype=float)
    if fit:
        tfidf = vectorizer.fit_transform(cleaned)
        scaled = scaler.fit_transform(handcrafted)
    else:
        tfidf = vectorizer.transform(cleaned)
        scaled = scaler.transform(handcrafted)
    return hstack([tfidf, csr_matrix(scaled)]).tocsr()


def load_data(path):
    df = pd.read_csv(path)
    df = df.rename(columns={c: c.lower() for c in df.columns})
    if "text" not in df.columns:
        for alt in ("email text", "email_text", "body", "content", "message"):
            if alt in df.columns:
                df = df.rename(columns={alt: "text"})
                break
    if "label" not in df.columns:
        for alt in ("email type", "email_type", "class", "target", "spam"):
            if alt in df.columns:
                df = df.rename(columns={alt: "label"})
                break
    if "text" not in df.columns or "label" not in df.columns:
        print("CSV must contain a text column and a label column")
        sys.exit(1)
    df = df[["text", "label"]].dropna().drop_duplicates()
    if df["label"].dtype == object:
        mapping = {"phishing email": 1, "phishing": 1, "spam": 1, "1": 1, "safe email": 0, "safe": 0, "legitimate": 0, "ham": 0, "0": 0}
        df["label"] = df["label"].astype(str).str.lower().map(mapping)
        df = df.dropna()
    df["label"] = df["label"].astype(int)
    return df


def evaluate(name, model, X_test, y_test):
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    matrix = confusion_matrix(y_test, predictions)
    print(f"\n===== {name} =====")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print("Confusion Matrix:")
    print(pd.DataFrame(matrix, index=["Actual Safe", "Actual Phishing"], columns=["Pred Safe", "Pred Phishing"]))
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=["Safe", "Phishing"]))
    return accuracy, matrix


def save_confusion_matrix(matrix, name, filename):
    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay(matrix, display_labels=["Safe", "Phishing"]).plot(ax=ax, cmap="Blues", colorbar=False)
    ax.set_title(f"Confusion Matrix - {name}")
    fig.tight_layout()
    fig.savefig(filename, dpi=150)
    plt.close(fig)


def train(data_path, model_path):
    df = load_data(data_path)
    print(f"Loaded {len(df)} emails | Phishing: {int(df['label'].sum())} | Safe: {int((df['label'] == 0).sum())}")

    X_train_text, X_test_text, y_train, y_test = train_test_split(
        df["text"].tolist(), df["label"].values, test_size=0.2, random_state=42, stratify=df["label"].values
    )

    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words="english", min_df=2)
    scaler = StandardScaler()
    X_train = build_matrix(X_train_text, vectorizer, scaler, fit=True)
    X_test = build_matrix(X_test_text, vectorizer, scaler)

    candidates = {
        "Logistic Regression": LogisticRegression(max_iter=1000, class_weight="balanced"),
        "Random Forest": RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1),
    }

    best_name, best_model, best_accuracy, best_matrix = None, None, -1, None
    for name, model in candidates.items():
        model.fit(X_train, y_train)
        accuracy, matrix = evaluate(name, model, X_test, y_test)
        if accuracy > best_accuracy:
            best_name, best_model, best_accuracy, best_matrix = name, model, accuracy, matrix

    print(f"\nBest model: {best_name} ({best_accuracy * 100:.2f}% accuracy)")
    save_confusion_matrix(best_matrix, best_name, "confusion_matrix.png")
    print("Confusion matrix image saved to confusion_matrix.png")

    joblib.dump({"model": best_model, "vectorizer": vectorizer, "scaler": scaler}, model_path)
    print(f"Model saved to {model_path}")


def predict(model_path, text):
    bundle = joblib.load(model_path)
    X = build_matrix([text], bundle["vectorizer"], bundle["scaler"])
    model = bundle["model"]
    label = model.predict(X)[0]
    probability = model.predict_proba(X)[0][1]
    return ("Phishing" if label == 1 else "Safe"), probability


def interactive(model_path):
    print("\nEnter an email to classify (type END on a new line to submit, QUIT to exit)")
    while True:
        lines = []
        while True:
            line = input("> ")
            if line.strip().upper() == "QUIT":
                return
            if line.strip().upper() == "END":
                break
            lines.append(line)
        if not lines:
            continue
        verdict, probability = predict(model_path, "\n".join(lines))
        print(f"Result: {verdict} (phishing probability {probability * 100:.1f}%)\n")


def main():
    parser = argparse.ArgumentParser(description="Phishing email detection model")
    parser.add_argument("--data", default="emails.csv", help="CSV with text and label columns (1 = phishing, 0 = safe)")
    parser.add_argument("--model", default="phishing_model.joblib")
    parser.add_argument("--predict", action="store_true", help="Classify emails interactively using a saved model")
    args = parser.parse_args()

    if args.predict:
        interactive(args.model)
    else:
        train(args.data, args.model)
        interactive_choice = input("\nTest the model on your own email text? (y/n): ").strip().lower()
        if interactive_choice == "y":
            interactive(args.model)


if __name__ == "__main__":
    main()
