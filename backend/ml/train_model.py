"""
PhishGuard AI — Deep Learning Model Training Script
Generates synthetic training data and trains the deep neural network classifiers.
"""

import sys
import os
import random
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from ml.features import extract_url_features, extract_email_features, get_url_feature_names, get_email_feature_names
from ml.classifier import PhishingClassifier


# ─── Synthetic Data Generation ───────────────────────────────────────────

SAFE_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',
    'github.com', 'stackoverflow.com', 'reddit.com', 'netflix.com', 'spotify.com',
    'kaspi.kz', 'halykbank.kz', 'gov.kz', 'egov.kz', 'nur.kz',
    'mail.ru', 'yandex.ru', 'vk.com', 'ok.ru', 'sberbank.ru',
    'zoom.us', 'slack.com', 'notion.so', 'figma.com', 'vercel.com',
    'dropbox.com', 'paypal.com', 'ebay.com', 'twitch.tv', 'discord.com',
    'telegram.org', 'whatsapp.com', 'tiktok.com', 'pinterest.com', 'medium.com',
]

SAFE_PATHS = [
    '', '/', '/about', '/contact', '/help', '/products', '/services',
    '/blog', '/news', '/faq', '/terms', '/privacy', '/search',
    '/en/home', '/ru/main', '/kz/about', '/docs/getting-started',
    '/careers', '/pricing', '/support', '/features', '/download',
    '/settings', '/profile', '/dashboard', '/api/docs', '/status',
]

PHISHING_PATTERNS = [
    'http://{domain}-secure-login.tk/verify/{path}',
    'http://{domain}.account-verify.ml/{path}',
    'http://{domain}-update.ga/signin/{path}',
    'http://www.{domain}.security-alert.xyz/{path}',
    'http://login-{domain}.cf/account/{path}',
    'http://{domain}.password-reset.top/{path}',
    'http://secure-{domain}.gq/update/{path}',
    'http://192.168.{ip1}.{ip2}/login/{path}',
    'http://{domain}-banking.win/confirm/{path}',
    'http://myaccount-{domain}.bid/restore/{path}',
    'http://{domain}.credential-update.stream/{path}',
    'http://verify-{domain}.click/authenticate/{path}',
    'http://alert-{domain}.link/suspend/{path}',
    'http://{domain}-wallet.buzz/unlock/{path}',
    'http://{random}.tk/free-gift/{path}',
    'http://{domain}-recovery.racing/{path}',
    'http://auth-{domain}.download/confirm/{path}',
    'http://{domain}.account-review.loan/{path}',
    'http://update-{domain}.date/verify/{path}',
    'http://{domain}-support.faith/restore/{path}',
    'http://10.{ip1}.{ip2}.{ip1}/admin/{path}',
    'http://{random}{random}.science/prize/{path}',
    'http://security.{domain}-alert.party/{path}',
    'http://{domain}-notification.work/action/{path}',
]

PHISHING_EMAIL_SUBJECTS = [
    'URGENT: Your account has been suspended!',
    'Action Required: Verify your identity now',
    'Security Alert: Unauthorized access detected',
    'Your password will expire in 24 hours',
    'Congratulations! You won a $1000 gift card!',
    'Срочно: Ваш аккаунт заблокирован!',
    'Внимание: Подозрительная активность на вашем счёте',
    'Подтвердите вашу личность немедленно',
    'Шұғыл: Сіздің аккаунтыңыз бұғатталды!',
    'Қауіпсіздік ескертуі: Құпиясөзіңізді жаңартыңыз',
    'WARNING: Account will be terminated',
    'Your payment has been declined - act now!',
    'Final Notice: Update your information',
    'You have 1 new security message',
    'Restricted account - verify immediately',
    'Уведомление: Подтвердите платёж',
    'Ваш аккаунт будет удалён через 24 часа!',
    'Сіздің картаңыз бұғатталды, тексеріңіз!',
]

PHISHING_EMAIL_BODIES = [
    'Dear Customer, We have detected unauthorized access to your account. Click here immediately to verify your identity: http://bank-secure-login.tk/verify. Failure to do so within 24 hours will result in permanent account suspension.',
    'URGENT! Your PayPal account has been limited. Please confirm your details at http://paypal-update.ml/confirm to restore access. Act NOW!',
    'Уважаемый клиент! Мы обнаружили подозрительную активность. Немедленно подтвердите данные: http://bank-verify.ga/login. В противном случае ваш счёт будет заблокирован.',
    'Құрметті клиент! Сіздің шотыңызда күдікті белсенділік анықталды. Мұнда басыңыз: http://kaspi-secure.tk/verify. Тексеруден өтпесеңіз, шотыңыз бұғатталады.',
    'You have won $5000! Claim your prize NOW at http://free-reward.xyz/claim. Limited time offer!!!',
    'Your Apple ID was used to sign in to iCloud. If this was not you, click http://apple-verify.ml/security to secure your account IMMEDIATELY.',
    'IMPORTANT: Your Netflix subscription payment failed. Update your payment method at http://netflix-billing.tk/update or your account will be closed.',
    'Внимание! На вашу карту поступил перевод на сумму 150 000 тенге. Подтвердите получение: http://bank-transfer.ga/confirm',
    'Dear User, We noticed unusual activity on your account. For your security, please verify your identity: http://account-security.cf/verify. This is an automated message.',
    'Сіздің Kaspi Gold картаңызбен күдікті транзакция анықталды. Растау үшін мұнда басыңыз: http://kaspi-alert.tk/check',
]

SAFE_EMAIL_SUBJECTS = [
    'Meeting reminder for tomorrow',
    'Your order has been shipped',
    'Weekly newsletter - Top stories',
    'Welcome to our service',
    'Invoice #12345 attached',
    'Кездесу туралы еске салу',
    'Сіздің тапсырысыңыз жіберілді',
    'Апталық жаңалықтар бюллетені',
    'Project update: Sprint review notes',
    'Your monthly statement is ready',
    'New comment on your post',
    'Reminder: Team standup at 10 AM',
    'Thank you for your purchase',
    'Your feedback matters to us',
    'Upcoming events this week',
    'Жаңа жауап: Сіздің сұрағыңызға',
    'Ежемесячный отчёт готов к просмотру',
    'Приглашение на вебинар',
]

SAFE_EMAIL_BODIES = [
    'Hi, just wanted to remind you about our meeting tomorrow at 2 PM. See you there!',
    'Your order #12345 has been shipped and will arrive in 3-5 business days. Track your order at https://amazon.com/orders.',
    'This week\'s top stories include new product launches and community events. Read more on our blog.',
    'Сәлеметсіз бе! Ертеңгі кездесу туралы еске саламын. Сағат 14:00-де кездесеміз.',
    'Сіздің тапсырысыңыз жіберілді. 3-5 жұмыс күні ішінде жеткізіледі.',
    'Thank you for signing up! Your account has been created successfully. Get started by visiting https://app.example.com/dashboard.',
    'Here are the sprint review notes from today\'s meeting. Please review and share your feedback by Friday.',
    'Your monthly bank statement for January 2025 is now available. Log in to your account at https://halykbank.kz to view it.',
    'Hi team, please find attached the quarterly report. Let me know if you have any questions.',
    'Здравствуйте! Ваш заказ доставлен. Спасибо за покупку! Оцените качество обслуживания.',
]


def generate_url_dataset(n_samples: int = 5000) -> pd.DataFrame:
    """Generate synthetic URL dataset for deep learning training."""
    data = []

    # Generate safe URLs
    for _ in range(n_samples):
        domain = random.choice(SAFE_DOMAINS)
        path = random.choice(SAFE_PATHS)
        protocol = random.choice(['https://', 'https://www.'])
        url = f"{protocol}{domain}{path}"

        features = extract_url_features(url)
        features['label'] = 0
        data.append(features)

    # Generate phishing URLs
    for _ in range(n_samples):
        domain = random.choice(SAFE_DOMAINS).split('.')[0]
        pattern = random.choice(PHISHING_PATTERNS)
        url = pattern.format(
            domain=domain,
            path=random.choice(['verify', 'confirm', 'update', 'login', 'secure', '']),
            ip1=random.randint(1, 254),
            ip2=random.randint(1, 254),
            random=''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(6, 12)))
        )

        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)

    return pd.DataFrame(data)


def generate_email_dataset(n_samples: int = 3000) -> pd.DataFrame:
    """Generate synthetic email dataset for deep learning training."""
    data = []

    # Safe emails
    for _ in range(n_samples):
        subject = random.choice(SAFE_EMAIL_SUBJECTS)
        body = random.choice(SAFE_EMAIL_BODIES)
        sender = f"{random.choice(['john', 'anna', 'manager', 'info', 'support', 'team', 'noreply', 'admin'])}@{random.choice(SAFE_DOMAINS)}"

        features = extract_email_features(subject, body, sender)
        features['label'] = 0
        data.append(features)

    # Phishing emails
    for _ in range(n_samples):
        subject = random.choice(PHISHING_EMAIL_SUBJECTS)
        body = random.choice(PHISHING_EMAIL_BODIES)
        sender = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(5, 10)))}@{random.choice(['mail.tk', 'secure-alert.ml', 'verify.ga', 'update.cf', 'login.xyz', 'alert.top', 'bank-notify.win', 'security.bid'])}"

        features = extract_email_features(subject, body, sender)
        features['label'] = 1
        data.append(features)

    return pd.DataFrame(data)


def train_url_model():
    """Train and save URL phishing deep learning classifier."""
    print("=" * 65)
    print("🔗 Training URL Phishing Classifier (Deep Learning)")
    print("=" * 65)

    df = generate_url_dataset(5000)
    feature_names = get_url_feature_names()
    X = df[feature_names].values
    y = df['label'].values

    print(f"\n📦 Dataset: {len(df)} samples ({(y==0).sum()} safe, {(y==1).sum()} phishing)")
    print(f"📐 Features: {len(feature_names)}")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    classifier = PhishingClassifier()
    metrics = classifier.train(X_train, y_train, feature_names, epochs=150, batch_size=64, lr=0.001)

    # ── Evaluate on test set ──
    print(f"\n{'─' * 50}")
    print(f"📊 Training Summary:")
    print(f"   Architecture:      {metrics['architecture']}")
    print(f"   Parameters:        {metrics['total_parameters']:,}")
    print(f"   Epochs trained:    {metrics['epochs_trained']}")
    print(f"   Best Val Accuracy: {metrics['best_val_accuracy']:.4f}")
    print(f"   Best Val Loss:     {metrics['best_val_loss']:.4f}")

    y_pred_scores = []
    for i in range(len(X_test)):
        score, _, _ = classifier.predict(X_test[i])
        y_pred_scores.append(1 if score >= 0.5 else 0)
    y_pred = np.array(y_pred_scores)

    print(f"\n📈 Test Set Metrics ({len(X_test)} samples):")
    print(f"   Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"   Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"   Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"   F1-Score:  {f1_score(y_test, y_pred):.4f}")
    print(f"\n📋 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

    classifier.save('url_model')
    return classifier


def train_email_model():
    """Train and save email phishing deep learning classifier."""
    print("\n" + "=" * 65)
    print("📧 Training Email Phishing Classifier (Deep Learning)")
    print("=" * 65)

    df = generate_email_dataset(3000)
    feature_names = get_email_feature_names()
    X = df[feature_names].values
    y = df['label'].values

    print(f"\n📦 Dataset: {len(df)} samples ({(y==0).sum()} safe, {(y==1).sum()} phishing)")
    print(f"📐 Features: {len(feature_names)}")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    classifier = PhishingClassifier()
    metrics = classifier.train(X_train, y_train, feature_names, epochs=150, batch_size=64, lr=0.001)

    # ── Evaluate on test set ──
    print(f"\n{'─' * 50}")
    print(f"📊 Training Summary:")
    print(f"   Architecture:      {metrics['architecture']}")
    print(f"   Parameters:        {metrics['total_parameters']:,}")
    print(f"   Epochs trained:    {metrics['epochs_trained']}")
    print(f"   Best Val Accuracy: {metrics['best_val_accuracy']:.4f}")
    print(f"   Best Val Loss:     {metrics['best_val_loss']:.4f}")

    y_pred_scores = []
    for i in range(len(X_test)):
        score, _, _ = classifier.predict(X_test[i])
        y_pred_scores.append(1 if score >= 0.5 else 0)
    y_pred = np.array(y_pred_scores)

    print(f"\n📈 Test Set Metrics ({len(X_test)} samples):")
    print(f"   Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"   Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"   Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"   F1-Score:  {f1_score(y_test, y_pred):.4f}")
    print(f"\n📋 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

    classifier.save('email_model')
    return classifier


if __name__ == '__main__':
    print("🛡️ PhishGuard AI — Deep Learning Model Training")
    print("=" * 65)
    train_url_model()
    train_email_model()
    print("\n" + "=" * 65)
    print("✅ All deep learning models trained and saved successfully!")
    print("=" * 65)
