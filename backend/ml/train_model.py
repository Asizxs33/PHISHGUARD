"""
PhishGuard AI — Deep Learning Model Training Script (Enhanced)
Generates realistic synthetic training data and trains deep neural network classifiers.
Includes diverse phishing patterns from real-world attacks.
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


# ─── Synthetic Data Generation (Greatly Expanded) ───────────────────────

SAFE_DOMAINS = [
    # Global tech
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',
    'github.com', 'stackoverflow.com', 'reddit.com', 'netflix.com', 'spotify.com',
    'zoom.us', 'slack.com', 'notion.so', 'figma.com', 'vercel.com',
    'dropbox.com', 'paypal.com', 'ebay.com', 'twitch.tv', 'discord.com',
    'telegram.org', 'whatsapp.com', 'tiktok.com', 'pinterest.com', 'medium.com',
    # Kazakhstan
    'kaspi.kz', 'halykbank.kz', 'gov.kz', 'egov.kz', 'nur.kz',
    'forte.kz', 'jusan.kz', 'kolesa.kz', 'krisha.kz', 'olx.kz',
    'tengrinews.kz', 'zakon.kz', 'inform.kz', 'bcc.kz',
    # Russia
    'mail.ru', 'yandex.ru', 'vk.com', 'ok.ru', 'sberbank.ru',
    'tinkoff.ru', 'vtb.ru', 'ozon.ru', 'wildberries.ru', 'avito.ru',
    # Other
    'bbc.com', 'cnn.com', 'nytimes.com', 'airbnb.com', 'booking.com',
    'uber.com', 'walmart.com', 'target.com', 'ikea.com', 'samsung.com',
]

SAFE_PATHS = [
    '', '/', '/about', '/contact', '/help', '/products', '/services',
    '/blog', '/news', '/faq', '/terms', '/privacy', '/search',
    '/en/home', '/ru/main', '/kz/about', '/docs/getting-started',
    '/careers', '/pricing', '/support', '/features', '/download',
    '/settings', '/profile', '/dashboard', '/api/docs', '/status',
    '/shop', '/catalog', '/articles', '/events', '/community',
    '/learn', '/resources', '/partners', '/investor-relations',
]

# === PHISHING URL PATTERNS (greatly expanded) ===

# Pattern 1: Brand-in-subdomain (kaspi.evil.tk)
PHISHING_BRAND_SUBDOMAIN = [
    'http://{brand}.secure-verify.tk/login',
    'http://{brand}.account-check.ml/verify',
    'http://{brand}.security-update.ga/confirm',
    'http://{brand}.login-portal.xyz/auth',
    'http://{brand}.verify-now.cf/account',
    'http://{brand}.support-desk.gq/help',
    'http://{brand}.alert-notice.top/warning',
    'http://{brand}.update-info.win/profile',
    'http://{brand}-online.secure-check.tk/access',
    'http://{brand}.notification.click/verify',
]

# Pattern 2: Brand-in-domain-with-hyphens (kaspi-bank-login.tk)
PHISHING_BRAND_HYPHENED = [
    'http://{brand}-secure-login.tk/verify',
    'http://{brand}-account-verify.ml/signin',
    'http://{brand}-update-security.ga/confirm',
    'http://{brand}-banking-online.xyz/login',
    'http://{brand}-password-reset.cf/restore',
    'http://{brand}-card-blocked.gq/unblock',
    'http://{brand}-urgent-notice.top/action',
    'http://{brand}-support-center.win/help',
    'http://secure-{brand}-login.tk/auth',
    'http://my-{brand}-account.ml/verify',
    'http://online-{brand}-bank.ga/signin',
    'http://login-{brand}-portal.xyz/access',
    'http://verify-{brand}-identity.cf/confirm',
    'http://alert-{brand}-security.gq/update',
]

# Pattern 3: Typosquatting (gooogle.com, faceb00k.com)
TYPOSQUATTING_DOMAINS = [
    'gooogle.com', 'googel.com', 'g00gle.com', 'goog1e.com',
    'faceboook.com', 'faceb00k.com', 'facebok.com', 'faecbook.com',
    'amaz0n.com', 'amazom.com', 'arnazon.com', 'armazon.com',
    'app1e.com', 'aple.com', 'appie.com',
    'micros0ft.com', 'mircosoft.com', 'microsofl.com',
    'netf1ix.com', 'netfiix.com', 'netlfix.com',
    'paypai.com', 'paypa1.com', 'pаypаl.com',  # Last one has Cyrillic 'а'
    'instagran.com', 'lnstagram.com', 'instaqram.com',
    'twltter.com', 'tvvitter.com', 'twiter.com',
    'kaspl.kz', 'kasp1.kz', 'kaspii.kz', 'kaspi-bank.kz',
    'halykba.nk.kz', 'haIykbank.kz', 'halykbаnk.kz',  # Last has Cyrillic 'а'
    'sberbenk.ru', 'sberbanк.ru', 'sbеrbank.ru',  # Last has Cyrillic 'е'
    'tink0ff.ru', 'tlnkoff.ru', 'tinkof.ru',
    'yandeks.ru', 'yаndex.ru',  # Last has Cyrillic 'а'
]

# Pattern 4: IP-based URLs
PHISHING_IP_PATTERNS = [
    'http://192.168.{ip1}.{ip2}/login',
    'http://10.{ip1}.{ip2}.{ip3}/admin/login',
    'http://172.{ip1}.{ip2}.{ip3}/verify',
    'http://185.{ip1}.{ip2}.{ip3}/bank/login',
    'http://91.{ip1}.{ip2}.{ip3}/secure/update',
    'http://45.{ip1}.{ip2}.{ip3}/account/verify',
    'http://194.{ip1}.{ip2}.{ip3}:8080/login',
    'http://103.{ip1}.{ip2}.{ip3}:3000/signin',
]

# Pattern 5: URL with @ symbol (redirect trick)
PHISHING_AT_SYMBOL = [
    'http://www.{brand}.com@evil-{rand}.tk/login',
    'http://{brand}.kz@suspicious-{rand}.ml/verify',
    'https://{brand}.com@{rand}.ga/secure',
]

# Pattern 6: Long confusing URLs
PHISHING_LONG_URLS = [
    'http://{brand}-secure-online-banking-verify-account-{rand}.tk/login/confirm/step1/verify/complete',
    'http://www.secure.{brand}.update.verify.{rand}.xyz/account/validate/identity/confirm',
    'http://{brand}.com.account.security.update.{rand}.ml/verify/login/auth',
]

# Pattern 7: Realistic phishing with brand in path
PHISHING_BRAND_IN_PATH = [
    'http://{rand}.tk/{brand}/login',
    'http://{rand}.ml/{brand}/verify-account',
    'http://secure-portal.xyz/{brand}/signin',
    'http://account-verify.top/{brand}/confirm',
    'http://{rand}.ga/{brand}/password-reset',
    'http://{rand}-portal.cf/{brand}/update',
]

# Pattern 8: Random/auto-generated domains
PHISHING_RANDOM_DOMAINS = [
    'http://{rand8}.tk/login',
    'http://{rand8}.ml/verify',
    'http://{rand8}{rand4}.xyz/account',
    'http://{rand8}-{rand4}.top/signin',
    'http://{rand12}.ga/confirm',
    'http://{rand8}.cf/update',
    'http://{rand8}{rand4}.gq/login',
    'http://{rand12}.win/verify',
    'http://{rand8}.click/secure',
    'http://{rand8}.link/account',
]

# Brand names to use in phishing patterns
BRAND_NAMES = [
    'google', 'apple', 'microsoft', 'amazon', 'facebook', 'instagram',
    'twitter', 'netflix', 'paypal', 'ebay', 'whatsapp', 'telegram',
    'kaspi', 'halykbank', 'sberbank', 'tinkoff', 'homebank', 'egov',
    'linkedin', 'youtube', 'discord', 'spotify', 'github', 'dropbox',
    'yandex', 'mail', 'vk', 'ozon', 'wildberries', 'forte', 'jusan',
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
    'LAST WARNING: Your account will be permanently deleted',
    'Invoice #INV-39281 - Payment overdue',
    'Ваш кредит одобрен! Получите деньги сейчас',
    'Сіздің жеңісіңіз! 500 000 теңге ұтып алдыңыз!',
    'Re: Your recent purchase - Problem with payment',
    'IT Department: Password must be changed immediately',
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
    'Your Microsoft 365 subscription requires immediate renewal. Click http://microsoft-renew.xyz/account to avoid losing access to your files and email.',
    'IT Security Notice: Your email password expires today. Click here to extend: http://mail-security.tk/extend. Failure to act will lock your mailbox.',
    'Құрметті клиент! Сіздің Halyk Bank шотыңыз уақытша бұғатталды. Шотты ашу үшін мына сілтемеге басыңыз: http://halyk-verify.ga/unblock',
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
    'Photo shared with you',
    'Happy Birthday from the team!',
    'Release notes v2.5.0',
    'Your delivery is scheduled for tomorrow',
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
    'The new software version has been released. Check out the changelog at https://github.com/project/releases.',
    'Congratulations on completing the course! Your certificate is attached.',
]


def _random_string(length: int) -> str:
    """Generate a random alphanumeric string."""
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=length))


def generate_url_dataset(n_samples: int = 8000) -> pd.DataFrame:
    """Generate synthetic URL dataset for deep learning training (Enhanced)."""
    data = []
    half = n_samples // 2

    # ── Generate SAFE URLs ──
    for _ in range(half):
        domain = random.choice(SAFE_DOMAINS)
        path = random.choice(SAFE_PATHS)
        protocol = random.choice(['https://', 'https://www.'])
        url = f"{protocol}{domain}{path}"

        features = extract_url_features(url)
        features['label'] = 0
        data.append(features)

    # Also add some safe URLs with query parameters
    for _ in range(half // 5):
        domain = random.choice(SAFE_DOMAINS)
        params = random.choice([
            '?q=search+term', '?page=2', '?lang=en', '?ref=homepage',
            '?utm_source=email&utm_medium=newsletter', '?id=12345',
        ])
        url = f"https://{domain}/search{params}"

        features = extract_url_features(url)
        features['label'] = 0
        data.append(features)

    # ── Generate PHISHING URLs ──
    phishing_count = 0
    target = half + half // 5  # Match the total safe URLs count

    # Type 1: Brand-in-subdomain
    while phishing_count < target * 0.15:
        brand = random.choice(BRAND_NAMES)
        pattern = random.choice(PHISHING_BRAND_SUBDOMAIN)
        url = pattern.format(brand=brand)
        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)
        phishing_count += 1

    # Type 2: Brand with hyphens
    while phishing_count < target * 0.25:
        brand = random.choice(BRAND_NAMES)
        pattern = random.choice(PHISHING_BRAND_HYPHENED)
        url = pattern.format(brand=brand, rand=_random_string(6))
        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)
        phishing_count += 1

    # Type 3: Typosquatting
    while phishing_count < target * 0.35:
        typo_domain = random.choice(TYPOSQUATTING_DOMAINS)
        path = random.choice(['/login', '/signin', '/verify', '/account', '/secure', '/', ''])
        url = f"http://{typo_domain}{path}"
        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)
        phishing_count += 1

    # Type 4: IP-based
    while phishing_count < target * 0.45:
        pattern = random.choice(PHISHING_IP_PATTERNS)
        url = pattern.format(
            ip1=random.randint(1, 254),
            ip2=random.randint(1, 254),
            ip3=random.randint(1, 254),
        )
        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)
        phishing_count += 1

    # Type 5: @ symbol redirect
    while phishing_count < target * 0.50:
        brand = random.choice(BRAND_NAMES)
        pattern = random.choice(PHISHING_AT_SYMBOL)
        url = pattern.format(brand=brand, rand=_random_string(6))
        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)
        phishing_count += 1

    # Type 6: Long confusing URLs
    while phishing_count < target * 0.55:
        brand = random.choice(BRAND_NAMES)
        pattern = random.choice(PHISHING_LONG_URLS)
        url = pattern.format(brand=brand, rand=_random_string(8))
        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)
        phishing_count += 1

    # Type 7: Brand in path
    while phishing_count < target * 0.65:
        brand = random.choice(BRAND_NAMES)
        pattern = random.choice(PHISHING_BRAND_IN_PATH)
        url = pattern.format(brand=brand, rand=_random_string(8))
        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)
        phishing_count += 1

    # Type 8: Random/auto-generated domains
    while phishing_count < target * 0.80:
        pattern = random.choice(PHISHING_RANDOM_DOMAINS)
        url = pattern.format(
            rand4=_random_string(4),
            rand8=_random_string(8),
            rand12=_random_string(12),
        )
        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)
        phishing_count += 1

    # Type 9: Mixed patterns (more variety)
    while phishing_count < target:
        pattern_type = random.randint(1, 6)
        brand = random.choice(BRAND_NAMES)
        rand = _random_string(random.randint(5, 10))

        if pattern_type == 1:
            tld = random.choice(['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'])
            url = f"http://{brand}-{rand}{tld}/login"
        elif pattern_type == 2:
            tld = random.choice(['.click', '.link', '.buzz', '.monster'])
            url = f"http://{rand}.{brand}-verify{tld}/account"
        elif pattern_type == 3:
            url = f"http://{brand}.{rand}.xyz/signin/verify/confirm"
        elif pattern_type == 4:
            url = f"http://www.{brand}.com@{rand}.tk/login"
        elif pattern_type == 5:
            tld = random.choice(['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'])
            url = f"http://{rand}{tld}/free-prize/winner/claim"
        else:
            url = f"http://{brand}-secure.{rand}.ml/password-reset"

        features = extract_url_features(url)
        features['label'] = 1
        data.append(features)
        phishing_count += 1

    return pd.DataFrame(data)


def generate_email_dataset(n_samples: int = 4000) -> pd.DataFrame:
    """Generate synthetic email dataset for deep learning training (Enhanced)."""
    data = []
    half = n_samples // 2

    # Safe emails
    for _ in range(half):
        subject = random.choice(SAFE_EMAIL_SUBJECTS)
        body = random.choice(SAFE_EMAIL_BODIES)
        sender = f"{random.choice(['john', 'anna', 'manager', 'info', 'support', 'team', 'noreply', 'admin', 'hr', 'sales'])}@{random.choice(SAFE_DOMAINS)}"

        features = extract_email_features(subject, body, sender)
        features['label'] = 0
        data.append(features)

    # Phishing emails
    for _ in range(half):
        subject = random.choice(PHISHING_EMAIL_SUBJECTS)
        body = random.choice(PHISHING_EMAIL_BODIES)
        sender = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(5, 10)))}@{random.choice(['mail.tk', 'secure-alert.ml', 'verify.ga', 'update.cf', 'login.xyz', 'alert.top', 'bank-notify.win', 'security.bid', 'support-center.click', 'urgent-notice.monster'])}"

        features = extract_email_features(subject, body, sender)
        features['label'] = 1
        data.append(features)

    return pd.DataFrame(data)


def train_url_model():
    """Train and save URL phishing deep learning classifier (Enhanced)."""
    print("=" * 65)
    print("🔗 Training URL Phishing Classifier (Deep Learning — Enhanced)")
    print("=" * 65)

    df = generate_url_dataset(8000)
    feature_names = get_url_feature_names()
    X = df[feature_names].values
    y = df['label'].values

    print(f"\n📦 Dataset: {len(df)} samples ({(y==0).sum()} safe, {(y==1).sum()} phishing)")
    print(f"📐 Features: {len(feature_names)} (was 18, now {len(feature_names)})")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    classifier = PhishingClassifier()
    metrics = classifier.train(X_train, y_train, feature_names, epochs=100, batch_size=64, lr=0.001)

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
    print("📧 Training Email Phishing Classifier (Deep Learning — Enhanced)")
    print("=" * 65)

    df = generate_email_dataset(4000)
    feature_names = get_email_feature_names()
    X = df[feature_names].values
    y = df['label'].values

    print(f"\n📦 Dataset: {len(df)} samples ({(y==0).sum()} safe, {(y==1).sum()} phishing)")
    print(f"📐 Features: {len(feature_names)}")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    classifier = PhishingClassifier()
    metrics = classifier.train(X_train, y_train, feature_names, epochs=100, batch_size=64, lr=0.001)

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
    print("🛡️ PhishGuard AI — Enhanced Deep Learning Model Training")
    print("=" * 65)
    train_url_model()
    train_email_model()
    print("\n" + "=" * 65)
    print("✅ All enhanced deep learning models trained and saved successfully!")
    print("=" * 65)
