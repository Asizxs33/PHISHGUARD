"""
PhishGuard AI — FastAPI Backend
REST API for phishing detection with ML-powered analysis.
"""

import os
import json
import io
import numpy as np
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ml.features import extract_url_features, extract_email_features, get_url_feature_names, get_email_feature_names
from ml.classifier import PhishingClassifier
from database import init_db, get_db, save_analysis, get_history, get_stats

# ─── Initialize App ──────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard AI",
    description="AI-powered phishing detection API with multilingual support (KZ/RU/EN)",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Load Models ─────────────────────────────────────────────────────────

url_classifier = PhishingClassifier()
email_classifier = PhishingClassifier()

@app.on_event("startup")
def startup():
    """Initialize database and load ML models."""
    init_db()

    if not url_classifier.load('url_model'):
        print("⚠️ URL model not found. Run 'python -m ml.train_model' first.")

    if not email_classifier.load('email_model'):
        print("⚠️ Email model not found. Run 'python -m ml.train_model' first.")


# ─── Request/Response Models ─────────────────────────────────────────────

class UrlRequest(BaseModel):
    url: str = Field(..., min_length=3, description="URL to analyze")

class EmailRequest(BaseModel):
    subject: str = Field(default="", description="Email subject")
    body: str = Field(..., min_length=1, description="Email body text")
    sender: str = Field(default="", description="Sender email address")

class AnalysisResponse(BaseModel):
    score: float
    verdict: str
    risk_level: str
    features: dict
    model_details: dict
    recommendations: list
    detailed_analysis: list
    timestamp: str

class HistoryQuery(BaseModel):
    limit: int = 50
    type: Optional[str] = None


# ─── Recommendation Engine ───────────────────────────────────────────────

    if analysis_type == 'url':
        if features.get('has_ip', 0):
            details.append({
                "kz": "Сайттың аты жоқ, тек сандар жазылған (мысалы, 192.168.x.x). Банктер мен дүкендер мұндай адресті қолданбайды. Бұл — алаяқтардың сайты.",
                "ru": "Адрес сайта состоит из цифр, а не названия. Настоящие компании (как Kaspi или Google) так не делают. Это похоже на временный сайт мошенников.",
                "en": "The website address is just numbers, not a name like google.com. Real businesses don't do this. It's likely a scam site."
            })
        if features.get('suspicious_tld', 0):
            details.append({
                "kz": "Сайттың соңы .tk, .xyz немесе .ml деп аяқталады. Мұндай сайттарды көбінесе алаяқтар ашады. Ресми сайттар көбінесе .kz деп аяқталады.",
                "ru": "Сайт зарегистрирован в странной зоне (.tk, .xyz, .ml), где часто обитают мошенники. Серьезные организации используют .kz, .ru или .com.",
                "en": "The website uses a suspicious ending (.tk, .xyz). Scammers often use these. Legitimate sites usually end in .com or .kz."
            })
        if features.get('is_shortened', 0):
             details.append({
                "kz": "Бұл сілтеме жасырылған. Оны бассаңыз, қайда түсетініңіз белгісіз. Алаяқтар қауіпті сайттарды осылай жасырады.",
                "ru": "Ссылка зашифрована и сокращена. Вы не видите, куда она ведет на самом деле. Так часто прячут вирусы или поддельные сайты.",
                "en": "The link is shortened and hidden. You can't see where it goes. Scammers do this to hide dangerous websites."
            })
        if features.get('suspicious_keywords', 0) > 0:
            details.append({
                "kz": "Сілтемеде 'login', 'bank', 'қауіпсіздік' (secure) деген сөздер бар. Бұған сенбеңіз. Алаяқтар сізді алдау үшін осы сөздерді әдейі жазып қойған.",
                "ru": "В адресе есть слова 'login', 'bank' или 'secure', но это обман. Мошенники специально пишут их, чтобы вы подумали, что это официальный сайт.",
                "en": "The link has words like 'login' or 'bank', but it's a trick. Scammers add these to make you trust a fake site."
            })
        if features.get('has_at_symbol', 0):
            details.append({
                "kz": "Адресте '@' белгісі тұр. Бұл — сізді алдап, басқа сайтқа кіргізу үшін жасалған қулық.",
                "ru": "В адресе есть значок '@'. Это хитрая уловка, чтобы обмануть браузер и перенаправить вас на другой, опасный сайт.",
                "en": "The address has an '@' symbol. This is a trick to fool your browser and send you to a dangerous site instead."
            })
        if features.get('num_subdomains', 0) > 2:
             details.append({
                "kz": "Сайттың аты тым ұзын және түсініксіз. Бұл — нағыз сайтқа ұқсату үшін жасалған алдамшы сайт.",
                "ru": "Адрес сайта слишком длинный и запутанный. Скорее всего, это подделка, которая пытается выглядеть как настоящий сайт.",
                "en": "The website address is too long and complicated. It's likely a fake trying to look like a real site."
            })
        if not features.get('has_https', 0):
             details.append({
                "kz": "Бұл сайтта «құлып» белгісі жоқ. Егер мұнда құпиясөз немесе карта нөмірін жазсаңыз, оны ұрылар оңай біліп алады.",
                "ru": "Сайт не защищен (нет замочка в строке адреса). Любой хакер может перехватить ваши пароли и данные карты, если вы их введете.",
                "en": "The site is not secure (no lock icon). Hackers can easily steal any passwords or card numbers you type here."
            })
        if features.get('has_double_slash', 0):
             details.append({
                "kz": "Сілтемеде қос сызық (//) бар. Бұл сізді байқатпай басқа жаққа бұрып жіберетін жасырын жол болуы мүмкін.",
                "ru": "В ссылке есть двойные косые черты (//). Это может быть скрытый путь, который перенаправит вас на опасную страницу.",
                "en": "The link has double slashes (//). This could be a hidden path to redirect you to a dangerous page."
            })
        if features.get('digit_ratio', 0) > 0.15: 
             details.append({
                "kz": "Сайттың атында сандар өте көп. Мұны адам емес, компьютер ашқан сияқты. Ол сенімді емес.",
                "ru": "В названии сайта слишком много цифр. Похоже, его создал робот, а не человек. Такие сайты живут недолго и опасны.",
                "en": "The website name has too many numbers. It looks like it was made by a robot. These sites are often dangerous scams."
            })

    elif analysis_type == 'email':
        if features.get('urgency_score', 0) > 0:
            details.append({
                "kz": "Сізді қорқытып, асықтырып жатыр: 'Шұғыл!', 'Шот бұғатталды!'. Сабыр сақтаңыз. Алаяқтар сізді қателік жасауға итермелеуде.",
                "ru": "Вас пугают и торопят: 'Срочно!', 'Ваш счет заблокирован!'. Это главный прием мошенников — заставить вас паниковать и совершить ошибку.",
                "en": "You are being rushed or scared: 'Urgent!', 'Account blocked!'. Don't panic. Scammers try to force you into making a mistake."
            })
        if features.get('free_email_provider', 0):
            details.append({
                "kz": "Хат қарапайым тегін поштадан (Gmail, Mail.ru) келген. Банктер мен мекемелер ешқашан мұндай пошта қолданбайды.",
                "ru": "Письмо пришло с обычной бесплатной почты (Gmail, Mail.ru), хотя представляются банком или компанией. Официальные организации пишут только с корпоративной почты.",
                "en": "The email came from a free service (Gmail, Yahoo). Real banks and companies never use these addresses."
            })
        if features.get('sender_has_numbers', 0) > 0:
            details.append({
                "kz": "Жіберушінің атында түсініксіз сандар бар. Бұл — спам тарататын роботтың автоматты поштасы болуы мүмкін.",
                "ru": "В имени отправителя есть странные цифры. Это может быть почта, которую создал робот для рассылки спама.",
                "en": "The sender's name has numbers in it. This might be an automated email created by a spam robot."
            })
        if features.get('link_count', 0) > 2:
            details.append({
                "kz": "Хатта тым көп сілтіме бар. Мұндай хаттар көбінесе жарнама немесе вирусты сайттарға шақыру болып келеді.",
                "ru": "В письме слишком много ссылок. Обычно так делают спамеры, чтобы вы нажали хоть на одну из них.",
                "en": "There are too many links in the email. Spammers do this hoping you will click on at least one of them."
            })
        if features.get('has_money_ref', 0):
            details.append({
                "kz": "Хатта ақша немесе төлем туралы жазылған. Абайлаңыз, сіздің ақшаңызды иемдену үшін алдап жатқан болуы мүмкін.",
                "ru": "В письме говорят про деньги, выигрыш или оплату. Будьте осторожны, это может быть финансовая ловушка.",
                "en": "The email talks about money or payments. Be careful, this could be a financial scam."
            })

    return details


def get_recommendations(verdict: str, analysis_type: str, features: dict) -> list:
    """Generate multilingual recommendations based on analysis results."""
    recs = []

    if verdict == "phishing":
        recs = [
            {"kz": "⛔ ТОҚТАҢЫЗ! Бұл өте қауіпті сілтеме. Оны ашпаңыз!", 
             "ru": "⛔ ОПАСНО! Не открывайте эту ссылку/письмо и не скачивайте файлы!",
             "en": "⛔ DANGEROUS! Do not open this link/email or download files!"},
            {"kz": "🔒 Ешкімге құпиясөзді, СМС-кодты және карта нөмірін айтпаңыз.", 
             "ru": "🔒 Никому не сообщайте: пароли, коды из СМС, номер карты.",
             "en": "🔒 Do not share personal info: passwords, SMS codes, card numbers."},
            {"kz": "📞 Банкке өзіңіз хабарласыңыз (телефон нөмірі картаңыздың артында жазулы).", 
             "ru": "📞 Позвоните в банк сами (номер есть на обратной стороне вашей карты).",
             "en": "📞 Contact the bank yourself (use the number on the back of your card)."},
        ]
    elif verdict == "suspicious":
        recs = [
            {"kz": "⚠️ Абайлаңыз! Бұл сілтеме күдікті, оны ашпаған дұрыс.", 
             "ru": "⚠️ Будьте осторожны! Ссылка выглядит странно, лучше не переходить.",
             "en": "⚠️ Be careful! This link looks strange, better not to click it."},
            {"kz": "🔍 Сайттың атына мұқият қараңыз. Ол ресми сайттан (мысалы, kaspi.kz) өзгеше болуы мүмкін.", 
             "ru": "🔍 Проверьте адрес сайта. Совпадает ли он с официальным сайтом банка/магазина?",
             "en": "🔍 Check the website address. Does it match the official bank/store site?"},
            {"kz": "🛡️ Антивирус бағдарламаңыз қосулы тұр ма?", 
             "ru": "🛡️ Убедитесь, что у вас работает антивирус.",
             "en": "🛡️ Make sure your antivirus software is running."},
        ]
    else:
        recs = [
            {"kz": "✅ Қауіпсіз. Сайт таза және сенімді көрінеді.", 
             "ru": "✅ Оценено как безопасное. Сайт выглядит чистым.",
             "en": "✅ Assessed as safe. The site looks clean."},
            {"kz": "💡 Интернетте әрқашан сақ болыңыз, бейтаныс сілтемелерді ашпаңыз.", 
             "ru": "💡 Всегда будьте внимательны в интернете, не открывайте незнакомые ссылки.",
             "en": "💡 Always stay vigilant online, avoid opening unfamiliar links."},
        ]

    if analysis_type == "url":
        if features.get('has_ip', 0):
            recs.append({"kz": "🚫 Сандардан тұратын сілтемелерді ашпаңыз, бұл қауіпті.",
                         "ru": "🚫 Не открывайте ссылки, состоящие только из цифр, это опасно.",
                         "en": "🚫 Do not open links made of numbers only, it's dangerous."})
        if features.get('suspicious_tld', 0):
            recs.append({"kz": "🚫 Соңы .tk, .xyz, .ml деп бітетін сайттарға сенбеңіз.",
                         "ru": "🚫 Не доверяйте сайтам на .tk, .xyz и других странных адресах.",
                         "en": "🚫 Do not trust sites ending in .tk, .xyz etc."})
        if not features.get('has_https', 0):
            recs.append({"kz": "🔓 Құлып белгісі жоқ сайтқа құпиясөз жазбаңыз.",
                         "ru": "🔓 Не вводите пароли на сайте, где нет значка замка.",
                         "en": "🔓 Do not enter passwords on a site without a lock icon."})

    return recs


def get_risk_level(score: float) -> str:
    """Get risk level label."""
    if score < 0.2:
        return "very_low"
    elif score < 0.4:
        return "low"
    elif score < 0.6:
        return "medium"
    elif score < 0.8:
        return "high"
    else:
        return "critical"


# ─── API Endpoints ───────────────────────────────────────────────────────

@app.post("/api/analyze-url", response_model=AnalysisResponse)
def analyze_url(request: UrlRequest, db: Session = Depends(get_db)):
    """Analyze a URL for phishing indicators."""
    if not url_classifier.is_trained:
        raise HTTPException(status_code=503, detail="URL model not loaded. Train the model first.")

    features = extract_url_features(request.url)
    feature_names = get_url_feature_names()
    feature_vector = np.array([features[f] for f in feature_names])

    score, verdict, details = url_classifier.predict(feature_vector)
    risk_level = get_risk_level(score)
    recommendations = get_recommendations(verdict, "url", features)
    detailed_analysis = generate_detailed_analysis(features, "url")

    # Save to history
    save_analysis(db, 'url', request.url, score, verdict, json.dumps(details))

    return AnalysisResponse(
        score=score,
        verdict=verdict,
        risk_level=risk_level,
        features=features,
        model_details=details,
        recommendations=recommendations,
        detailed_analysis=detailed_analysis,
        timestamp=datetime.utcnow().isoformat()
    )


@app.post("/api/analyze-email", response_model=AnalysisResponse)
def analyze_email(request: EmailRequest, db: Session = Depends(get_db)):
    """Analyze email content for phishing indicators."""
    if not email_classifier.is_trained:
        raise HTTPException(status_code=503, detail="Email model not loaded. Train the model first.")

    features = extract_email_features(request.subject, request.body, request.sender)
    feature_names = get_email_feature_names()
    feature_vector = np.array([features[f] for f in feature_names])

    score, verdict, details = email_classifier.predict(feature_vector)
    risk_level = get_risk_level(score)
    recommendations = get_recommendations(verdict, "email", features)
    detailed_analysis = generate_detailed_analysis(features, "email")

    input_summary = f"From: {request.sender} | Subject: {request.subject}"
    save_analysis(db, 'email', input_summary, score, verdict, json.dumps(details))

    return AnalysisResponse(
        score=score,
        verdict=verdict,
        risk_level=risk_level,
        features=features,
        model_details=details,
        recommendations=recommendations,
        detailed_analysis=detailed_analysis,
        timestamp=datetime.utcnow().isoformat()
    )


@app.post("/api/analyze-qr")
def analyze_qr(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Analyze a QR code image for phishing URLs."""
    if not url_classifier.is_trained:
        raise HTTPException(status_code=503, detail="URL model not loaded. Train the model first.")

    try:
        from PIL import Image
        image_data = file.file.read()
        image = Image.open(io.BytesIO(image_data))

        # Try to decode QR code
        decoded_url = None

        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
            decoded = pyzbar_decode(image)
            if decoded:
                decoded_url = decoded[0].data.decode('utf-8')
        except ImportError:
            pass

        if not decoded_url:
            # Fallback: try with basic QR detection
            try:
                import cv2
                img_array = np.array(image)
                detector = cv2.QRCodeDetector()
                decoded_url, _, _ = detector.detectAndDecode(img_array)
            except ImportError:
                raise HTTPException(status_code=422, detail="QR code could not be decoded. Install pyzbar or opencv-python.")

        if not decoded_url:
            raise HTTPException(status_code=422, detail="No QR code found in the image or QR code is empty.")

        # Analyze the decoded URL
        features = extract_url_features(decoded_url)
        feature_names = get_url_feature_names()
        feature_vector = np.array([features[f] for f in feature_names])

        score, verdict, details = url_classifier.predict(feature_vector)
        risk_level = get_risk_level(score)
        recommendations = get_recommendations(verdict, "url", features)
        detailed_analysis = generate_detailed_analysis(features, "url")

        save_analysis(db, 'qr', decoded_url, score, verdict, json.dumps(details))

        return {
            "decoded_url": decoded_url,
            "score": score,
            "verdict": verdict,
            "risk_level": risk_level,
            "features": features,
            "model_details": details,
            "recommendations": recommendations,
            "detailed_analysis": detailed_analysis,
            "timestamp": datetime.utcnow().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing QR code: {str(e)}")


@app.get("/api/history")
def get_analysis_history(limit: int = 50, type: Optional[str] = None, db: Session = Depends(get_db)):
    """Get analysis history."""
    return {"history": get_history(db, limit, type)}


@app.get("/api/stats")
def get_analysis_stats(db: Session = Depends(get_db)):
    """Get aggregate analysis statistics."""
    return get_stats(db)


@app.get("/")
def root():
    return {
        "app": "PhishGuard AI",
        "version": "1.0.0",
        "status": "running",
        "endpoints": [
            "POST /api/analyze-url",
            "POST /api/analyze-email",
            "POST /api/analyze-qr",
            "GET /api/history",
            "GET /api/stats"
        ]
    }
