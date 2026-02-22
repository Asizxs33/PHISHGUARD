"""
CyberQalqan AI — FastAPI Backend (Enhanced)
REST API for phishing detection with ML + Heuristic ensemble analysis.
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
from ml.heuristic_analyzer import analyze_url_heuristic, combine_scores
from ml.cyber_advisor import get_chat_response, SUGGESTED_QUESTIONS
from database import init_db, get_db, save_analysis, get_history, get_stats

# ─── Initialize App ──────────────────────────────────────────────────────

app = FastAPI(
    title="CyberQalqan AI",
    description="AI-powered phishing detection API with ML + Heuristic ensemble (KZ/RU/EN)",
    version="2.0.0"
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


# ─── Detailed Analysis Generator ────────────────────────────────────────

def generate_detailed_analysis(features: dict, analysis_type: str, heuristic_issues: list = None) -> list:
    """Generate detailed multilingual analysis based on features and heuristic issues."""
    details = []

    if analysis_type == 'url':
        # ── Heuristic-based alerts (from heuristic analyzer) ──
        if heuristic_issues:
            for issue in heuristic_issues:
                issue_type = issue.get('type', '')
                severity = issue.get('severity', 0)

                if issue_type == 'brand_impersonation' and severity >= 0.8:
                    brand = issue.get('brand', '')
                    official = issue.get('official_domains', [''])[0] if issue.get('official_domains') else ''
                    details.append({
                        "kz": f"⚠️ Бұл сайт '{brand}' компаниясына ұқсап тұр, бірақ бұл ЖАЛҒАН! Нағыз сайт: {official}. Алаяқтар атақты компаниялардың атын пайдаланып, адамдарды алдайды.",
                        "ru": f"⚠️ Сайт притворяется компанией '{brand}', но это ПОДДЕЛКА! Настоящий сайт: {official}. Мошенники используют имена известных компаний.",
                        "en": f"⚠️ This site impersonates '{brand}' but it's FAKE! The real site is: {official}. Scammers use famous brand names to trick people."
                    })

                elif issue_type == 'typosquatting':
                    similar = issue.get('similar_to', '')
                    details.append({
                        "kz": f"🔍 Бұл сайттың аты нағыз сайтқа ({similar}) өте ұқсас, бірақ бір-екі әріп өзгертілген. Бұл — 'typosquatting' деген алдау тәсілі.",
                        "ru": f"🔍 Адрес сайта очень похож на настоящий ({similar}), но изменены 1-2 буквы. Это мошенническая техника — 'тайпосквоттинг'.",
                        "en": f"🔍 The website address looks very similar to the real one ({similar}) but with 1-2 changed letters. This is 'typosquatting' — a phishing technique."
                    })

                elif issue_type == 'brand_in_subdomain':
                    brand = issue.get('brand', '')
                    details.append({
                        "kz": f"🚫 '{brand}' сөзі сілтемеде бар, бірақ ол нағыз сайт емес. Алаяқтар танымал бренд атын жалған сайтқа кіргізіп қойған.",
                        "ru": f"🚫 Слово '{brand}' есть в ссылке, но это не настоящий сайт. Мошенники вставили известное название бренда в поддельный адрес.",
                        "en": f"🚫 The word '{brand}' appears in the link, but this is not the real site. Scammers embed brand names in fake addresses."
                    })

                elif issue_type == 'mixed_scripts':
                    details.append({
                        "kz": "⚠️ Сайт атында латын және кирилл әріптері араластырылған. Бұл — IDN гомограф шабуылы деп аталатын қауіпті алдау.",
                        "ru": "⚠️ В адресе сайта смешаны латинские и кириллические буквы. Это опасная техника — IDN гомографическая атака.",
                        "en": "⚠️ The website mixes Latin and Cyrillic characters. This is a dangerous trick called an IDN homograph attack."
                    })

                elif issue_type == 'at_symbol_redirect':
                    details.append({
                        "kz": "🚫 Сілтемеде '@' белгісі бар. Бұл сізді байқатпай басқа қауіпті сайтқа бұрып жіберу үшін қолданылады.",
                        "ru": "🚫 В ссылке есть символ '@'. Он используется для скрытого перенаправления на совсем другой, опасный сайт.",
                        "en": "🚫 The link contains '@'. This is used to secretly redirect you to a completely different, dangerous site."
                    })

                elif issue_type == 'javascript_uri':
                    details.append({
                        "kz": "🛑 Сілтемеде JavaScript коды жасырылған. Бұл өте қауіпті — ол сіздің деректеріңізді ұрлауы мүмкін!",
                        "ru": "🛑 В ссылке спрятан JavaScript код. Это крайне опасно — он может украсть ваши данные!",
                        "en": "🛑 The link contains hidden JavaScript code. This is extremely dangerous — it can steal your data!"
                    })

                elif issue_type == 'punycode_domain':
                    details.append({
                        "kz": "⚠️ Сайт аты арнайы кодталған (Punycode). Ол нағыз сайтқа ұқсап көрінуі мүмкін, бірақ мүлдем басқа жерге апарады.",
                        "ru": "⚠️ Адрес сайта закодирован особым образом (Punycode). Он может выглядеть как настоящий, но ведёт совсем в другое место.",
                        "en": "⚠️ The domain uses special encoding (Punycode). It may look real but actually leads somewhere else."
                    })

        # ── Feature-based alerts ──
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
        if features.get('has_at_symbol', 0) and not any(i.get('type') == 'at_symbol_redirect' for i in (heuristic_issues or [])):
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

        # New feature-based alerts
        if features.get('brand_typosquat', 0) and not any(i.get('type') == 'typosquatting' for i in (heuristic_issues or [])):
            details.append({
                "kz": "🔍 Сайт атындағы сөз танымал брендке (Google, Kaspi, т.б.) өте ұқсас, бірақ бірнеше әріп өзгертілген.",
                "ru": "🔍 Название сайта очень похоже на известный бренд (Google, Kaspi и т.д.), но изменено несколько букв.",
                "en": "🔍 The domain name closely resembles a known brand but with small letter changes."
            })
        if features.get('brand_in_domain', 0) > 0 and not any(i.get('type') in ('brand_impersonation', 'brand_in_subdomain') for i in (heuristic_issues or [])):
            details.append({
                "kz": "🚫 Сілтемеде танымал бренд аты бар, бірақ ол нағыз сайт емес.",
                "ru": "🚫 В ссылке содержится имя известного бренда, но это не настоящий сайт.",
                "en": "🚫 The link contains a famous brand name but is not the real site."
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
    """Analyze a URL for phishing indicators using ML + Heuristic ensemble."""

    # ── Step 1: Heuristic Analysis (always available, no model needed) ──
    h_score, h_verdict, h_details = analyze_url_heuristic(request.url)
    heuristic_issues = h_details.get('issues', [])

    # ── Step 2: ML Model Prediction ──
    features = extract_url_features(request.url)
    feature_names = get_url_feature_names()

    if url_classifier.is_trained:
        feature_vector = np.array([features[f] for f in feature_names])
        ml_score, ml_verdict, ml_details = url_classifier.predict(feature_vector)

        # ── Step 3: Combine ML + Heuristic ──
        final_score, final_verdict = combine_scores(
            ml_score, h_score, ml_verdict, h_verdict, heuristic_issues
        )

        # Merge model details
        combined_details = {
            **ml_details,
            'heuristic_score': h_score,
            'heuristic_issues_count': len(heuristic_issues),
            'ml_score': ml_score,
            'final_ensemble_score': final_score,
            'analysis_method': 'ML + Heuristic Ensemble',
        }
    else:
        # Fallback: use only heuristic if model not loaded
        final_score = h_score
        final_verdict = h_verdict
        combined_details = {
            'heuristic_score': h_score,
            'heuristic_issues_count': len(heuristic_issues),
            'analysis_method': 'Heuristic Only (ML model not loaded)',
            'confidence': round(abs(h_score - 0.5) * 2, 4),
        }

    risk_level = get_risk_level(final_score)
    recommendations = get_recommendations(final_verdict, "url", features)
    detailed_analysis = generate_detailed_analysis(features, "url", heuristic_issues)

    # Save to history
    save_analysis(db, 'url', request.url, final_score, final_verdict, json.dumps(combined_details))

    return AnalysisResponse(
        score=final_score,
        verdict=final_verdict,
        risk_level=risk_level,
        features=features,
        model_details=combined_details,
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

        # ── Ensemble Analysis (ML + Heuristic) ──
        h_score, h_verdict, h_details = analyze_url_heuristic(decoded_url)
        heuristic_issues = h_details.get('issues', [])

        features = extract_url_features(decoded_url)
        feature_names = get_url_feature_names()

        if url_classifier.is_trained:
            feature_vector = np.array([features[f] for f in feature_names])
            ml_score, ml_verdict, ml_details = url_classifier.predict(feature_vector)
            final_score, final_verdict = combine_scores(
                ml_score, h_score, ml_verdict, h_verdict, heuristic_issues
            )
            combined_details = {
                **ml_details,
                'heuristic_score': h_score,
                'heuristic_issues_count': len(heuristic_issues),
                'ml_score': ml_score,
                'final_ensemble_score': final_score,
                'analysis_method': 'ML + Heuristic Ensemble',
            }
        else:
            final_score = h_score
            final_verdict = h_verdict
            combined_details = {
                'heuristic_score': h_score,
                'analysis_method': 'Heuristic Only',
            }

        risk_level = get_risk_level(final_score)
        recommendations = get_recommendations(final_verdict, "url", features)
        detailed_analysis = generate_detailed_analysis(features, "url", heuristic_issues)

        save_analysis(db, 'qr', decoded_url, final_score, final_verdict, json.dumps(combined_details))

        return {
            "decoded_url": decoded_url,
            "score": final_score,
            "verdict": final_verdict,
            "risk_level": risk_level,
            "features": features,
            "model_details": combined_details,
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


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="User message")


@app.post("/api/chat")
def chat(request: ChatRequest):
    """Cybersecurity AI advisor chat."""
    result = get_chat_response(request.message)
    return {
        "answer": result["answer"],
        "source": result["source"],
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/chat/suggestions")
def chat_suggestions():
    """Get suggested questions for the chat."""
    return {"suggestions": SUGGESTED_QUESTIONS}


@app.get("/")
def root():
    return {
        "app": "CyberQalqan AI",
        "version": "2.0.0",
        "status": "running",
        "analysis_engine": "ML Neural Network + Heuristic Rules Ensemble",
        "endpoints": [
            "POST /api/analyze-url",
            "POST /api/analyze-email",
            "POST /api/analyze-qr",
            "POST /api/chat",
            "GET /api/chat/suggestions",
            "GET /api/history",
            "GET /api/stats"
        ]
    }
