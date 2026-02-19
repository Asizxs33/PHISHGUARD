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
    timestamp: str

class HistoryQuery(BaseModel):
    limit: int = 50
    type: Optional[str] = None


# ─── Recommendation Engine ───────────────────────────────────────────────

def get_recommendations(verdict: str, analysis_type: str, features: dict) -> list:
    """Generate multilingual recommendations based on analysis results."""
    recs = []

    if verdict == "phishing":
        recs = [
            {"kz": "⛔ ҚАУІПТІ! Бұл сілтемені/хатты ашпаңыз!", 
             "ru": "⛔ ОПАСНО! Не открывайте эту ссылку/письмо!",
             "en": "⛔ DANGEROUS! Do not open this link/email!"},
            {"kz": "🔒 Ешқандай жеке деректеріңізді бермеңіз", 
             "ru": "🔒 Не передавайте личные данные",
             "en": "🔒 Do not share any personal information"},
            {"kz": "📞 Банкке немесе қызметке тікелей хабарласыңыз", 
             "ru": "📞 Свяжитесь с банком или сервисом напрямую",
             "en": "📞 Contact the bank or service directly"},
        ]
    elif verdict == "suspicious":
        recs = [
            {"kz": "⚠️ Сақ болыңыз! Бұл сілтеме күдікті көрінеді", 
             "ru": "⚠️ Будьте осторожны! Ссылка выглядит подозрительно",
             "en": "⚠️ Be careful! This link looks suspicious"},
            {"kz": "🔍 URL мекенжайын мұқият тексеріңіз", 
             "ru": "🔍 Внимательно проверьте URL-адрес",
             "en": "🔍 Carefully verify the URL address"},
            {"kz": "🛡️ Антивирус бағдарламасын қолданыңыз", 
             "ru": "🛡️ Используйте антивирусное ПО",
             "en": "🛡️ Use antivirus software"},
        ]
    else:
        recs = [
            {"kz": "✅ Қауіпсіз деп бағаланды", 
             "ru": "✅ Оценено как безопасное",
             "en": "✅ Assessed as safe"},
            {"kz": "💡 Онлайн қауіпсіздікте әрқашан сақ болыңыз", 
             "ru": "💡 Всегда будьте бдительны в интернете",
             "en": "💡 Always stay vigilant online"},
        ]

    if analysis_type == "url":
        if features.get('has_ip', 0):
            recs.append({"kz": "🚫 URL IP-мекенжай қолданады — бұл фишингтің белгісі",
                         "ru": "🚫 URL использует IP-адрес — признак фишинга",
                         "en": "🚫 URL uses IP address — a sign of phishing"})
        if features.get('suspicious_tld', 0):
            recs.append({"kz": "🚫 Күдікті домен аймағы (.tk, .ml, т.б.)",
                         "ru": "🚫 Подозрительная доменная зона (.tk, .ml и т.д.)",
                         "en": "🚫 Suspicious TLD (.tk, .ml, etc.)"})
        if not features.get('has_https', 0):
            recs.append({"kz": "🔓 HTTPS жоқ — қосылым қорғалмаған",
                         "ru": "🔓 Нет HTTPS — соединение не защищено",
                         "en": "🔓 No HTTPS — connection is not secure"})

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

    # Save to history
    save_analysis(db, 'url', request.url, score, verdict, json.dumps(details))

    return AnalysisResponse(
        score=score,
        verdict=verdict,
        risk_level=risk_level,
        features=features,
        model_details=details,
        recommendations=recommendations,
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

    input_summary = f"From: {request.sender} | Subject: {request.subject}"
    save_analysis(db, 'email', input_summary, score, verdict, json.dumps(details))

    return AnalysisResponse(
        score=score,
        verdict=verdict,
        risk_level=risk_level,
        features=features,
        model_details=details,
        recommendations=recommendations,
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

        save_analysis(db, 'qr', decoded_url, score, verdict, json.dumps(details))

        return {
            "decoded_url": decoded_url,
            "score": score,
            "verdict": verdict,
            "risk_level": risk_level,
            "features": features,
            "model_details": details,
            "recommendations": recommendations,
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
