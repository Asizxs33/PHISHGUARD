"""
CyberQalqan AI — Telegram Bot
Full-featured phishing detection & cybersecurity advisor bot.
Connects to the existing FastAPI backend on Render.

Deployed as a Web Service on Render (free tier) with a health endpoint.
"""

import os
import io
import sys
import asyncio
import logging
import threading
import httpx
from typing import Optional, Dict, Any, List, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from dotenv import load_dotenv

# FIX: Windows ProactorEventLoop doesn't work properly with python-telegram-bot
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ReplyKeyboardMarkup,
    KeyboardButton,
)
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    filters,
    ContextTypes,
)
from telegram.constants import ParseMode, ChatAction
from telegram.request import HTTPXRequest

# ─── Config ──────────────────────────────────────────────────────────────

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
API_URL = os.getenv("API_URL", "https://phishguard-api-lpki.onrender.com")
PORT = int(os.getenv("PORT", 8080))

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Conversation states
WAITING_URL, WAITING_EMAIL_SUBJECT, WAITING_EMAIL_BODY, WAITING_EMAIL_SENDER, WAITING_QR, WAITING_PHONE = range(6)


# ─── Health Check HTTP Server (keeps Render happy) ───────────────────────

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok","service":"CyberQalqan Telegram Bot"}')
        logger.info("📡 Health check received: Kept alive by pinger")


def start_health_server():
    """Start a simple HTTP server for Render health checks."""
    try:
        server = HTTPServer(("0.0.0.0", PORT), HealthHandler)
        logger.info(f"🌐 Health server started on port {PORT}")
        server.serve_forever()
    except Exception as e:
        logger.error(f"❌ Health server failed: {e}")


# ─── API Helper & Client ─────────────────────────────────────────────────

# Persistent client for efficient connection pooling
_api_client: Optional[httpx.AsyncClient] = None

async def get_api_client() -> httpx.AsyncClient:
    global _api_client
    if _api_client is None or _api_client.is_closed:
        _api_client = httpx.AsyncClient(
            timeout=60.0,
            headers={"User-Agent": "CyberQalqanBot/2.0 (Bot Security Analysis)"}
        )
    return _api_client

async def api_request(method: str, endpoint: str, **kwargs) -> dict:
    """Make an async request to the CyberQalqan API backend with retries."""
    url = f"{API_URL}{endpoint}"
    max_retries = 3
    retry_delay = 3  # Start with 3 seconds

    client = await get_api_client()

    for attempt in range(max_retries):
        try:
            if method == "GET":
                resp = await client.get(url, params=kwargs.get("params"))
            elif method == "POST":
                if "files" in kwargs:
                    resp = await client.post(url, files=kwargs["files"])
                else:
                    resp = await client.post(url, json=kwargs.get("json"))
            else:
                return None

            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code in [429, 500, 502, 503, 504]:
                logger.warning(f"⚠️ API returned {resp.status_code}, retrying ({attempt+1}/{max_retries}) in {retry_delay}s...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                continue
            else:
                logger.error(f"❌ API error {resp.status_code}: {resp.text[:200]}")
                return None

        except (httpx.TimeoutException, httpx.ConnectError) as e:
            logger.warning(f"⚠️ Connection error ({e}), retrying ({attempt+1}/{max_retries})...")
            await asyncio.sleep(2)
        except Exception as e:
            logger.error(f"❌ API exception: {e}")
            return None
    
    return None


# ─── Emoji & Formatting Helpers ──────────────────────────────────────────

VERDICT_EMOJI = {
    "phishing": "🔴",
    "suspicious": "🟡",
    "safe": "🟢",
}

RISK_EMOJI = {
    "critical": "🚨",
    "high": "⚠️",
    "medium": "⚡",
    "low": "✅",
    "very_low": "🛡️",
}

VERDICT_TEXT = {
    "phishing": "ФИШИНГ — ҚАУІПТІ!",
    "suspicious": "КҮДІКТІ",
    "safe": "ҚАУІПСІЗ",
}

RISK_TEXT = {
    "critical": "Өте жоғары қауіп",
    "high": "Жоғары қауіп",
    "medium": "Орташа қауіп",
    "low": "Төмен қауіп",
    "very_low": "Қауіпсіз",
}


def escape_md(text: str) -> str:
    """Escape special markdown characters."""
    return text.replace("`", "'")


def format_analysis_result(result: dict, input_label: str = "URL") -> str:
    """Format analysis result into a pretty Telegram message."""
    verdict = result.get("verdict", "unknown")
    score = result.get("score", 0)
    risk = result.get("risk_level", "medium")

    v_emoji = VERDICT_EMOJI.get(verdict, "❔")
    r_emoji = RISK_EMOJI.get(risk, "❔")
    v_text = VERDICT_TEXT.get(verdict, verdict)
    r_text = RISK_TEXT.get(risk, risk)

    filled = int(score * 10)
    bar = "█" * filled + "░" * (10 - filled)

    lines = [
        f"{'━' * 24}",
        f"  {v_emoji}  *{v_text}*  {v_emoji}",
        f"{'━' * 24}",
        "",
        f"📊 *Қауіп деңгейі:* {r_emoji} {r_text}",
        f"📈 *Ұпай:* [{bar}] {score:.0%}",
        "",
    ]

    analysis = result.get("detailed_analysis", [])
    if analysis:
        lines.append("🔍 *Талдау нәтижелері:*")
        for item in analysis[:5]:
            if isinstance(item, dict):
                text = item.get("kz", item.get("ru", item.get("en", "")))
            else:
                text = str(item)
            if text:
                text = text.replace("*", "").replace("_", "").replace("`", "'")
                lines.append(f"  {text}")
        lines.append("")

    recs = result.get("recommendations", [])
    if recs:
        lines.append("💡 *Ұсыныстар:*")
        for rec in recs[:4]:
            if isinstance(rec, dict):
                text = rec.get("kz", rec.get("ru", rec.get("en", "")))
            else:
                text = str(rec)
            if text:
                text = text.replace("*", "").replace("_", "").replace("`", "'")
                lines.append(f"  {text}")

    return "\n".join(lines)


# ─── /start Command ─────────────────────────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Welcome message with main menu."""
    keyboard = [
        [KeyboardButton("🔗 URL тексеру"), KeyboardButton("📧 Email тексеру")],
        [KeyboardButton("📷 Фото тексеру"), KeyboardButton("📱 Нөмірді тексеру")],
        [KeyboardButton("🎙️ Аудио/Дауыс"), KeyboardButton("💬 AI Кеңесші")],
        [KeyboardButton("📊 Статистика"), KeyboardButton("📜 Тарих")],
        [KeyboardButton("🛑 Қауіпті домендер"), KeyboardButton("🎮 Тренажер")],
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

    await update.message.reply_text(
        "🛡️ *CyberQalqan AI*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "Киберқауіпсіздік жасанды интеллект жүйесі\n\n"
        "🔗 *URL тексеру* — сілтемені фишингке тексеру\n"
        "📧 *Email тексеру* — хат мазмұнын талдау\n"
        "📷 *Фото тексеру* — QR-код немесе мәтінді (OCR) оқу\n"
        "📱 *Нөмірді тексеру* — телефон нөмірін алаяқтарға тексеру\n"
        "🎙️ *Аудио/Дауыс* — голосовой (vishing) талдау (тек файл жіберіңіз)\n"
        "💬 *AI Кеңесші* — кибер қауіпсіздік бойынша кеңес\n"
        "🎮 *Тренажер* — фишингке алданып қалмауды үйрететін симулятор\n"
        "📊 *Статистика* — жалпы талдау статистикасы\n"
        "📜 *Тарих* — соңғы тексерулер\n"
        "🛑 *Қауіпті домендер* — бұғатталған сайттар тізімі (жүктеу)\n\n"
        "Төмендегі батырмаларды қолданыңыз немесе тікелей сілтеме/фото/аудио жіберіңіз! 👇",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=reply_markup
    )


# ─── /help Command ───────────────────────────────────────────────────────

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show help."""
    await update.message.reply_text(
        "🛡️ *CyberQalqan AI — Көмек*\n\n"
        "*Командалар:*\n"
        "  /start — Басты мәзір\n"
        "  /url — URL сілтемесін тексеру\n"
        "  /email — Email хатты тексеру\n"
        "  /qr — Фотоны тексеру (QR немесе OCR мәтін)\n"
        "  /phone — Телефон нөмірін тексеру\n"
        "  /stats — Статистика\n"
        "  /history — Тексерулер тарихы\n"
        "  /domains — Қауіпті домендер тізімін жүктеп алу\n"
        "  /help — Көмек\n\n"
        "*Жылдам тексеру:*\n"
        "  Тікелей сілтемені жіберіңіз — бот тексереді!\n"
        "  Фото жіберіңіз — QR-код немесе түбіртек (чек) мәтінін тексереді!\n"
        "  Дауыстық хабарлама жіберіңіз — алаяқтардың (вишинг) сөзін сараптайды!\n"
        "  Кез келген сұрақ жазыңыз — AI кеңесші жауап береді!\n",
        parse_mode=ParseMode.MARKDOWN
    )


# ─── URL Analysis ────────────────────────────────────────────────────────

async def url_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start URL analysis flow."""
    if context.args:
        url = " ".join(context.args)
        await _analyze_url(update, context, url)
        return ConversationHandler.END

    await update.message.reply_text(
        "🔗 *URL тексеру*\n\n"
        "Тексергіңіз келетін сілтемені жіберіңіз:\n"
        "Мысалы: https://example.com\n\n"
        "Бас тарту: /cancel",
        parse_mode=ParseMode.MARKDOWN
    )
    return WAITING_URL


async def receive_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive URL and analyze."""
    url = update.message.text.strip()
    await _analyze_url(update, context, url)
    return ConversationHandler.END


async def _analyze_url(update: Update, context: ContextTypes.DEFAULT_TYPE, url: str):
    """Perform URL analysis."""
    await update.message.chat.send_action(ChatAction.TYPING)

    safe_url = escape_md(url[:80])
    msg = await update.message.reply_text(
        f"🔍 Тексерілуде...\n{safe_url}\n\n⏳ Күте тұрыңыз..."
    )

    result = await api_request("POST", "/api/analyze-url", json={"url": url})

    if result:
        safe_display = escape_md(url[:60])
        text = f"🔗 *URL:* {safe_display}\n\n" + format_analysis_result(result, "URL")
        try:
            await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
        except Exception:
            await msg.edit_text(text.replace("*", ""))
    else:
        await msg.edit_text(
            "❌ Қате! Серверге қосылу мүмкін болмады.\n"
            "Сервер ояту үшін 1-2 минут күтіңіз және қайталаңыз."
        )


# ─── Email Analysis ──────────────────────────────────────────────────────

async def email_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start email analysis flow."""
    await update.message.reply_text(
        "📧 *Email тексеру*\n\n"
        "Хат тақырыбын жазыңыз (немесе - жіберіңіз):\n\n"
        "Бас тарту: /cancel",
        parse_mode=ParseMode.MARKDOWN
    )
    return WAITING_EMAIL_SUBJECT


async def receive_email_subject(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive email subject."""
    subject = update.message.text.strip()
    context.user_data["email_subject"] = "" if subject == "-" else subject
    await update.message.reply_text("📝 Хат мәтінін жіберіңіз (body):")
    return WAITING_EMAIL_BODY


async def receive_email_body(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive email body."""
    context.user_data["email_body"] = update.message.text.strip()
    await update.message.reply_text("📨 Жіберушінің email мекенжайын жазыңыз (немесе -):")
    return WAITING_EMAIL_SENDER


async def receive_email_sender(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive email sender and perform analysis."""
    sender = update.message.text.strip()
    sender = "" if sender == "-" else sender

    subject = context.user_data.get("email_subject", "")
    body = context.user_data.get("email_body", "")

    await update.message.chat.send_action(ChatAction.TYPING)
    msg = await update.message.reply_text("🔍 Email тексерілуде...\n⏳ Күте тұрыңыз...")

    result = await api_request("POST", "/api/analyze-email", json={
        "subject": subject, "body": body, "sender": sender
    })

    if result:
        safe_subject = escape_md(subject[:40] or "жоқ")
        safe_sender = escape_md(sender[:40] or "белгісіз")
        header = f"📧 *Email талдау*\n  Тақырып: {safe_subject}\n  Жіберуші: {safe_sender}\n\n"
        text = header + format_analysis_result(result, "Email")
        try:
            await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
        except Exception:
            await msg.edit_text(text.replace("*", ""))
    else:
        await msg.edit_text("❌ Қате! Серверге қосылу мүмкін болмады.")

    context.user_data.pop("email_subject", None)
    context.user_data.pop("email_body", None)
    return ConversationHandler.END


# ─── QR Code Analysis ────────────────────────────────────────────────────

async def qr_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start QR analysis flow."""
    await update.message.reply_text(
        "📷 *QR код тексеру*\n\n"
        "QR-код суретін жіберіңіз:\n"
        "(Фото ретінде жіберіңіз, файл емес)\n\n"
        "Бас тарту: /cancel",
        parse_mode=ParseMode.MARKDOWN
    )
    return WAITING_QR


async def receive_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive photo: 1. Try QR analysis. 2. If no QR, try text OCR analysis."""
    if update.message.photo:
        photo = update.message.photo[-1]
    elif update.message.document:
        photo = update.message.document
    else:
        await update.message.reply_text("❌ Фото жіберіңіз!")
        return WAITING_QR

    await update.message.chat.send_action(ChatAction.TYPING)
    msg = await update.message.reply_text("🔍 Суретті тексеріп жатырмын...\n⏳ Күте тұрыңыз...")

    file = await photo.get_file()
    photo_bytes = await file.download_as_bytearray()

    # 1. Try QR Code Analysis First
    qr_result = await api_request(
        "POST", "/api/analyze-qr",
        files={"file": ("qr.png", io.BytesIO(photo_bytes), "image/png")}
    )

    if qr_result:
        decoded_url = qr_result.get("decoded_url", "белгісіз")
        safe_url = escape_md(decoded_url[:60])
        header = f"📷 *QR Код Талдау*\n  Сілтеме: {safe_url}\n\n"
        text = header + format_analysis_result(qr_result, "QR")
        try:
            await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
        except Exception:
            await msg.edit_text(text.replace("*", ""))
        return ConversationHandler.END

    # 2. If NO QR code found, try OCR Image Text Analysis
    msg = await msg.edit_text("🔍 QR-код табылмады. Суреттегі мәтінді оқуға көштім (OCR)...\n⏳ Күте тұрыңыз...")
    
    ocr_result = await api_request(
        "POST", "/api/analyze-image",
        files={"file": ("image.jpg", io.BytesIO(photo_bytes), "image/jpeg")}
    )
    
    if ocr_result:
        extracted = ocr_result.get("extracted_text", "")
        analysis = ocr_result.get("analysis", {}).get("answer", {})
        
        if isinstance(analysis, dict):
            ai_text = analysis.get("kz", analysis.get("ru", analysis.get("en", "..."))).strip()
        else:
            ai_text = str(analysis).strip()
            
        ai_text = escape_md(ai_text)
        
        # Don't show the whole extracted text to the user, just a snippet to not spam
        snippet = extracted[:150].replace('\n', ' ') + "..." if len(extracted) > 150 else extracted.replace('\n', ' ')
        safe_snippet = escape_md(snippet)
        
        text = f"🖼️ *Суреттен оқылған мәтін:*\n_{safe_snippet}_\n\n🤖 *CyberQalqan AI:*\n{ai_text}"
        try:
            await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
        except Exception:
            await msg.edit_text(text.replace("*", "").replace("_", ""))
    else:
        await msg.edit_text("❌ QR-код немесе түсінікті мәтін табылмады!\nСурет сапасын тексеріп қайта жіберіңіз.")

    return ConversationHandler.END


# ─── Stats ────────────────────────────────────────────────────────────────

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show analysis statistics."""
    await update.message.chat.send_action(ChatAction.TYPING)
    result = await api_request("GET", "/api/stats")

    if result:
        total = result.get("total_analyses", 0)
        safe = result.get("safe", 0)
        suspicious = result.get("suspicious", 0)
        phishing = result.get("phishing", 0)
        by_type = result.get("by_type", {})

        safe_pct = (safe / total * 100) if total > 0 else 0
        sus_pct = (suspicious / total * 100) if total > 0 else 0
        phish_pct = (phishing / total * 100) if total > 0 else 0

        text = (
            f"📊 *CyberQalqan AI — Статистика*\n"
            f"{'━' * 24}\n\n"
            f"📋 *Жалпы тексерулер:* {total}\n\n"
            f"🟢 Қауіпсіз: *{safe}* ({safe_pct:.0f}%)\n"
            f"🟡 Күдікті: *{suspicious}* ({sus_pct:.0f}%)\n"
            f"🔴 Фишинг: *{phishing}* ({phish_pct:.0f}%)\n\n"
            f"📈 *Тексеру түрлері:*\n"
            f"  🔗 URL: {by_type.get('url', 0)}\n"
            f"  📧 Email: {by_type.get('email', 0)}\n"
            f"  📷 QR: {by_type.get('qr', 0)}\n"
        )
        await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text("❌ Статистиканы жүктеу мүмкін болмады.\nСервер ояту үшін 1-2 минут күтіңіз.")


# ─── History ──────────────────────────────────────────────────────────────

async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show recent analysis history."""
    await update.message.chat.send_action(ChatAction.TYPING)
    result = await api_request("GET", "/api/history", params={"limit": 10})

    if result and result.get("history"):
        lines = ["📜 *Соңғы тексерулер:*\n"]
        type_emoji = {"url": "🔗", "email": "📧", "qr": "📷"}

        for i, item in enumerate(result["history"], 1):
            t = item.get("type", "?")
            emoji = type_emoji.get(t, "❔")
            v = item.get("verdict", "?")
            v_emoji = VERDICT_EMOJI.get(v, "❔")
            inp = escape_md(item.get("input", "")[:35])
            score = item.get("score", 0)
            ts = item.get("timestamp", "")[:10]
            lines.append(f"*{i}.* {emoji} {v_emoji} {inp}\n     Ұпай: {score:.0%} | {ts}")

        try:
            await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
        except Exception:
            await update.message.reply_text("\n".join(lines).replace("*", ""))
    elif result:
        await update.message.reply_text("📜 Тарих бос — әлі тексеру жүргізілмеген.")
    else:
        await update.message.reply_text("❌ Тарихты жүктеу мүмкін болмады.")


# ─── Download Dangerous Domains ──────────────────────────────────────────

async def download_domains_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Download the dangerous domains list as a file."""
    await update.message.chat.send_action(ChatAction.UPLOAD_DOCUMENT)
    
    url = f"{API_URL}/api/dangerous-domains/download"
    client = await get_api_client()
    try:
        resp = await client.get(url)
        if resp.status_code == 200:
            file_content = resp.content
            await update.message.reply_document(
                document=file_content,
                filename="dangerous_domains.txt",
                caption="⚠️ *Қауіпті домендер тізімі*\n\nБұл файлда анықталған фишинг және қауіпті сайттар тізімі сақталған.",
                parse_mode=ParseMode.MARKDOWN
            )
        else:
            await update.message.reply_text("❌ Файлды жүктеу мүмкін болмады. Сервер қатесі.")
    except Exception as e:
        logger.error(f"Failed to download domains: {e}")
        await update.message.reply_text("❌ Қате пайда болды. Кейінірек қайталап көріңіз.")


# ─── Phone Analysis ──────────────────────────────────────────────────────

async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start phone analysis flow."""
    if context.args:
        phone = " ".join(context.args)
        await _analyze_phone(update, context, phone)
        return ConversationHandler.END

    await update.message.reply_text(
        "📱 *Телефон нөмірін тексеру*\n\n"
        "Тексергіңіз келетін нөмірді жіберіңіз:\n"
        "Мысалы: +7 701 000 0000 немесе 87010000000\n\n"
        "Бас тарту: /cancel",
        parse_mode=ParseMode.MARKDOWN
    )
    return WAITING_PHONE


async def receive_phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive phone number and analyze."""
    phone = update.message.text.strip()
    await _analyze_phone(update, context, phone)
    return ConversationHandler.END


async def _analyze_phone(update: Update, context: ContextTypes.DEFAULT_TYPE, phone: str):
    """Perform phone analysis."""
    await update.message.chat.send_action(ChatAction.TYPING)

    safe_phone = escape_md(phone[:30])
    msg = await update.message.reply_text(
        f"🔍 Тексерілуде...\n{safe_phone}\n\n⏳ Күте тұрыңыз..."
    )

    result = await api_request("POST", "/api/analyze-phone", json={"phone": phone})

    if result:
        safe_display = escape_md(phone[:30])
        text = f"📱 *Нөмір:* {safe_display}\n\n" + format_analysis_result(result, "Phone")
        try:
            await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
        except Exception:
            await msg.edit_text(text.replace("*", ""))
    else:
        await msg.edit_text(
            "❌ Қате! Серверге қосылу мүмкін болмады.\n"
            "Сервер ояту үшін 1-2 минут күтіңіз және қайталаңыз."
        )


# ─── AI Chat & Group Link Moderation ─────────────────────────────────────

import re

# Regex to find URLs anywhere in the text
URL_REGEX = re.compile(r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)')

def get_urls_from_message(message) -> List[str]:
    """Extracts URLs from a Telegram message using entities and regex."""
    if not message:
        return []

    clean_urls = set()

    # 1. Extract from standard entities
    entities = message.entities or []
    text = message.text or ""
    for ent in entities:
        if ent.type == "url":
            clean_urls.add(text[ent.offset:ent.offset + ent.length])
        elif ent.type == "text_link" and ent.url:
            clean_urls.add(ent.url)

    # 2. Extract from caption entities (if media message)
    caption_entities = message.caption_entities or []
    caption = message.caption or ""
    for ent in caption_entities:
        if ent.type == "url":
            clean_urls.add(caption[ent.offset:ent.offset + ent.length])
        elif ent.type == "text_link" and ent.url:
            clean_urls.add(ent.url)

    # 3. Fallback to regex testing just in case
    text_to_search = text + " " + caption
    if text_to_search.strip():
        regex_urls = URL_REGEX.findall(text_to_search)
        for u in regex_urls:
            u = u.rstrip(".,;!?()[]{}'\"")
            if '.' in u and len(u) > 4:
                clean_urls.add(u)

    # Clean up and validate URLs
    final_urls = []
    for u in clean_urls:
        if not u.startswith(('http://', 'https://')):
            u = 'http://' + u
        final_urls.append(u)

    return list(final_urls)


async def process_urls_in_background(update: Update, context: ContextTypes.DEFAULT_TYPE, urls: List[str]):
    """Background task to analyze URLs and delete message if malicious."""
    for url in urls:
        try:
            # 1. Ask our backend API
            result = await api_request("POST", "/api/analyze-url", json={"url": url})
            if not result:
                continue
                
            # 2. Check if dangerous
            verdict = result.get("verdict", "safe")
            risk = result.get("risk_level", "low")
            score = result.get("score", 0.0)
            
            is_malicious = False
            reason_text = ""
            
            # Analyze detailed issues to generate specific punishment reasons
            details = result.get("detailed_analysis", [])
            details_str = str(details).lower()
            
            if verdict == "phishing" or risk in ["critical", "high"] or score > 0.75:
                is_malicious = True
                
                # Determine the exact reason for the warning message based on our new backend checks
                if "казино" in details_str or "casino" in details_str or "құмар" in details_str:
                    reason_text = "🎰 Реклама онлайн-казино / азартных игр"
                elif "openphish" in details_str or "osint" in details_str:
                    reason_text = "🚨 Сайт находится в глобальном черном списке мошенников (OSINT)"
                elif "фишинг" in details_str or "phishing" in details_str or "карта" in details_str or "cvv" in details_str or "external domain" in details_str:
                    reason_text = "🎣 Сбор паролей или данных карт (Фишинг)"
                elif "iframe" in details_str or "редирект" in details_str or "redirect" in details_str:
                    reason_text = "🔀 Скрытый редирект или опасный iframe"
                else:
                    reason_text = "⚠️ Вредоносная или опасная ссылка"

            # 3. Take action
            if is_malicious:
                logger.info(f"Detected malicious URL ({verdict} / {score}) in group message: {url}")
                try:
                    # Try to delete the message (needs Admin rights)
                    if update.message:
                        await update.message.delete()
                        
                        # Send public warning
                        user = update.message.from_user
                        username = user.username if getattr(user, 'username', None) else "Пользователь"
                        user_mention = f"@{username}" if username != "Пользователь" else getattr(user, 'first_name', 'Неизвестный')
                        
                        warning_text = (
                            f"🛡 <b>CyberQalqan AI Security</b>\n\n"
                            f"Удалено сообщение от {user_mention}, так как оно содержало опасную ссылку.\n"
                            f"<b>Обнаружено:</b> {reason_text}\n\n"
                            f"<i>Система автоматически модерирует опасный контент.</i>"
                        )
                        await context.bot.send_message(
                            chat_id=update.effective_chat.id, 
                            text=warning_text, 
                            parse_mode=ParseMode.HTML
                        )
                except Exception as e:
                    logger.error(f"Failed to delete message/send warning: {e}")
                
                # Stop checking other URLs in this same message once we found a bad one
                break
            else:
                # 4. Action for safe URLs
                logger.info(f"URL is safe ({verdict} / {score}): {url}")
                if update.message:
                    try:
                        await update.message.reply_text(
                            "✅ <b>CyberQalqan AI:</b> Сілтеме қауіпсіз / Ссылка безопасна", 
                            parse_mode=ParseMode.HTML, 
                            disable_notification=True,
                            reply_to_message_id=update.message.message_id
                        )
                    except Exception as e:
                        logger.error(f"Failed to send safe URL confirmation: {e}")
                
        except Exception as e:
            logger.error(f"Background URL processing error: {e}")

async def chat_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle general text. Checks for links first, if none, treats as AI chat."""
    if not update.message:
        return
        
    text = update.message.text or update.message.caption or ""
    text = text.strip()

    # 1. Search for ANY URLs anywhere in the message (text, caption, entities)
    urls = get_urls_from_message(update.message)
    
    if urls:
        # If it's a private chat and someone just sent a direct link, reply with analysis
        if update.effective_chat.type == "private" and text.startswith(("http://", "https://", "www.")) and len(text.split()) == 1:
            await _analyze_url(update, context, text)
            return
            
        # For groups OR messages that contain text + links, run moderation in background
        asyncio.create_task(process_urls_in_background(update, context, urls))
        
        # If the bot is in a group, we shouldn't respond to general text with AI chat unless explicitly tagged
        if update.effective_chat.type in ["group", "supergroup"]:
            return

    if not text:
        return

    # If it's a group, only respond to AI chat if the bot is specifically mentioned
    if update.effective_chat.type in ["group", "supergroup"]:
        # simple check: if bot username is not in text, do nothing
        bot_info = await context.bot.get_me()
        bot_username = f"@{bot_info.username}"
        if bot_username not in text:
            return
        # remove bot username from the prompt
        text = text.replace(bot_username, "").strip()

    # Auto-detect phone numbers (only in private chat usually)
    digits = re.sub(r'\D', '', text)
    is_mostly_digits = len(text) > 0 and (sum(c.isdigit() for c in text) / len(text)) > 0.5
    if (text.startswith('+') and len(digits) >= 10) or (len(digits) >= 10 and len(digits) <= 15 and is_mostly_digits):
        await _analyze_phone(update, context, text)
        return

    # Call AI Advisor
    await update.message.chat.send_action(ChatAction.TYPING)
    result = await api_request("POST", "/api/chat", json={"message": text})

    if result:
        answer = result.get("answer", {})
        if isinstance(answer, dict):
            response_text = answer.get("kz", answer.get("ru", answer.get("en", "...")))
        else:
            response_text = str(answer)

        safe_response = response_text.replace("`", "'")
        try:
            await update.message.reply_text(f"🤖 *CyberQalqan AI:*\n\n{safe_response}", parse_mode=ParseMode.MARKDOWN)
        except Exception:
            await update.message.reply_text(f"🤖 CyberQalqan AI:\n\n{response_text}")
    else:
        await update.message.reply_text("❌ AI кеңесшіге қосылу мүмкін болмады.\nСервер ояну үшін 1-2 минут күтіңіз.")

# ─── Button Handlers ─────────────────────────────────────────────────────

async def ai_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle AI Chat button press."""
    suggestions = [
        "📸 Instagram қорғау", "🔐 Құпиясөз қауіпсіздігі",
        "📱 Телефон бұзылды ма?", "🎣 Фишинг деген не?",
        "📶 Wi-Fi қауіпсіздік", "🌐 VPN деген не?",
    ]
    keyboard = [[InlineKeyboardButton(s, callback_data=f"chat_{s}")] for s in suggestions]
    await update.message.reply_text(
        "💬 *AI Кеңесші*\n\nКибер қауіпсіздік бойынша кез келген сұрақ жазыңыз!\nНемесе дайын сұрақтардан таңдаңыз:",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def inline_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline keyboard button presses."""
    query = update.callback_query
    await query.answer()

    if query.data.startswith("chat_"):
        question = query.data[5:]
        await query.message.chat.send_action(ChatAction.TYPING)
        result = await api_request("POST", "/api/chat", json={"message": question})

        if result:
            answer = result.get("answer", {})
            if isinstance(answer, dict):
                response_text = answer.get("kz", answer.get("ru", answer.get("en", "...")))
            else:
                response_text = str(answer)

            safe_response = response_text.replace("`", "'")
            try:
                await query.message.reply_text(f"🤖 *CyberQalqan AI:*\n\n{safe_response}", parse_mode=ParseMode.MARKDOWN)
            except Exception:
                await query.message.reply_text(f"🤖 CyberQalqan AI:\n\n{response_text}")


# ─── Phishing Simulator ────────────────────────────────────────────────────

async def simulator_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start a phishing simulation training session."""
    await update.message.chat.send_action(ChatAction.TYPING)
    msg = await update.message.reply_text("🎮 *Phishing Simulator*\n\nАлаяқтық жағдай жасалуда... / Генерирую тестовый сценарий...\n⏳ Күте тұрыңыз...", parse_mode=ParseMode.MARKDOWN)

    # Call the backend API to generate a scenario
    result = await api_request("GET", "/api/simulator/generate")
    
    if result and "scenario" in result:
        scenario = result["scenario"]
        
        # Determine language preference based on common user strings or just dual-lingo
        # For the test, we will show the fake message in the generated language, but buttons in dual
        
        sim_msg_kz = scenario.get("message_kz", "")
        sim_msg_ru = scenario.get("message_ru", "")
        sender = scenario.get("sender", "Unknown")
        sim_type = scenario.get("type", "sms").upper()
        
        # Save explanations to context for the callback query
        import uuid
        scenario_id = str(uuid.uuid4())[:8]
        context.user_data[f"sim_{scenario_id}"] = {
            "explanation_kz": scenario.get("explanation_kz", ""),
            "explanation_ru": scenario.get("explanation_ru", "")
        }
        
        text = (
            f"🚨 *ЖАТТЫҒУ / ТРЕНИРОВКА*\n\n"
            f"Сізге жаңа хабарлама келді елестетіңіз:\n"
            f"Представьте, что вам пришло следующее сообщение:\n\n"
            f"📱 *Қайдан / От:* {sender} ({sim_type})\n"
            f"💬 *Мәтін / Текст:*\n"
            f"🇰🇿 {sim_msg_kz}\n"
            f"─────\n"
            f"🇷🇺 {sim_msg_ru}\n\n"
            f"🤔 *Не істейсіз? / Что будете делать?*"
        )
        
        keyboard = [
            [
                InlineKeyboardButton("✅ Мына сілтемеге өту (Перейти по ссылке)", callback_data=f"sim_fail_{scenario_id}")
            ],
            [
                InlineKeyboardButton("🛑 Жоқ! Бұл алаяқтар (Нет! Это мошенники)", callback_data=f"sim_pass_{scenario_id}")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        try:
            await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=reply_markup)
        except Exception:
            await msg.edit_text(text.replace("*", ""), reply_markup=reply_markup)
            
    else:
        await msg.edit_text("❌ Сервер қатесі. Сценарий құру мүмкін болмады. / Ошибка создания сценария.")

# ─── Voice / Audio Analysis ──────────────────────────────────────────────

async def voice_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle voice messages and send them for transcription and vishing analysis."""
    if not update.message or (not update.message.voice and not update.message.audio):
        return

    await update.message.chat.send_action(ChatAction.RECORD_VOICE)
    msg = await update.message.reply_text("🎙️ Дауыстық хабарлама сарапталуда...\n\n⏳ Күте тұрыңыз...")

    try:
        audio_file = update.message.voice or update.message.audio
        file = await audio_file.get_file()
        audio_bytes = await file.download_as_bytearray()
        
        result = await api_request(
            "POST", "/api/analyze-audio",
            files={"file": ("voice.ogg", io.BytesIO(audio_bytes), "audio/ogg")}
        )
        
        if result:
            transcript = result.get("transcript", "")
            analysis = result.get("analysis", {}).get("answer", {})
            
            if isinstance(analysis, dict):
                ai_text = analysis.get("kz", analysis.get("ru", analysis.get("en", "..."))).strip()
            else:
                ai_text = str(analysis).strip()
                
            ai_text = escape_md(ai_text)
            safe_transcript = escape_md(transcript[:500])
            
            text = f"🎙️ *Транскрипция:*\n_{safe_transcript}_\n\n🤖 *CyberQalqan AI:*\n{ai_text}"
            try:
                await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
            except Exception:
                await msg.edit_text(text.replace("*", "").replace("_", ""))
        else:
            await msg.edit_text("❌ Кешіріңіз, дауыстық хабарламаны сараптау мүмкін болмады.")
    except Exception as e:
        logger.error(f"Voice handling error: {e}")
        await msg.edit_text("⚠️ Сервер қатесі. Кейінірек қайталап көріңіз.")


async def video_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle video messages and send them for deepfake and vishing analysis."""
    if not update.message or (not update.message.video and not update.message.document):
        return

    # Just in case it's a document but not a video format
    if update.message.document and not str(update.message.document.mime_type).startswith('video/'):
        return

    await update.message.chat.send_action(ChatAction.RECORD_VIDEO)
    msg = await update.message.reply_text("📹 Бейнежазба (видео) сарапталуда...\n\nТергеу ИИ (Deepfake) мен Вишинг белгілеріне жүргізіліп жатыр.\n⏳ Күте тұрыңыз...")

    try:
        video_file = update.message.video or update.message.document
        file = await video_file.get_file()
        
        # Check size (Render free tier limitations)
        if hasattr(file, 'file_size') and file.file_size > 20 * 1024 * 1024:
            await msg.edit_text("⚠️ Файл тым үлкен (20 МБ-тан аспауы тиіс). / Файл слишком большой.")
            return
            
        video_bytes = await file.download_as_bytearray()
        
        result = await api_request(
            "POST", "/api/analyze-video",
            files={"file": ("video.mp4", io.BytesIO(video_bytes), "video/mp4")}
        )
        
        if result:
            transcript = result.get("transcript", "")
            analysis = result.get("analysis", {}).get("answer", {})
            
            if isinstance(analysis, dict):
                ai_text = analysis.get("kz", analysis.get("ru", analysis.get("en", "..."))).strip()
            else:
                ai_text = str(analysis).strip()
                
            ai_text = escape_md(ai_text)
            safe_transcript = escape_md(transcript[:500])
            
            text = f"📹 *Видео Транскрипциясы:*\n_{safe_transcript}_\n\n🤖 *CyberQalqan AI (Deepfake түйіні):*\n{ai_text}"
            try:
                await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
            except Exception:
                await msg.edit_text(text.replace("*", "").replace("_", ""))
        else:
            await msg.edit_text("❌ Кешіріңіз, бейнежазбаны сараптау мүмкін болмады.")
    except Exception as e:
        logger.error(f"Video handling error: {e}")
        await msg.edit_text("⚠️ Сервер қатесі. Видео пішімі қате немесе серверде орын жоқ.")
async def audio_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Prompt the user to send an audio/voice message when they click the button."""
    await update.message.reply_text(
        "🎙️ *Аудио/Дауыс тексеру*\n\n"
        "Маған кез-келген дауыстық хабарлама (голосовое) немесе аудио файл жіберіңіз.\n"
        "Мен оның мәтінін оқып, ішінде алаяқтық (vishing) белгілері бар-жоғын тексеремін!",
        parse_mode=ParseMode.MARKDOWN
    )

# ─── Cancel & Error ──────────────────────────────────────────────────────

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text("❌ Бас тартылды. /start — басты мәзірге оралу.")
    return ConversationHandler.END


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Exception: {context.error}")
    if update and update.message:
        try:
            await update.message.reply_text("⚠️ Қате пайда болды. Қайталап көріңіз.")
        except Exception:
            pass


# ─── Main ────────────────────────────────────────────────────────────────

def main():
    if not BOT_TOKEN:
        logger.error("❌ BOT_TOKEN IS MISSING!")
        logger.error("Please set it in Render Dashboard -> Environment Variables")
        return

    # 1. Start health check server in background thread (immediately!)
    # This is critical for Render to keep the service alive
    health_thread = threading.Thread(target=start_health_server, daemon=True)
    health_thread.start()

    # 2. Build application
    logger.info("🔨 Building application...")
    app = Application.builder().token(BOT_TOKEN).build()

    # 3. Register handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("stats", stats_command))
    app.add_handler(CommandHandler("history", history_command))
    app.add_handler(CommandHandler("domains", download_domains_command))

    # Conversation handlers
    url_conv = ConversationHandler(
        entry_points=[
            CommandHandler("url", url_command),
            MessageHandler(filters.Regex("^🔗 URL тексеру$"), url_command),
        ],
        states={WAITING_URL: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_url)]},
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    app.add_handler(url_conv)

    email_conv = ConversationHandler(
        entry_points=[
            CommandHandler("email", email_command),
            MessageHandler(filters.Regex("^📧 Email тексеру$"), email_command),
        ],
        states={
            WAITING_EMAIL_SUBJECT: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_email_subject)],
            WAITING_EMAIL_BODY: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_email_body)],
            WAITING_EMAIL_SENDER: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_email_sender)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    app.add_handler(email_conv)

    qr_conv = ConversationHandler(
        entry_points=[
            CommandHandler("qr", qr_command),
            MessageHandler(filters.Regex("^📷 Фото тексеру$"), qr_command),
        ],
        states={WAITING_QR: [MessageHandler(filters.PHOTO | filters.Document.IMAGE, receive_photo)]},
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    app.add_handler(qr_conv)

    phone_conv = ConversationHandler(
        entry_points=[
            CommandHandler("phone", phone_command),
            MessageHandler(filters.Regex("^📱 Нөмірді тексеру$"), phone_command),
        ],
        states={WAITING_PHONE: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_phone)]},
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    app.add_handler(phone_conv)

    app.add_handler(CallbackQueryHandler(inline_button_handler))
    app.add_handler(MessageHandler(filters.Regex("^📊 Статистика$"), stats_command))
    app.add_handler(MessageHandler(filters.Regex("^📜 Тарих$"), history_command))
    app.add_handler(MessageHandler(filters.Regex("^🛑 Қауіпті домендер$"), download_domains_command))
    app.add_handler(MessageHandler(filters.Regex("^💬 AI Кеңесші$"), ai_button_handler))
    app.add_handler(MessageHandler(filters.Regex("^🎙️ Аудио/Дауыс$"), audio_button_handler))
    app.add_handler(MessageHandler(filters.Regex("^🎮 Тренажер$"), simulator_command))
    app.add_handler(MessageHandler(filters.PHOTO, receive_photo))
    app.add_handler(MessageHandler(filters.VOICE | filters.AUDIO, voice_handler))
    app.add_handler(MessageHandler(filters.VIDEO | filters.Document.VIDEO, video_handler))
    app.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, chat_handler))

    app.add_error_handler(error_handler)

    # 4. Start the bot!
    logger.info("🛡️ CyberQalqan AI Telegram Bot is starting...")
    logger.info(f"📡 API: {API_URL}")
    
    # run_polling is safer for production on most servers
    app.run_polling(
        drop_pending_updates=True, 
        allowed_updates=Update.ALL_TYPES,
        poll_interval=2.0,  # Slower polling for Render stability
        close_loop=False
    )

if __name__ == "__main__":
    main()
