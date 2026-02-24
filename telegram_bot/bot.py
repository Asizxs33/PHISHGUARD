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
        [KeyboardButton("📷 QR код тексеру"), KeyboardButton("📱 Нөмірді тексеру")],
        [KeyboardButton("💬 AI Кеңесші"), KeyboardButton("📊 Статистика"), KeyboardButton("📜 Тарих")],
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

    await update.message.reply_text(
        "🛡️ *CyberQalqan AI*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "Киберқауіпсіздік жасанды интеллект жүйесі\n\n"
        "🔗 *URL тексеру* — сілтемені фишингке тексеру\n"
        "📧 *Email тексеру* — хат мазмұнын талдау\n"
        "📷 *QR код тексеру* — QR-кодтағы сілтемені тексеру\n"
        "📱 *Нөмірді тексеру* — телефон нөмірін алаяқтарға тексеру\n"
        "💬 *AI Кеңесші* — кибер қауіпсіздік бойынша кеңес\n"
        "📊 *Статистика* — жалпы талдау статистикасы\n"
        "📜 *Тарих* — соңғы тексерулер\n\n"
        "Төмендегі батырмаларды қолданыңыз немесе тікелей сілтеме жіберіңіз! 👇",
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
        "  /qr — QR-кодты тексеру (фото жіберіңіз)\n"
        "  /phone — Телефон нөмірін тексеру\n"
        "  /stats — Статистика\n"
        "  /history — Тексерулер тарихы\n"
        "  /help — Көмек\n\n"
        "*Жылдам тексеру:*\n"
        "  Тікелей сілтемені жіберіңіз — бот тексереді!\n"
        "  Фото жіберіңіз — QR-код бар ма, тексереді!\n"
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


async def receive_qr_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Receive QR photo and analyze."""
    if update.message.photo:
        photo = update.message.photo[-1]
    elif update.message.document:
        photo = update.message.document
    else:
        await update.message.reply_text("❌ Фото жіберіңіз!")
        return WAITING_QR

    await update.message.chat.send_action(ChatAction.TYPING)
    msg = await update.message.reply_text("🔍 QR-код тексерілуде...\n⏳ Күте тұрыңыз...")

    file = await photo.get_file()
    photo_bytes = await file.download_as_bytearray()

    result = await api_request(
        "POST", "/api/analyze-qr",
        files={"file": ("qr.png", io.BytesIO(photo_bytes), "image/png")}
    )

    if result:
        decoded_url = result.get("decoded_url", "белгісіз")
        safe_url = escape_md(decoded_url[:60])
        header = f"📷 *QR Код Талдау*\n  Сілтеме: {safe_url}\n\n"
        text = header + format_analysis_result(result, "QR")
        try:
            await msg.edit_text(text, parse_mode=ParseMode.MARKDOWN)
        except Exception:
            await msg.edit_text(text.replace("*", ""))
    else:
        await msg.edit_text("❌ QR-код оқылмады!\nСурет сапасын тексеріңіз немесе басқа фото жіберіңіз.")

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


# ─── AI Chat ─────────────────────────────────────────────────────────────

async def chat_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle AI cybersecurity chat."""
    text = update.message.text.strip()

    # Auto-detect URLs
    if text.startswith(("http://", "https://", "www.")):
        await _analyze_url(update, context, text)
        return

    # Auto-detect phone numbers
    import re
    digits = re.sub(r'\D', '', text)
    is_mostly_digits = len(text) > 0 and (sum(c.isdigit() for c in text) / len(text)) > 0.5
    if (text.startswith('+') and len(digits) >= 10) or (len(digits) >= 10 and len(digits) <= 15 and is_mostly_digits):
        await _analyze_phone(update, context, text)
        return

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
            MessageHandler(filters.Regex("^📷 QR код тексеру$"), qr_command),
        ],
        states={WAITING_QR: [MessageHandler(filters.PHOTO | filters.Document.IMAGE, receive_qr_photo)]},
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
    app.add_handler(MessageHandler(filters.Regex("^💬 AI Кеңесші$"), ai_button_handler))
    app.add_handler(MessageHandler(filters.PHOTO, receive_qr_photo))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, chat_handler))

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
