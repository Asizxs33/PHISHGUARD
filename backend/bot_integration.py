"""
CyberQalqan AI — Telegram Bot Integration Module
This module runs the Telegram bot in a background thread within the FastAPI backend.
It uses ML modules and Database functions directly for maximum performance.
"""

import os
import io
import asyncio
import logging
import threading
import json
from datetime import datetime
from typing import Optional

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

# Import local modules
from ml.features import extract_url_features, extract_email_features, get_url_feature_names, get_email_feature_names
from ml.heuristic_analyzer import analyze_url_heuristic, combine_scores
from ml.cyber_advisor import get_chat_response
from database import SessionLocal, save_analysis, get_history, get_stats

# ─── Config ──────────────────────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Conversation states
WAITING_URL, WAITING_EMAIL_SUBJECT, WAITING_EMAIL_BODY, WAITING_EMAIL_SENDER, WAITING_QR = range(5)

# ─── Shared Logic (replicating main.py logic for bot) ─────────────────────

VERDICT_EMOJI = {"phishing": "🔴", "suspicious": "🟡", "safe": "🟢"}
RISK_EMOJI = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "✅", "very_low": "🛡️"}
VERDICT_TEXT = {"phishing": "ФИШИНГ — ҚАУІПТІ!", "suspicious": "КҮДІКТІ", "safe": "ҚАУІПСІЗ"}
RISK_TEXT = {
    "critical": "Өте жоғары қауіп", "high": "Жоғары қауіп", 
    "medium": "Орташа қауіп", "low": "Төмен қауіп", "very_low": "Қауіпсіз"
}

def get_risk_level_label(score: float) -> str:
    if score < 0.2: return "very_low"
    elif score < 0.4: return "low"
    elif score < 0.6: return "medium"
    elif score < 0.8: return "high"
    else: return "critical"

def format_bot_result(result: dict) -> str:
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
            text = item.get("kz", "") if isinstance(item, dict) else str(item)
            if text: lines.append(f"  {text}")
        lines.append("")

    recs = result.get("recommendations", [])
    if recs:
        lines.append("💡 *Ұсыныстар:*")
        for rec in recs[:4]:
            text = rec.get("kz", "") if isinstance(rec, dict) else str(rec)
            if text: lines.append(f"  {text}")

    return "\n".join(lines)

# ─── Bot Handlers ───────────────────────────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [KeyboardButton("🔗 URL тексеру"), KeyboardButton("📧 Email тексеру")],
        [KeyboardButton("📷 QR код тексеру"), KeyboardButton("💬 AI Кеңесші")],
        [KeyboardButton("📊 Статистика"), KeyboardButton("📜 Тарих")],
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text(
        "🛡️ *CyberQalqan AI*\n━━━━━━━━━━━━━━━━━━━━━━\nКиберқауіпсіздік жүйесі\n\nСайтты немесе хатты тексеру үшін төмендегі батырмаларды қолданыңыз 👇",
        parse_mode=ParseMode.MARKDOWN, reply_markup=reply_markup
    )

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    db = SessionLocal()
    try:
        res = get_stats(db)
        total = res.get("total_analyses", 0)
        text = (
            f"📊 *Статистика*\n{'━' * 24}\n"
            f"📋 Жалпы тексерулер: {total}\n"
            f"🟢 Қауіпсіз: {res.get('safe', 0)}\n"
            f"🔴 Фишинг: {res.get('phishing', 0)}"
        )
        await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)
    finally:
        db.close()

async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    db = SessionLocal()
    try:
        hist = get_history(db, limit=10)
        if not hist:
            await update.message.reply_text("📜 Тарих бос.")
            return
        lines = ["📜 *Соңғы тексерулер:*\n"]
        for i, item in enumerate(hist, 1):
            v = item.get("verdict", "?")
            v_emoji = VERDICT_EMOJI.get(v, "❔")
            lines.append(f"*{i}.* {v_emoji} `{item.get('input', '')[:30]}`")
        await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)
    finally:
        db.close()

async def chat_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if text.startswith(("http://", "https://", "www.")):
        await analyze_url_logic(update, text)
        return
    
    await update.message.chat.send_action(ChatAction.TYPING)
    res = get_chat_response(text)
    ans = res.get("answer", {}).get("kz", "Кешіріңіз, түсінбедім.")
    await update.message.reply_text(f"🤖 *AI:* {ans}", parse_mode=ParseMode.MARKDOWN)

async def analyze_url_logic(update, url):
    await update.message.chat.send_action(ChatAction.TYPING)
    h_score, h_verdict, h_details = analyze_url_heuristic(url)
    
    # Lazy imports from main to avoid circular dependency
    import main
    from ml.features import extract_url_features, get_url_feature_names
    from ml.heuristic_analyzer import combine_scores
    
    features = extract_url_features(url)
    
    if main.url_classifier.is_trained:
        ml_score, ml_verdict, ml_details = main.url_classifier.predict([features[f] for f in get_url_feature_names()])
        score, verdict = combine_scores(ml_score, h_score, ml_verdict, h_verdict, h_details.get('issues', []))
    else:
        score, verdict = h_score, h_verdict

    risk = get_risk_level_label(score)
    detailed = main.generate_detailed_analysis(features, "url", h_details.get('issues', []))
    recs = main.get_recommendations(verdict, "url", features)

    db = SessionLocal()
    try:
        save_analysis(db, 'url', url, score, verdict, json.dumps(h_details))
    finally:
        db.close()

    res = {
        "verdict": verdict, "score": score, "risk_level": risk,
        "detailed_analysis": detailed, "recommendations": recs
    }
    await update.message.reply_text(format_bot_result(res), parse_mode=ParseMode.MARKDOWN)

# ─── Bot Runner ─────────────────────────────────────────────────────────

def run_bot(token):
    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Regex("^📊 Статистика$"), stats_command))
    app.add_handler(MessageHandler(filters.Regex("^📜 Тарих$"), history_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, chat_handler))
    
    logger.info("🤖 Bot thread started")
    app.run_polling()

def start_bot_thread():
    token = os.environ.get("BOT_TOKEN")
    if not token:
        logger.error("❌ NO BOT_TOKEN found in environment")
        return
    
    thread = threading.Thread(target=run_bot, args=(token,), daemon=True)
    thread.start()
