"""
CyberQalqan AI — Cyber Security Advisor (Knowledge-Based Chat)
Answers cybersecurity questions using a built-in knowledge base.
No API keys required — all knowledge is embedded in code.
"""

import g4f
from typing import Dict, Any

# ─── System Instructions for LLM ────────────────────────────────────────

SYSTEM_PROMPT = """
Ты — CyberQalqan AI, умный ИИ-консультант по кибербезопасности из Казахстана.
Твоя задача — помогать пользователям защищать свои данные от мошенников, фишинга и взломов.

Твои основные правила:
1. Отвечай на том же языке, на котором к тебе обратились (Казахский, Русский или Английский).
2. Давай четкие, структурированные и короткие ответы (используй списки и эмодзи).
3. НИКОГДА не упоминай, что ты "языковая модель", "AI от OpenAI" или "ChatGPT". Ты — CyberQalqan AI.
4. Если пользователь спрашивает, что ты умеешь, отвечай, что можешь проверить письма, ссылки, телефонные номера и дать советы по безопасности (Instagram, пароли, банки, Wi-Fi).
5. Приводи примеры из казахстанских реалий, если это уместно (Kaspi, Halyk, eGov, OLX).

Вот базовая база знаний, на которую ты должен опираться:
- Взлом Instagram: Включить 2FA (Authenticator/SMS), сложные пароли (12+ символов).
- Фишинг: Поддельные сайты или SMS (например "Kaspi: ваша карта заблокирована").
- Wi-Fi: Не заходить в банк через публичный Wi-Fi без VPN.
- Карты: Не говорить никому CVV и SMS коды. Лучше открыть виртуальную карту для онлайн покупок.
- Дети в интернете: Использовать Family Link, не общаться с незнакомцами.
- Утечка данных: Проверять почту через haveibeenpwned.com, менять пароли.
"""

# Quick responses for common short phrases to save time
QUICK_RESPONSES = {
    "рақмет": {"kz": "Оқасы жоқ! 😊 Тағы сұрағыңыз болса, жазыңыз!", "ru": "Пожалуйста! 😊", "en": "You're welcome! 😊"},
    "спасибо": {"kz": "Оқасы жоқ! 😊", "ru": "Пожалуйста! Обращайтесь ещё! 😊", "en": "You're welcome! 😊"},
    "thanks": {"kz": "Оқасы жоқ! 😊", "ru": "Пожалуйста! 😊", "en": "You're welcome! Feel free to ask more! 😊"},
    "thank you": {"kz": "Оқасы жоқ! 😊", "ru": "Пожалуйста! 😊", "en": "You're welcome! 😊"},
    "көмек": {"kz": "Мен сізге көмектесуге дайынмын! Қандай сұрағыңыз бар?", "ru": "Я готов помочь! Какой у вас вопрос?", "en": "I'm ready to help! What's your question?"},
    "help": {"kz": "Мен көмектесуге дайынмын!", "ru": "Я готов помочь!", "en": "I'm ready to help! What's your question?"},
    "привет": {"kz": "Сәлеметсіз бе! Мен CyberQalqan AI-мын. Сізге қандай көмек керек?", "ru": "Здравствуйте! Я CyberQalqan AI. Чем могу помочь?", "en": "Hello! I am CyberQalqan AI. How can I help you?"},
    "сәлем": {"kz": "Сәлеметсіз бе! Мен CyberQalqan AI-мын. Сізге қандай көмек керек?", "ru": "Здравствуйте! Я CyberQalqan AI. Чем могу помочь?", "en": "Hello! I am CyberQalqan AI. How can I help you?"},
    "hello": {"kz": "Сәлеметсіз бе! Мен CyberQalqan AI-мын. Сізге қандай көмек керек?", "ru": "Здравствуйте! Я CyberQalqan AI. Чем могу помочь?", "en": "Hello! I am CyberQalqan AI. How can I help you?"},
}


from g4f.client import Client

def get_chat_response(message: str) -> Dict[str, any]:
    """Get a chat response for the given message using g4f (LLM)."""
    msg_lower = message.lower().strip()

    # Check quick responses first to save time and API calls
    for key, response in QUICK_RESPONSES.items():
        if key in msg_lower:
            return {
                "answer": response,
                "source": "CyberQalqan AI (Quick Response)",
            }

    try:
        # Call the g4f LLM provider via the new Client interface
        client = Client()
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": message},
            ]
        )
        
        # Get the text content from the response
        response_text = response.choices[0].message.content
        
        # Clean up ads that some free g4f providers return
        ad_markers = [
            "Need proxies cheaper than the market?", 
            "https://op.wtf"
        ]
        for marker in ad_markers:
            if marker in response_text:
                response_text = response_text.split(marker)[0].strip()
        
        # Determine language vaguely based on input (fallback for JSON frontend if it requires a dict)
        if isinstance(response_text, str):
             answer_dict = {
                 "kz": response_text,
                 "ru": response_text,
                 "en": response_text
             }
        else:
             answer_dict = {
                 "kz": str(response_text),
                 "ru": str(response_text),
                 "en": str(response_text)
             }

        return {
            "answer": answer_dict,
            "source": "CyberQalqan LLM (g4f)",
        }
        
    except Exception as e:
        print(f"g4f Error: {e}")
        # Fallback if g4f fails (e.g. rate limit, no internet)
        fallback_msg = "Кешіріңіз, қазір менің серверімде жүктеме көп (LLM Error). Кішкене күте тұрыңыз. / Извините, сейчас большая нагрузка. Подождите немного."
        return {
            "answer": {
                "kz": fallback_msg,
                "ru": fallback_msg,
                "en": fallback_msg
            },
            "source": "CyberQalqan System Error"
        }


# Suggested questions for the chat UI
SUGGESTED_QUESTIONS = [
    {"kz": "Instagram аккаунтымды қалай қорғаймын?", "icon": "📸"},
    {"kz": "Телефоным бұзылды ма?", "icon": "📱"},
    {"kz": "Фишинг деген не?", "icon": "🎣"},
    {"kz": "Сенімді пароль қалай жасаймын?", "icon": "🔐"},
    {"kz": "Wi-Fi қауіпсіздігі", "icon": "📶"},
    {"kz": "Бұл сайт қауіпсіз бе?", "icon": "🌐"},
    {"kz": "VPN деген не?", "icon": "🌍"},
    {"kz": "2FA деген не?", "icon": "🔒"},
]
