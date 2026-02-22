import { useState, useRef, useEffect } from 'react'
import { sendChatMessage, getChatSuggestions } from '../api'

export default function CyberChat() {
    const [messages, setMessages] = useState([])
    const [input, setInput] = useState('')
    const [loading, setLoading] = useState(false)
    const [suggestions, setSuggestions] = useState([])
    const bottomRef = useRef(null)

    useEffect(() => {
        getChatSuggestions()
            .then(data => setSuggestions(data.suggestions || []))
            .catch(() => { })

        // Welcome message
        setMessages([{
            role: 'assistant',
            text: {
                kz: "👋 **Сәлеметсіз бе!** Мен — CyberQalqan AI киберқауіпсіздік кеңесшісімін.\n\nМаған кез келген сұрақ қоя аласыз:\n   🔒 Парольді қалай қорғаймын?\n   📱 Телефоным бұзылды ма?\n   🌐 Бұл сайт қауіпсіз бе?\n   📸 Instagram аккаунтымды қорғау\n\nСұрағыңызды жазыңыз! 👇",
                ru: "👋 Здравствуйте! Задайте вопрос о кибербезопасности.",
                en: "👋 Hello! Ask me about cybersecurity."
            },
            time: new Date()
        }])
    }, [])

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [messages])

    const handleSend = async (text) => {
        const msg = (text || input).trim()
        if (!msg || loading) return

        const userMsg = { role: 'user', text: msg, time: new Date() }
        setMessages(prev => [...prev, userMsg])
        setInput('')
        setLoading(true)

        try {
            const res = await sendChatMessage(msg)
            setMessages(prev => [...prev, {
                role: 'assistant',
                text: res.answer,
                time: new Date(res.timestamp)
            }])
        } catch {
            setMessages(prev => [...prev, {
                role: 'assistant',
                text: { kz: '⚠️ Серверге қосылу мүмкін болмады. Кейінірек қайталаңыз.', ru: 'Ошибка связи с сервером.', en: 'Connection error.' },
                time: new Date()
            }])
        }
        setLoading(false)
    }

    const formatMd = (text) => {
        if (!text) return ''
        return text
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/`(.*?)`/g, '<code class="px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300 text-xs font-mono">$1</code>')
            .replace(/\n/g, '<br/>')
    }

    const renderMsg = (msg, i) => {
        const isUser = msg.role === 'user'
        const content = typeof msg.text === 'string' ? msg.text : msg.text?.kz || ''
        const ruContent = typeof msg.text === 'object' ? msg.text?.ru : null

        return (
            <div key={i} className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-4 fade-up`}>
                <div className={`max-w-[85%] ${isUser ? 'order-2' : 'order-1'}`}>
                    {/* Header */}
                    <div className={`flex items-center gap-2 mb-1.5 ${isUser ? 'justify-end' : ''}`}>
                        {!isUser && (
                            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white text-xs font-bold shadow-lg shadow-indigo-500/20">
                                AI
                            </div>
                        )}
                        <span className="text-[0.6rem] text-slate-600 font-mono">
                            {isUser ? 'СІЗ' : 'CYBERQALQAN AI'}
                        </span>
                        <span className="text-[0.55rem] text-slate-700 font-mono">
                            {msg.time?.toLocaleTimeString?.('kk-KZ', { hour: '2-digit', minute: '2-digit' }) || ''}
                        </span>
                        {isUser && (
                            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white text-xs font-bold">
                                👤
                            </div>
                        )}
                    </div>

                    {/* Bubble */}
                    <div className={`rounded-2xl px-5 py-4 text-sm leading-relaxed
                        ${isUser
                            ? 'bg-gradient-to-br from-indigo-500/20 to-purple-500/15 border border-indigo-500/20 text-slate-200 rounded-tr-md'
                            : 'glass border border-white/[0.06] text-slate-300 rounded-tl-md'
                        }`}>
                        <div dangerouslySetInnerHTML={{ __html: formatMd(content) }} />
                        {ruContent && (
                            <details className="mt-3 group">
                                <summary className="cursor-pointer text-[0.7rem] text-slate-500 hover:text-slate-400 transition-colors select-none">
                                    🇷🇺 Орысша / На русском
                                </summary>
                                <div className="mt-2 pt-2 border-t border-white/5 text-xs text-slate-500"
                                    dangerouslySetInnerHTML={{ __html: formatMd(ruContent) }} />
                            </details>
                        )}
                    </div>
                </div>
            </div>
        )
    }

    return (
        <div className="flex flex-col h-[calc(100vh-64px)]">
            {/* Header */}
            <div className="relative glass rounded-3xl p-6 mb-4 overflow-hidden fade-up shrink-0">
                <div className="absolute inset-0 dot-pattern opacity-20" />
                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-1">
                        <div className="w-1 h-8 rounded-full bg-gradient-to-b from-purple-400 to-pink-400" />
                        <h2 className="text-2xl font-black tracking-tight gradient-text">КИБЕР КЕҢЕСШІ</h2>
                        <div className="ml-auto flex items-center gap-2">
                            <span className="relative flex h-2 w-2">
                                <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75 animate-ping" />
                                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
                            </span>
                            <span className="text-[0.6rem] text-emerald-400 font-mono">ONLINE</span>
                        </div>
                    </div>
                    <p className="text-slate-500 text-xs ml-4 font-mono">
                        AI КИБЕРҚАУІПСІЗДІК КЕҢЕСШІСІ · СҰРАҚ ҚОЙЫҢЫЗ
                    </p>
                </div>
            </div>

            {/* Chat Area */}
            <div className="flex-1 overflow-y-auto pr-2 min-h-0">
                <div className="space-y-1 pb-4">
                    {messages.map((msg, i) => renderMsg(msg, i))}

                    {loading && (
                        <div className="flex justify-start mb-4 fade-up">
                            <div className="glass rounded-2xl rounded-tl-md px-5 py-4 border border-white/[0.06]">
                                <div className="flex items-center gap-3">
                                    <div className="flex gap-1">
                                        <span className="w-2 h-2 rounded-full bg-indigo-400 animate-bounce" style={{ animationDelay: '0ms' }} />
                                        <span className="w-2 h-2 rounded-full bg-purple-400 animate-bounce" style={{ animationDelay: '150ms' }} />
                                        <span className="w-2 h-2 rounded-full bg-pink-400 animate-bounce" style={{ animationDelay: '300ms' }} />
                                    </div>
                                    <span className="text-xs text-slate-500 font-mono">ЖАУАП ДАЙЫНДАЛУДА...</span>
                                </div>
                            </div>
                        </div>
                    )}
                    <div ref={bottomRef} />
                </div>
            </div>

            {/* Suggestions */}
            {messages.length <= 1 && suggestions.length > 0 && (
                <div className="shrink-0 mb-3 fade-up stagger-1">
                    <div className="text-[0.6rem] text-slate-600 font-mono tracking-wider mb-2">ЖЫЛДАМ СҰРАҚТАР</div>
                    <div className="flex flex-wrap gap-2">
                        {suggestions.map((s, i) => (
                            <button key={i} onClick={() => handleSend(s.kz)}
                                className="group px-3.5 py-2.5 rounded-xl text-xs border transition-all cursor-pointer
                                    hover:-translate-y-1 hover:shadow-lg
                                    bg-indigo-500/5 border-indigo-500/15 text-indigo-300
                                    hover:border-indigo-500/40 hover:shadow-indigo-500/10 text-left">
                                <span className="mr-1.5">{s.icon}</span> {s.kz}
                            </button>
                        ))}
                    </div>
                </div>
            )}

            {/* Input */}
            <div className="shrink-0 glass glow-border rounded-2xl p-4 fade-up stagger-2">
                <form onSubmit={e => { e.preventDefault(); handleSend() }} className="flex gap-3">
                    <input
                        type="text"
                        value={input}
                        onChange={e => setInput(e.target.value)}
                        placeholder="Сұрағыңызды жазыңыз..."
                        className="input-dark flex-1"
                        disabled={loading}
                    />
                    <button type="submit" disabled={loading || !input.trim()}
                        className="px-6 py-3.5 rounded-xl bg-gradient-to-r from-purple-500 to-pink-600 text-white
                            font-bold shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/35
                            hover:-translate-y-1 active:translate-y-0 transition-all
                            disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:translate-y-0
                            cursor-pointer text-sm tracking-wide">
                        {loading ? '⏳' : '➤ ЖІБЕРУ'}
                    </button>
                </form>
            </div>
        </div>
    )
}
