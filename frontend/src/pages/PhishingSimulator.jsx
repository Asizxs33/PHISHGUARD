import { useState } from 'react'
import { generateSimulation } from '../api'

export default function PhishingSimulator() {
    const [loading, setLoading] = useState(false)
    const [scenario, setScenario] = useState(null)
    const [resultView, setResultView] = useState(null) // 'pass' or 'fail'
    const [error, setError] = useState('')
    const [activeLang, setActiveLang] = useState('ru')

    const startSimulation = async () => {
        setLoading(true); setError(''); setScenario(null); setResultView(null);
        try {
            const data = await generateSimulation()
            setScenario(data.scenario)
        } catch (err) {
            setError(err.response?.data?.detail || 'Серверге қосылу мүмкін болмады. Ошибка сервера.')
        }
        setLoading(false)
    }

    const handleAction = (isPass) => {
        setResultView(isPass ? 'pass' : 'fail')
    }

    const getPlatformIcon = (platform) => {
        if (!platform) return '📧'
        const p = platform.toLowerCase()
        if (p.includes('sms')) return '💬'
        if (p.includes('telegram') || p.includes('whatsapp')) return '📱'
        return '📧'
    }

    return (
        <div>
            {/* Header */}
            <div className="relative glass rounded-3xl p-8 mb-6 overflow-hidden fade-up">
                <div className="absolute inset-0 dot-pattern opacity-20" />
                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-1 h-8 rounded-full bg-gradient-to-b from-rose-400 to-orange-400" />
                        <h2 className="text-3xl font-black tracking-tight gradient-text">ФИШИНГ СИМУЛЯТОР</h2>
                    </div>
                    <p className="text-slate-500 text-sm ml-4 font-mono">
                        CYBERQALQAN AI • ОҚЫТУ ТРЕНАЖЕРЫ • SCAM AWARENESS
                    </p>
                </div>
            </div>

            {error && (
                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm fade-up font-mono mb-4">
                    [ERROR] {error}
                </div>
            )}

            {!scenario && !loading && (
                <div className="glass glow-border rounded-2xl p-12 text-center fade-up stagger-1 border-orange-500/10">
                    <div className="text-6xl mb-6" style={{ animation: 'float 3s ease-in-out infinite' }}>🎣</div>
                    <h3 className="text-2xl font-bold text-white mb-4">Жасанды Интеллект (AI) Тренажері</h3>
                    <p className="text-slate-400 max-w-lg mx-auto mb-8 leading-relaxed">
                        Бұл бөлімде ЖИ сізге арнайы фишингтік хаттар немесе хабарламалар жасайды.
                        Оларды оқып, зиянды екенін анықтауға тырысыңыз. Өз қауіпсіздік дағдыларыңызды шыңдаңыз!
                        <br /><br />
                        Здесь ИИ генерирует для вас уникальные фишинговые сообщения.
                        Попытайтесь распознать обман и улучшите свои навыки кибербезопасности!
                    </p>
                    <button onClick={startSimulation}
                        className="px-8 py-4 rounded-xl bg-gradient-to-r from-rose-500 to-orange-600 text-white
                            font-bold shadow-lg shadow-orange-500/25 hover:shadow-xl hover:shadow-orange-500/35
                            hover:-translate-y-1 active:translate-y-0 transition-all text-lg tracking-wide">
                        ▶ БАСТАУ / НАЧАТЬ
                    </button>
                </div>
            )}

            {loading && (
                <div className="glass rounded-2xl p-12 text-center fade-up border border-orange-500/20">
                    <div className="shimmer mb-6 mx-auto max-w-[350px]"></div>
                    <div className="text-orange-400 font-bold tracking-wide text-lg mt-4 animate-pulse">
                        LLM ГЕНЕРАЦИЯ ЖАСАУДА... / СОЗДАНИЕ СЦЕНАРИЯ...
                    </div>
                    <div className="text-slate-600 text-xs font-mono mt-2 cursor-blink">
                        generating_phishing_context → rendering_ui
                    </div>
                </div>
            )}

            {scenario && (
                <div className="fade-up stagger-1">
                    <div className="flex items-center gap-3 mb-4 px-2">
                        <div className="w-1 h-5 rounded-full bg-gradient-to-b from-rose-400 to-orange-400" />
                        <h3 className="text-lg font-bold text-slate-200 tracking-tight">Сценарий / Сценарий</h3>
                        <div className="ml-auto flex gap-2">
                            {['kz', 'ru', 'en'].map(lang => (
                                <button key={lang} onClick={() => setActiveLang(lang)}
                                    className={`px-3 py-1 rounded-lg text-xs font-bold uppercase transition-all
                                        ${activeLang === lang ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' : 'bg-white/5 text-slate-500 hover:text-slate-300'}`}>
                                    {lang}
                                </button>
                            ))}
                        </div>
                    </div>

                    <div className="glass rounded-2xl p-0 overflow-hidden mb-6 border-slate-700/50">
                        {/* Mock UI Header */}
                        <div className="bg-slate-900/80 px-4 py-3 border-b border-slate-700/50 flex items-center gap-3">
                            <div className="text-2xl">{getPlatformIcon(scenario.platform)}</div>
                            <div>
                                <div className="text-sm font-bold text-slate-200">{scenario.sender_name || 'Unknown Sender'}</div>
                                <div className="text-xs text-slate-500">{scenario.platform || 'Message'}</div>
                            </div>
                        </div>

                        {/* Mock UI Body */}
                        <div className="p-6 bg-[#0B0F19]">
                            <div className="bg-slate-800/50 rounded-2xl rounded-tl-none p-4 max-w-[85%] border border-slate-700/50">
                                <div className="text-slate-200 whitespace-pre-line text-[15px] leading-relaxed">
                                    {scenario.message[activeLang] || scenario.message.ru}
                                </div>
                            </div>
                        </div>

                        {/* Interactive Actions (Only show if not yet answered) */}
                        {!resultView && (
                            <div className="p-6 bg-slate-900/40 border-t border-slate-700/50 flex flex-col sm:flex-row gap-4 justify-center">
                                <button onClick={() => handleAction(false)}
                                    className="flex-1 py-3 px-4 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-400
                                        font-bold hover:bg-blue-500/20 hover:border-blue-500/50 hover:-translate-y-1 transition-all">
                                    🔗 Сілтемеге өту / Перейти по ссылке
                                </button>
                                <button onClick={() => handleAction(true)}
                                    className="flex-1 py-3 px-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400
                                        font-bold hover:bg-rose-500/20 hover:border-rose-500/50 hover:-translate-y-1 transition-all">
                                    🛑 Шағымдану / Пожаловаться (Спам)
                                </button>
                            </div>
                        )}
                    </div>

                    {/* Result View */}
                    {resultView && (
                        <div className={`glass glow-border rounded-2xl p-6 fade-up ${resultView === 'pass' ? 'border-emerald-500/30' : 'border-rose-500/30'}`}>
                            <div className="flex items-start gap-4 mb-4">
                                <div className="text-5xl">
                                    {resultView === 'pass' ? '✅' : '❌'}
                                </div>
                                <div>
                                    <h3 className={`text-xl font-bold mb-2 ${resultView === 'pass' ? 'text-emerald-400' : 'text-rose-400'}`}>
                                        {resultView === 'pass' ? 'Дұрыс! Бұл фишинг еді. / Правильно! Это был фишинг.' : 'Қате! Сіз алаяқтарға алдандыңыз. / Ошибка! Вы попались на уловку.'}
                                    </h3>
                                    <p className="text-slate-300 whitespace-pre-line leading-relaxed">
                                        {scenario.explanation[activeLang] || scenario.explanation.ru}
                                    </p>
                                </div>
                            </div>

                            <div className="bg-black/30 rounded-xl p-4 mt-4 border border-white/5">
                                <h4 className="text-sm font-bold text-slate-400 mb-3 uppercase tracking-wider">
                                    Қауіпті белгілер / Индикаторы опасности:
                                </h4>
                                <ul className="space-y-2">
                                    {(scenario.indicators || []).map((indicator, idx) => (
                                        <li key={idx} className="flex gap-2 text-sm text-slate-300">
                                            <span className="text-orange-400 mt-0.5">🚩</span>
                                            <span>{indicator[activeLang] || indicator.ru || indicator}</span>
                                        </li>
                                    ))}
                                </ul>
                            </div>

                            <div className="mt-6 flex justify-end">
                                <button onClick={startSimulation}
                                    className="px-6 py-2.5 rounded-xl bg-white/10 text-white font-bold hover:bg-white/20 transition-all border border-white/10">
                                    🔄 Келесі жаттығу / Следующая задача
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}
