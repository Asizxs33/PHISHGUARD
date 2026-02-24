import { useState } from 'react'
import { analyzePhone } from '../api'

// We will use a custom mini ResultCard specifically for phones to show all the cool features
function PhoneResultCard({ result }) {
    if (!result) return null

    const { verdict, score, details } = result

    // UI mapping for verdicts
    const verdictConfig = {
        safe: {
            color: 'emerald',
            bg: 'bg-emerald-500/10',
            border: 'border-emerald-500/20',
            text: 'text-emerald-400',
            icon: '✓',
            label: 'ҚАУІПСІЗ НӨМІР',
            desc: 'Бұл нөмірден қауіп төніп тұрған жоқ. Сенім жүргізуге болады.'
        },
        suspicious: {
            color: 'amber',
            bg: 'bg-amber-500/10',
            border: 'border-amber-500/20',
            text: 'text-amber-400',
            icon: '⚠',
            label: 'КҮДІКТІ НӨМІР',
            desc: 'Нөмірде кейбір күдікті белгілер бар. Сақ болыңыз.'
        },
        phishing: {
            color: 'rose',
            bg: 'bg-rose-500/10',
            border: 'border-rose-500/20',
            text: 'text-rose-400',
            icon: '🛑',
            label: 'АЛАЯҚТЫҚ ҚАУПІ ЖОҒАРЫ!',
            desc: 'Бұл нөмір мошенниктерге тиесілі болуы мүмкін. Байланысты дереу үзіңіз!'
        }
    }

    const config = verdictConfig[verdict] || verdictConfig['suspicious']
    const pct = verdict === 'phishing' ? 100 : Math.round((score || 0) * 100)

    return (
        <div className={`mt-6 rounded-3xl ${config.bg} ${config.border} border p-8 fade-up transform transition-all duration-500 hover:scale-[1.01]`}>
            {/* Header */}
            <div className="flex flex-col md:flex-row items-center md:items-start gap-6 mb-8">
                <div className={`w-20 h-20 rounded-2xl flex items-center justify-center text-4xl shadow-lg border border-white/10
                    bg-gradient-to-br from-${config.color}-500 to-${config.color}-700 text-white shrink-0`}>
                    {config.icon}
                </div>

                <div className="flex-1 text-center md:text-left">
                    <div className={`font-mono text-[0.65rem] tracking-widest ${config.text} mb-2 opacity-80 uppercase`}>
                        [AI ANALYSIS COMPLETE]
                    </div>
                    <h3 className={`text-2xl md:text-3xl font-black ${config.text} tracking-tight mb-2`}>
                        {config.label}
                    </h3>
                    <p className="text-slate-300 text-sm md:text-base opacity-90">
                        {config.desc}
                    </p>
                </div>

                {/* Risk Score Circle */}
                <div className="shrink-0 flex flex-col items-center">
                    <div className="relative w-24 h-24 flex items-center justify-center bg-[#0a0a14] rounded-full border border-white/5 shadow-inner">
                        <svg className="absolute inset-0 w-full h-full -rotate-90">
                            <circle cx="48" cy="48" r="42" fill="none" className="stroke-slate-800" strokeWidth="6" />
                            <circle cx="48" cy="48" r="42" fill="none" className={`stroke-${config.color}-500`}
                                strokeWidth="6" strokeDasharray="264" strokeDashoffset={264 - (264 * pct) / 100}
                                strokeLinecap="round" style={{ transition: 'stroke-dashoffset 1.5s cubic-bezier(0.4, 0, 0.2, 1)' }} />
                        </svg>
                        <div className="text-center z-10">
                            <div className={`text-2xl font-black ${config.text}`}>{pct}%</div>
                        </div>
                    </div>
                    <div className="text-[0.6rem] text-slate-500 font-mono mt-2 tracking-widest">RISK LEVEL</div>
                </div>
            </div>

            {/* AI Insights & Heuristics */}
            {details && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-8">

                    {/* Heuristic Issues */}
                    {details.issues && details.issues.length > 0 && (
                        <div className="glass rounded-2xl p-5 border border-white/5">
                            <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 mb-4 tracking-wide uppercase">
                                <span className="text-amber-400">⚡</span> Анықталған Факторлар
                            </h4>
                            <div className="space-y-3">
                                {details.issues.map((issue, idx) => (
                                    <div key={idx} className="flex gap-3 bg-white/5 p-3 rounded-xl">
                                        <div className="text-rose-400 mt-0.5">•</div>
                                        <div>
                                            <div className="text-xs font-bold text-slate-200 mb-1">{issue.type.replace(/_/g, ' ').toUpperCase()}</div>
                                            <div className="text-[0.7rem] text-slate-400">{issue.detail}</div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Deep Learning Stats */}
                    {details.ml_score !== undefined && (
                        <div className="glass rounded-2xl p-5 border border-white/5">
                            <h4 className="flex items-center gap-2 text-sm font-bold text-slate-300 mb-4 tracking-wide uppercase">
                                <span className="text-indigo-400">🧠</span> Нейрожелі (Deep Learning)
                            </h4>
                            <div className="flex items-center justify-between mb-4 bg-white/5 p-3 rounded-xl border border-indigo-500/20">
                                <span className="text-xs text-slate-400 font-mono">NEURAL_PROBABILITY</span>
                                <span className="text-indigo-400 font-bold font-mono text-sm">{(details.ml_score * 100).toFixed(1)}%</span>
                            </div>

                            <p className="text-[0.7rem] text-slate-500 leading-relaxed">
                                AI моделі (PhoneNet) бұл нөмірдің математикалық құрылымын, энтропиясын және формат ауытқуларын талдап, 8000+ мошенник нөмірлерімен салыстырды.
                            </p>

                            <div className="mt-4 flex flex-wrap gap-2">
                                <span className="text-[0.6rem] px-2 py-1 rounded bg-indigo-500/10 text-indigo-400 font-mono border border-indigo-500/20">entropy_check</span>
                                <span className="text-[0.6rem] px-2 py-1 rounded bg-indigo-500/10 text-indigo-400 font-mono border border-indigo-500/20">pattern_match</span>
                                <span className="text-[0.6rem] px-2 py-1 rounded bg-indigo-500/10 text-indigo-400 font-mono border border-indigo-500/20">prefix_attention</span>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}

export default function PhoneAnalyzer() {
    const [phone, setPhone] = useState('')
    const [loading, setLoading] = useState(false)
    const [result, setResult] = useState(null)
    const [error, setError] = useState('')

    const handleAnalyze = async (e) => {
        e.preventDefault()
        if (!phone.trim()) return
        setLoading(true); setError(''); setResult(null)
        try { setResult(await analyzePhone(phone.trim())) }
        catch (err) { setError(err.response?.data?.detail || 'Серверге қосылу мүмкін болмады.') }
        setLoading(false)
    }

    const examples = [
        { num: '+77011234567', label: 'Қалыпты нөмір', safe: true },
        { num: '+77272585965', label: 'Қалыпты (Қалалық)', safe: true },
        { num: '+442079460958', label: 'Шет елдік (+44)', safe: false },
        { num: '+78005553535', label: '8-800 Spoofing', safe: false },
        { num: '+2348123456789', label: 'Нигерия (+234)', safe: false },
        { num: '+79999999999', label: 'Төмен энтропия (спам)', safe: false },
    ]

    const pipeline = [
        { n: '01', icon: '📞', title: 'FEATURE EXTRACTION', desc: 'Нөмірдің ұзындығы, цифрлар хаотичносты, префикстер', color: 'from-blue-500' },
        { n: '02', icon: '🧠', title: 'NEURAL NETWORK', desc: 'PhoneNet AI: 10 математикалық метрика арқылы талдау', color: 'from-indigo-500' },
        { n: '03', icon: '👮', title: 'HEURISTIC RULES', desc: 'Қауіпті аймақтар мен подмена нөмірлерін анықтау', color: 'from-purple-500' },
        { n: '04', icon: '🎯', title: 'AI VERDICT', desc: 'Екі жүйенің шешімін біріктіріп, нақты қауіп деңгейін есептеу', color: 'from-cyan-500' },
    ]

    return (
        <div>
            {/* Header */}
            <div className="relative glass rounded-3xl p-8 mb-6 overflow-hidden fade-up">
                <div className="absolute inset-0 dot-pattern opacity-20" />
                <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-500/10 rounded-full blur-[80px] -translate-y-1/2 translate-x-1/2" />
                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-1 h-8 rounded-full bg-gradient-to-b from-indigo-400 to-purple-400" />
                        <h2 className="text-3xl font-black tracking-tight gradient-text">ТЕЛЕФОН НӨМІРІН ТЕКСЕРУ</h2>
                    </div>
                    <p className="text-slate-400 text-sm ml-4 max-w-2xl mt-3 leading-relaxed">
                        Күмәнді қоңырау шалушының нөмірін енгізіңіз. Біздің <b>Deep Learning AI</b> жүйеміз нөмірдің құрылымын, шыққан аймағын және мошенниктерге тән паттерндерді талдайды.
                    </p>
                </div>
            </div>

            {/* Input */}
            <div className="glass glow-border rounded-2xl p-8 mb-4 fade-up stagger-1">
                <form onSubmit={handleAnalyze}>
                    <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-2">
                            <span className="text-indigo-500 text-lg">📱</span>
                            <label className="text-sm font-bold text-slate-300 tracking-wide uppercase">Күдікті нөмір</label>
                        </div>
                        <span className="text-indigo-500/40 text-[0.65rem] font-mono tracking-widest">[+7 / 8 САНДАРЫМЕН БАСТАҢЫЗ]</span>
                    </div>

                    <div className="flex flex-col sm:flex-row gap-4">
                        <div className="relative flex-1">
                            <input type="tel" value={phone} onChange={e => setPhone(e.target.value)}
                                placeholder="+7 (70X) XXX-XX-XX"
                                className="w-full bg-[#08080f]/50 border border-white/10 rounded-xl px-5 py-4 text-lg text-white font-mono shadow-inner
                                focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 placeholder:text-slate-600 transition-all" />
                        </div>
                        <button type="submit" disabled={loading || !phone.trim()}
                            className="px-10 py-4 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 text-white
                                font-black tracking-widest uppercase shadow-lg shadow-indigo-500/25 hover:shadow-xl hover:shadow-indigo-500/40
                                hover:-translate-y-1 active:translate-y-0 transition-all duration-300
                                disabled:opacity-30 disabled:cursor-not-allowed flex items-center justify-center gap-2">
                            {loading ? (
                                <>
                                    <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                                    ТАЛДАУ...
                                </>
                            ) : 'СКАНЕРЛЕУ'}
                        </button>
                    </div>
                </form>

                <div className="mt-8 pt-6 border-t border-white/5">
                    <div className="flex items-center gap-2 mb-3">
                        <span className="text-indigo-400/50 text-xs">⚡</span>
                        <div className="text-[0.65rem] text-slate-500 font-bold tracking-widest uppercase">ЖЫЛДАМ ТЕСТ ҮЛГІЛЕРІ</div>
                    </div>
                    <div className="flex flex-wrap gap-2.5">
                        {examples.map((ex, idx) => (
                            <button key={idx} onClick={() => setPhone(ex.num)}
                                className={`group px-4 py-2.5 rounded-xl text-[0.7rem] font-bold border transition-all duration-300 cursor-pointer
                                    hover:-translate-y-1 hover:shadow-lg flex items-center gap-2
                                    ${ex.safe
                                        ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-400/80 hover:text-emerald-400 hover:bg-emerald-500/10 hover:border-emerald-500/40 hover:shadow-emerald-500/10'
                                        : 'bg-rose-500/5 border-rose-500/20 text-rose-400/80 hover:text-rose-400 hover:bg-rose-500/10 hover:border-rose-500/40 hover:shadow-rose-500/10'}`}>
                                <span className="font-mono text-white/40 group-hover:text-white/80 transition-colors">{ex.num}</span>
                                <span className="w-px h-3 bg-white/10 mx-1" />
                                {ex.label}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Error Message */}
            {error ? (
                <div className="p-5 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm fade-up font-mono flex items-start gap-3">
                    <span className="text-xl">⚠️</span>
                    <div>
                        <div className="font-bold mb-1">[КАТЕ]</div>
                        {error}
                    </div>
                </div>
            ) : null}

            {loading && (
                <div className="mt-8 rounded-3xl border border-indigo-500/20 bg-[#0a0a14] p-12 text-center fade-up relative overflow-hidden">
                    {/* Scanning animation effect */}
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-indigo-500 to-transparent opacity-50 scanner-line" />

                    <div className="relative inline-block mb-6">
                        <div className="text-5xl">📱</div>
                        <div className="absolute -top-2 -right-2 w-4 h-4 rounded-full bg-indigo-500 animate-ping" />
                    </div>

                    <div className="text-indigo-400 font-black tracking-widest text-lg mb-2 uppercase">ИИ ТАЛДАУ ЖҮРГІЗІЛУДЕ</div>
                    <div className="text-slate-500 text-xs font-mono mb-6 cursor-blink uppercase tracking-wider">
                        extracting_features → neural_network_eval → heuristic_check
                    </div>

                    <div className="max-w-[200px] mx-auto h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 w-full animate-pulse origin-left" style={{ animationDuration: '1s' }} />
                    </div>
                </div>
            )}

            {!loading && <PhoneResultCard result={result} />}

            {/* Pipeline */}
            <div className="glass rounded-2xl p-8 mt-5 fade-up stagger-2">
                <div className="flex items-center gap-3 mb-6">
                    <div className="w-1.5 h-5 rounded-full bg-gradient-to-b from-blue-400 to-cyan-400" />
                    <h3 className="text-sm font-black text-slate-300 tracking-widest uppercase">DEEP LEARNING PIPELINE</h3>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {pipeline.map((s, i) => (
                        <div key={s.n} className="group rounded-2xl bg-white/[0.02] border border-white/[0.05] p-6 relative overflow-hidden hover:bg-white/[0.04] transition-all hover:-translate-y-1">
                            <div className={`absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r ${s.color} to-transparent opacity-0 group-hover:opacity-100 transition-opacity`} />

                            <div className="flex justify-between items-start mb-4">
                                <div className="text-3xl" style={{ animation: `float ${3 + i * 0.4}s ease-in-out infinite` }}>{s.icon}</div>
                                <div className="font-mono text-4xl font-black text-white/[0.03] group-hover:text-white/[0.05] transition-colors">{s.n}</div>
                            </div>

                            <div className="text-xs font-black text-white/90 mb-2 tracking-widest">{s.title}</div>
                            <div className="text-[0.75rem] text-slate-400 leading-relaxed">{s.desc}</div>
                        </div>
                    ))}
                </div>
            </div>

            <style jsx>{`
                .scanner-line {
                    animation: scan 2s linear infinite;
                }
                @keyframes scan {
                    0% { transform: translateY(-100%); opacity: 0; }
                    10% { opacity: 1; }
                    90% { opacity: 1; }
                    100% { transform: translateY(300px); opacity: 0; }
                }
            `}</style>
        </div>
    )
}
