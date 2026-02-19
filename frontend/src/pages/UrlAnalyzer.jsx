import { useState } from 'react'
import { analyzeUrl } from '../api'
import { ResultCard } from '../components/ResultCard'

export default function UrlAnalyzer() {
    const [url, setUrl] = useState('')
    const [loading, setLoading] = useState(false)
    const [result, setResult] = useState(null)
    const [error, setError] = useState('')

    const handleAnalyze = async (e) => {
        e.preventDefault()
        if (!url.trim()) return
        setLoading(true); setError(''); setResult(null)
        try { setResult(await analyzeUrl(url.trim())) }
        catch (err) { setError(err.response?.data?.detail || 'Серверге қосылу мүмкін болмады.') }
        setLoading(false)
    }

    const examples = [
        { url: 'https://google.com', label: 'google.com', safe: true },
        { url: 'https://kaspi.kz', label: 'kaspi.kz', safe: true },
        { url: 'http://paypal-secure-login.tk/verify-account', label: 'paypal-fake.tk', safe: false },
        { url: 'http://192.168.1.1/bank-login/verify', label: 'IP-address login', safe: false },
    ]

    const pipeline = [
        { n: '01', icon: '📐', title: 'FEATURE EXTRACTION', desc: '18 URL метрика: ұзындық, энтропия, TLD, IP, HTTPS', color: 'from-blue-500' },
        { n: '02', icon: '🧠', title: 'NEURAL FORWARD PASS', desc: 'ResidualBlock(3) + FeatureAttention + BatchNorm', color: 'from-indigo-500' },
        { n: '03', icon: '📊', title: 'SCORE COMPUTE', desc: 'Sigmoid → 0-100% қауіп ұпайы + Confidence', color: 'from-purple-500' },
        { n: '04', icon: '⚡', title: 'CLASSIFICATION', desc: 'Қауіпсіз / Күдікті / Фишинг модельдеу', color: 'from-cyan-500' },
    ]

    return (
        <div>
            {/* Header */}
            <div className="relative glass rounded-3xl p-8 mb-6 overflow-hidden fade-up">
                <div className="absolute inset-0 dot-pattern opacity-20" />
                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-1 h-8 rounded-full bg-gradient-to-b from-blue-400 to-indigo-400" />
                        <h2 className="text-3xl font-black tracking-tight gradient-text">URL ТЕКСЕРУ</h2>
                    </div>
                    <p className="text-slate-500 text-sm ml-4 font-mono">
                        СІЛТЕМЕНІ ЕНГІЗУ → НЕЙРОЖЕЛІ ТАЛДАУ → ҚАУІП БАҒАЛАУ
                    </p>
                </div>
            </div>

            {/* Input */}
            <div className="glass glow-border rounded-2xl p-6 mb-4 fade-up stagger-1">
                <form onSubmit={handleAnalyze}>
                    <div className="flex items-center gap-2 mb-3">
                        <span className="text-indigo-500/60 text-xs font-mono">[INPUT]</span>
                        <label className="text-sm font-medium text-slate-400">Тексерілетін URL мекенжай</label>
                    </div>
                    <div className="flex gap-3 flex-wrap">
                        <input type="text" value={url} onChange={e => setUrl(e.target.value)}
                            placeholder="https://example.com"
                            className="input-dark flex-1 min-w-[280px]" />
                        <button type="submit" disabled={loading || !url.trim()}
                            className="px-8 py-3.5 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 text-white
                                font-bold shadow-lg shadow-indigo-500/25 hover:shadow-xl hover:shadow-indigo-500/35
                                hover:-translate-y-1 active:translate-y-0 transition-all
                                disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:translate-y-0
                                cursor-pointer text-sm tracking-wide">
                            {loading ? '⏳ ТАЛДАУДА...' : '⬡ СКАНЕРЛЕУ'}
                        </button>
                    </div>
                </form>

                <div className="mt-5 pt-4 border-t border-white/5">
                    <div className="text-[0.6rem] text-slate-600 font-mono tracking-wider mb-2">ТЕСТ ҮЛГІЛЕРІ</div>
                    <div className="flex flex-wrap gap-2">
                        {examples.map(ex => (
                            <button key={ex.url} onClick={() => setUrl(ex.url)}
                                className={`group px-3.5 py-2 rounded-xl text-xs font-mono border transition-all cursor-pointer
                                    hover:-translate-y-1 hover:shadow-lg
                                    ${ex.safe
                                        ? 'bg-emerald-500/5 border-emerald-500/15 text-emerald-400 hover:border-emerald-500/40 hover:shadow-emerald-500/10'
                                        : 'bg-rose-500/5 border-rose-500/15 text-rose-400 hover:border-rose-500/40 hover:shadow-rose-500/10'}`}>
                                {ex.safe ? '◇' : '◆'} {ex.label}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {error && (
                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm fade-up font-mono">
                    [ERROR] {error}
                </div>
            )}

            {loading && (
                <div className="glass rounded-2xl p-8 text-center fade-up">
                    <div className="shimmer mb-6 mx-auto max-w-[350px]"></div>
                    <div className="text-indigo-400 font-bold tracking-wide text-sm">НЕЙРОЖЕЛІ ТАЛДАУ ЖҮРГІЗІЛУДЕ</div>
                    <div className="text-slate-600 text-xs font-mono mt-2 cursor-blink">
                        feature_extraction → attention_layer → classification
                    </div>
                </div>
            )}

            <ResultCard result={result} />

            {/* Pipeline */}
            <div className="glass rounded-2xl p-6 mt-5 fade-up stagger-2">
                <div className="flex items-center gap-2 mb-5">
                    <div className="w-1 h-4 rounded-full bg-gradient-to-b from-blue-400 to-cyan-400" />
                    <h3 className="text-sm font-bold text-slate-300">ТАЛДАУ PIPELINE</h3>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                    {pipeline.map((s, i) => (
                        <div key={s.n} className="group glass glass-hover rounded-xl p-5 relative overflow-hidden">
                            <div className={`absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r ${s.color} to-transparent opacity-0 group-hover:opacity-100 transition-opacity`} />
                            <div className="text-2xl mb-3" style={{ animation: `float ${3 + i * 0.4}s ease-in-out infinite` }}>{s.icon}</div>
                            <div className="font-mono text-[0.55rem] text-indigo-500/50 tracking-widest mb-1">STEP {s.n}</div>
                            <div className="text-xs font-bold text-slate-300 mb-1 tracking-wide">{s.title}</div>
                            <div className="text-[0.7rem] text-slate-600">{s.desc}</div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    )
}
