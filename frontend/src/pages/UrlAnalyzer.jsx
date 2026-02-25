import { useState } from 'react'
import { analyzeUrl } from '../api'
import { ResultCard } from '../components/ResultCard'

export default function UrlAnalyzer() {
    const [url, setUrl] = useState('')
    const [loading, setLoading] = useState(false)
    const [result, setResult] = useState(null)
    const [error, setError] = useState('')

    const [scanStep, setScanStep] = useState(-1)

    const handleAnalyze = async (e) => {
        e.preventDefault()
        if (!url.trim()) return

        setLoading(true); setError(''); setResult(null); setScanStep(0);

        const steps = 4;
        const stepDuration = 800; // 800ms per step

        const animationInterval = setInterval(() => {
            setScanStep(prev => {
                if (prev >= steps - 1) {
                    clearInterval(animationInterval);
                    return prev;
                }
                return prev + 1;
            });
        }, stepDuration);

        const minDelay = new Promise(resolve => setTimeout(resolve, steps * stepDuration));

        try {
            const apiPromise = analyzeUrl(url.trim());
            const [apiResult] = await Promise.all([apiPromise, minDelay]);
            setResult(apiResult);
        } catch (err) {
            setError(err.response?.data?.detail || 'Серверге қосылу мүмкін болмады.')
        } finally {
            clearInterval(animationInterval);
            setLoading(false);
            setScanStep(-1);
        }
    }

    const scanStepsUI = [
        { icon: '🔄', text: 'Сайт серверіне қосылу...' },
        { icon: '👁️', text: 'Беттің мазмұнын оқу (HTML/Text)...' },
        { icon: '🎰', text: 'Казино және фишинг белгілерін іздеу...' },
        { icon: '🧠', text: 'ML нейрожелісі бойынша бағалау...' },
    ]

    const examples = [
        { url: 'https://google.com', label: 'google.com', safe: true },
        { url: 'https://kaspi.kz', label: 'kaspi.kz', safe: true },
        { url: 'http://kaspi-secure-login.tk/verify', label: 'kaspi-fake.tk', safe: false },
        { url: 'http://gooogle.com/login', label: 'gooogle (typo)', safe: false },
        { url: 'http://paypal-update.ml/confirm', label: 'paypal-fake.ml', safe: false },
        { url: 'http://192.168.1.1/bank-login', label: 'IP-address login', safe: false },
    ]

    const pipeline = [
        { n: '01', icon: '📐', title: 'FEATURE EXTRACTION', desc: '28 URL метрика: бренд ұқсастығы, typosquat, энтропия, TLD, IP', color: 'from-blue-500' },
        { n: '02', icon: '🧠', title: 'NEURAL NETWORK', desc: 'ResidualBlock(3) + FeatureAttention + BatchNorm', color: 'from-indigo-500' },
        { n: '03', icon: '🔍', title: 'HEURISTIC ANALYSIS', desc: 'Бренд алдау, typosquatting, IDN гомограф, URL үлгілер', color: 'from-purple-500' },
        { n: '04', icon: '⚡', title: 'ENSEMBLE SCORING', desc: 'ML + Эвристика → біріккен қауіп бағасы', color: 'from-cyan-500' },
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
                        URL → CYBERQALQAN AI (28 FEATURES) → ENSEMBLE SCORING
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
                <div className="glass glow-border rounded-2xl p-8 mb-6 fade-up">
                    <div className="flex flex-col items-center justify-center">
                        <div className="relative w-16 h-16 mb-6">
                            <div className="absolute inset-0 border-4 border-indigo-500/20 rounded-full"></div>
                            <div className="absolute inset-0 border-4 border-indigo-500 rounded-full border-t-transparent animate-spin"></div>
                            <div className="absolute inset-0 flex items-center justify-center text-2xl">
                                {scanStep >= 0 && scanStepsUI[Math.min(scanStep, scanStepsUI.length - 1)].icon}
                            </div>
                        </div>

                        <h3 className="text-xl font-bold text-white mb-6 tracking-wide">CAЙТ СКАНЕРЛЕНУДЕ...</h3>

                        <div className="w-full max-w-sm space-y-4">
                            {scanStepsUI.map((step, index) => (
                                <div key={index} className={`flex items-center gap-4 transition-all duration-500 
                                    ${index === scanStep ? 'opacity-100 translate-x-0' :
                                        index < scanStep ? 'opacity-50 translate-x-0' : 'opacity-20 translate-x-4'}`}>
                                    <div className={`w-8 h-8 shrink-0 rounded-full flex items-center justify-center text-sm
                                        ${index < scanStep ? 'bg-emerald-500/20 text-emerald-400' :
                                            index === scanStep ? 'bg-indigo-500/20 text-indigo-400 animate-pulse shadow-[0_0_15px_rgba(99,102,241,0.5)]' :
                                                'bg-slate-800 text-slate-500'}`}>
                                        {index < scanStep ? '✓' : index + 1}
                                    </div>
                                    <span className={`text-sm font-medium
                                        ${index === scanStep ? 'text-indigo-300' :
                                            index < scanStep ? 'text-emerald-400/70' : 'text-slate-500'}`}>
                                        {step.text}
                                    </span>
                                </div>
                            ))}
                        </div>
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
