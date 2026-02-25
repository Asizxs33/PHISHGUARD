import { useState, useEffect } from 'react'
import { getHistory, API_BASE_URL } from '../api'

export default function History() {
    const [history, setHistory] = useState([])
    const [loading, setLoading] = useState(true)
    const [filter, setFilter] = useState('all')

    useEffect(() => { loadHistory() }, [filter])

    const loadHistory = async () => {
        setLoading(true)
        try {
            const type = filter === 'all' ? null : filter
            const data = await getHistory(100, type)
            setHistory(data.history || [])
        } catch { setHistory([]) }
        setLoading(false)
    }

    const vc = {
        safe: { color: 'text-emerald-400', border: 'border-emerald-500/30', badge: 'badge-safe', label: 'SAFE', glow: 'shadow-emerald-500/5' },
        suspicious: { color: 'text-amber-400', border: 'border-amber-500/30', badge: 'badge-warn', label: 'WARN', glow: 'shadow-amber-500/5' },
        phishing: { color: 'text-rose-400', border: 'border-rose-500/30', badge: 'badge-danger', label: 'THREAT', glow: 'shadow-rose-500/5' },
    }

    return (
        <div>
            {/* Header */}
            <div className="relative glass rounded-3xl p-8 mb-6 overflow-hidden fade-up">
                <div className="absolute inset-0 dot-pattern opacity-20" />
                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-1 h-8 rounded-full bg-gradient-to-b from-emerald-400 to-cyan-400" />
                        <h2 className="text-3xl font-black tracking-tight gradient-text">СКАНЕРЛЕУ ТАРИХЫ</h2>
                    </div>
                    <p className="text-slate-500 text-sm ml-4 font-mono">
                        БАРЛЫҚ ТАЛДАУ НӘТИЖЕЛЕРІ — <span className="text-indigo-400">{history.length}</span> ЖАЗБА
                    </p>
                </div>
            </div>

            {/* Filters */}
            <div className="flex gap-2 mb-6 flex-wrap fade-up stagger-1">
                {[
                    { key: 'all', label: '◈ БАРЛЫҒЫ' },
                    { key: 'url', label: '⬡ URL' },
                    { key: 'email', label: '✉ EMAIL' },
                    { key: 'qr', label: '⬢ QR' },
                ].map(f => (
                    <button key={f.key} onClick={() => setFilter(f.key)}
                        className={`px-4 py-2.5 rounded-xl text-xs font-mono border transition-all cursor-pointer
                            ${filter === f.key
                                ? 'bg-indigo-500/10 border-indigo-500/30 text-indigo-400 shadow-sm shadow-indigo-500/10'
                                : 'bg-transparent border-white/5 text-slate-600 hover:text-slate-400 hover:border-white/10'}`}>
                        {f.label}
                    </button>
                ))}

                <a
                    href={`${API_BASE_URL.replace('/api', '')}/api/dangerous-domains/download`}
                    download="dangerous_domains.txt"
                    className="ml-auto flex items-center gap-2 px-4 py-2 text-xs font-bold border rounded-xl
                             bg-rose-500/10 border-rose-500/30 text-rose-400 hover:bg-rose-500/20 hover:border-rose-500/50 transition-all cursor-pointer shadow-[0_0_15px_rgba(244,113,133,0.15)]"
                >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                    </svg>
                    ОПАСНЫЕ ДОМЕНЫ
                </a>
            </div>

            {loading && (
                <div className="text-center py-16 fade-up">
                    <div className="shimmer mb-4 mx-auto max-w-[250px]"></div>
                    <div className="text-slate-600 text-sm font-mono cursor-blink">loading_history</div>
                </div>
            )}

            {!loading && history.length === 0 && (
                <div className="glass rounded-2xl p-16 text-center fade-up">
                    <div className="text-5xl mb-4" style={{ animation: 'float 3s ease-in-out infinite' }}>◎</div>
                    <div className="text-lg font-bold text-slate-400 mb-2">ЖАЗБАЛАР ТАБЫЛМАДЫ</div>
                    <div className="text-sm text-slate-600 font-mono">URL, Email немесе QR сканерлеуді іске қосыңыз</div>
                </div>
            )}

            {!loading && history.length > 0 && (
                <div className="space-y-2 fade-up stagger-2">
                    {history.map((item, idx) => {
                        const v = vc[item.verdict] || vc.phishing
                        return (
                            <div key={item.id || idx}
                                className={`glass glass-hover rounded-xl px-5 py-4 border-l-[3px] ${v.border}
                                    flex justify-between items-center flex-wrap gap-3 ${v.glow}`}>
                                <div className="flex-1 min-w-[200px]">
                                    <div className="flex items-center gap-2.5 mb-1.5">
                                        <span className="text-sm">{item.type === 'url' ? '⬡' : item.type === 'email' ? '✉' : '⬢'}</span>
                                        <span className="font-mono text-[0.55rem] text-slate-600 uppercase tracking-widest">{item.type}</span>
                                        {item.timestamp && (
                                            <span className="font-mono text-[0.6rem] text-slate-700 ml-auto">
                                                {new Date(item.timestamp).toLocaleString('kk-KZ')}
                                            </span>
                                        )}
                                    </div>
                                    <div className="font-mono text-xs text-slate-500 break-all">{item.input}</div>
                                </div>
                                <div className="flex items-center gap-3">
                                    <span className={`font-mono text-lg font-black ${v.color}`}
                                        style={{ textShadow: item.verdict === 'phishing' ? '0 0 10px rgba(251,113,133,0.3)' : 'none' }}>
                                        {(item.score * 100).toFixed(0)}%
                                    </span>
                                    <span className={`font-mono text-[0.6rem] px-2.5 py-1 rounded-md font-bold ${v.badge}`}>
                                        {v.label}
                                    </span>
                                </div>
                            </div>
                        )
                    })}
                </div>
            )}
        </div>
    )
}
