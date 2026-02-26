import { useState, useEffect, useRef } from 'react'

export function ScoreGauge({ score, verdict }) {
    const [animated, setAnimated] = useState(0)
    const pct = Math.round(score * 100)
    const circ = 2 * Math.PI * 52

    useEffect(() => {
        let frame
        const start = performance.now()
        const animate = (now) => {
            const progress = Math.min((now - start) / 1200, 1)
            const eased = 1 - Math.pow(1 - progress, 4)
            setAnimated(Math.round(pct * eased))
            if (progress < 1) frame = requestAnimationFrame(animate)
        }
        frame = requestAnimationFrame(animate)
        return () => cancelAnimationFrame(frame)
    }, [pct])

    const offset = circ - (animated / 100) * circ
    const color = score < 0.3 ? '#34d399' : score < 0.7 ? '#fbbf24' : '#fb7185'
    const glow = score < 0.3 ? 'rgba(52,211,153,0.3)' : score < 0.7 ? 'rgba(251,191,36,0.3)' : 'rgba(251,113,133,0.4)'

    return (
        <div className="flex flex-col items-center gap-4">
            <div className="relative w-44 h-44 flex items-center justify-center">
                {/* Outer glow ring */}
                <div className="absolute inset-0 rounded-full" style={{ boxShadow: `0 0 30px ${glow}, 0 0 60px ${glow}`, opacity: 0.5 }} />

                {/* Background dots */}
                <div className="absolute inset-2 rounded-full dot-pattern opacity-30" />

                <svg width="176" height="176" className="absolute">
                    {/* Track */}
                    <circle cx="88" cy="88" r="52" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="8" />
                    {/* Animated arc */}
                    <circle cx="88" cy="88" r="52" fill="none" stroke={color} strokeWidth="8"
                        strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={offset}
                        transform="rotate(-90 88 88)"
                        style={{ transition: 'stroke-dashoffset 0.05s linear', filter: `drop-shadow(0 0 8px ${glow})` }} />
                    {/* Endpoint dot */}
                    <circle cx="88" cy="88" r="52" fill="none" stroke={color} strokeWidth="3"
                        strokeDasharray="2 500" strokeDashoffset={offset}
                        transform="rotate(-90 88 88)" opacity="0.5" />
                </svg>

                <div className="text-center z-10">
                    <div className="text-4xl font-black tracking-tighter" style={{ color, textShadow: `0 0 20px ${glow}` }}>
                        {animated}<span className="text-lg">%</span>
                    </div>
                    <div className="text-[0.6rem] text-slate-500 font-mono tracking-widest uppercase mt-1">қауіп деңгейі</div>
                </div>
            </div>

            <span className={`inline-flex items-center gap-2 px-5 py-2 rounded-full text-sm font-bold tracking-wide
                ${verdict === 'safe' ? 'badge-safe' : verdict === 'suspicious' ? 'badge-warn' : 'badge-danger'}`}>
                {verdict === 'safe' && '◈ ҚАУІПСІЗ'}
                {verdict === 'suspicious' && '◈ КҮДІКТІ'}
                {verdict === 'phishing' && '◈ ФИШИНГ АНЫҚТАЛДЫ'}
            </span>
        </div>
    )
}

export function ResultCard({ result }) {
    if (!result) return null

    return (
        <div className="glass rounded-2xl p-8 mt-6 fade-up glow-border">
            <div className="flex flex-wrap gap-10 items-start">
                <ScoreGauge score={result.score} verdict={result.verdict} />

                <div className="flex-1 min-w-[260px]">
                    <div className="flex items-center gap-3 mb-6 pb-4 border-b border-white/5">
                        <div className="w-1 h-6 rounded-full bg-gradient-to-b from-indigo-400 to-purple-400" />
                        <h3 className="text-lg font-bold text-slate-200 tracking-tight">Талдау нәтижесі</h3>
                        <span className="ml-auto font-mono text-[0.6rem] text-slate-600">
                            {result.model_details?.analysis_method || result.model_details?.model_type || 'Neural Network'}
                        </span>
                    </div>

                    <div className="grid grid-cols-3 gap-3 mb-5">
                        <div className="glass rounded-xl p-4 border-l-2 border-indigo-500/50 group hover:border-indigo-400 transition-colors">
                            <div className="text-[0.65rem] text-slate-500 font-mono tracking-wider mb-1">НЕЙРОЖЕЛІ</div>
                            <div className="text-2xl font-black text-indigo-400 neon-text">
                                {((result.model_details?.ml_score ?? result.model_details?.neural_network_score ?? 0) * 100).toFixed(1)}
                                <span className="text-sm text-indigo-500/60">%</span>
                            </div>
                        </div>
                        <div className="glass rounded-xl p-4 border-l-2 border-amber-500/50 group hover:border-amber-400 transition-colors">
                            <div className="text-[0.65rem] text-slate-500 font-mono tracking-wider mb-1">ЭВРИСТИКА</div>
                            <div className="text-2xl font-black text-amber-400 neon-text">
                                {((result.model_details?.heuristic_score ?? 0) * 100).toFixed(1)}
                                <span className="text-sm text-amber-500/60">%</span>
                            </div>
                            {result.model_details?.heuristic_issues_count > 0 && (
                                <div className="text-[0.55rem] text-amber-500/60 font-mono mt-1">
                                    {result.model_details.heuristic_issues_count} мәселе табылды
                                </div>
                            )}
                        </div>
                        <div className="glass rounded-xl p-4 border-l-2 border-purple-500/50 group hover:border-purple-400 transition-colors">
                            <div className="text-[0.65rem] text-slate-500 font-mono tracking-wider mb-1">СЕНІМДІЛІК</div>
                            <div className="text-2xl font-black text-purple-400 neon-text">
                                {(result.model_details?.confidence * 100 || 0).toFixed(1)}
                                <span className="text-sm text-purple-500/60">%</span>
                            </div>
                        </div>
                    </div>

                    {result.model_details?.top_features && Object.keys(result.model_details.top_features).length > 0 && (
                        <div className="mb-4">
                            <h4 className="text-[0.65rem] font-mono text-slate-500 tracking-wider mb-2">МАҢЫЗДЫ БЕЛГІЛЕР</h4>
                            <div className="flex flex-wrap gap-1.5">
                                {Object.entries(result.model_details.top_features).map(([name, val]) => (
                                    <span key={name} className="font-mono text-[0.65rem] px-2.5 py-1 rounded-lg
                                        bg-indigo-500/10 text-indigo-300 border border-indigo-500/15 hover:border-indigo-500/30 transition-colors">
                                        {name}: {(val * 100).toFixed(1)}%
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {result.detailed_analysis?.length > 0 && (
                <div className="mt-6 p-5 rounded-xl bg-orange-500/5 border-orange-500/15 border">
                    <h4 className="font-semibold text-slate-300 mb-3 flex items-center gap-2">
                        <span className="text-base">⚠️</span> Қауіптілік себептері / Причины опасности
                    </h4>
                    <ul className="space-y-4">
                        {result.detailed_analysis.map((item, i) => (
                            <li key={i} className="text-sm text-slate-400 flex flex-col gap-1">
                                <div className="flex gap-3">
                                    <span className="text-orange-500/50 font-mono text-xs mt-0.5">[{String(i + 1).padStart(2, '0')}]</span>
                                    <span className="text-slate-300">{item?.kz}</span>
                                </div>
                                <div className="pl-9 text-xs text-slate-500 font-light max-w-[90%]">
                                    {item?.ru}
                                </div>
                            </li>
                        ))}
                    </ul>
                </div>
            )}

            {result.recommendations?.length > 0 && (
                <div className={`mt-6 p-5 rounded-xl border
                    ${result.verdict === 'phishing' ? 'bg-rose-500/5 border-rose-500/15'
                        : result.verdict === 'suspicious' ? 'bg-amber-500/5 border-amber-500/15'
                            : 'bg-emerald-500/5 border-emerald-500/15'}`}>
                    <h4 className="font-semibold text-slate-300 mb-3 flex items-center gap-2">
                        <span className="text-base">💡</span> Ұсыныстар
                    </h4>
                    <ul className="space-y-2">
                        {result.recommendations.map((rec, i) => (
                            <li key={i} className="text-sm text-slate-400 flex gap-3">
                                <span className="text-indigo-500/50 font-mono text-xs mt-0.5">[{String(i + 1).padStart(2, '0')}]</span>
                                <span>{rec.kz}</span>
                            </li>
                        ))}
                    </ul>
                </div>
            )}

            {result.features && (
                <details className="mt-5 group">
                    <summary className="cursor-pointer text-sm font-medium text-indigo-400/80 hover:text-indigo-300 py-2 transition-colors select-none font-mono text-xs tracking-wider">
                        [+] ТОЛЫҚ МЕТРИКАЛАР
                    </summary>
                    <div className="mt-3 overflow-x-auto rounded-xl border border-white/5">
                        <table className="w-full">
                            <tbody>
                                {Object.entries(result.features).map(([key, val], i) => (
                                    <tr key={key} className={`border-b border-white/[0.03] ${i % 2 === 0 ? 'bg-white/[0.01]' : ''} hover:bg-indigo-500/5 transition-colors`}>
                                        <td className="font-mono text-[0.7rem] text-slate-500 px-4 py-2.5">{key}</td>
                                        <td className="font-mono text-[0.7rem] text-slate-300 px-4 py-2.5 text-right font-medium">
                                            {typeof val === 'number' ? (val % 1 === 0 ? val : val.toFixed(4)) : String(val)}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </details>
            )}
        </div>
    )
}
