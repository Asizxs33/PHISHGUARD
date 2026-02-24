import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { getStats, getHistory } from '../api'

const COLORS = { safe: '#34d399', suspicious: '#fbbf24', phishing: '#fb7185' }

function AnimatedCounter({ value, duration = 1200 }) {
    const [count, setCount] = useState(0)
    useEffect(() => {
        let frame; const start = performance.now()
        const animate = (now) => {
            const p = Math.min((now - start) / duration, 1)
            setCount(Math.round(value * (1 - Math.pow(1 - p, 3))))
            if (p < 1) frame = requestAnimationFrame(animate)
        }
        frame = requestAnimationFrame(animate)
        return () => cancelAnimationFrame(frame)
    }, [value, duration])
    return count
}

function CyberGrid() {
    return (
        <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-20">
            <div className="absolute inset-0" style={{
                backgroundImage: 'linear-gradient(rgba(99, 102, 241, 0.4) 1px, transparent 1px), linear-gradient(90deg, rgba(99, 102, 241, 0.4) 1px, transparent 1px)',
                backgroundSize: '30px 30px',
                transform: 'perspective(500px) rotateX(60deg) translateY(-100px) translateZ(-200px)',
                animation: 'gridMove 10s linear infinite'
            }} />
        </div>
    )
}

function RadarScan() {
    return (
        <div className="absolute -top-32 -right-32 w-96 h-96 rounded-full border border-indigo-500/10 flex items-center justify-center opacity-30 pointer-events-none mix-blend-screen">
            <div className="absolute inset-0 rounded-full border border-indigo-500/20" style={{ animation: 'ping 4s cubic-bezier(0, 0, 0.2, 1) infinite' }} />
            <div className="absolute inset-12 rounded-full border border-purple-500/20" style={{ animation: 'ping 4s cubic-bezier(0, 0, 0.2, 1) infinite 1s' }} />
            <div className="absolute inset-24 rounded-full border border-cyan-500/20" style={{ animation: 'ping 4s cubic-bezier(0, 0, 0.2, 1) infinite 2s' }} />
            <div className="w-full h-full rounded-full bg-gradient-to-tr from-indigo-500/5 to-transparent relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-400/30 to-transparent w-1/2 h-full origin-right"
                    style={{ animation: 'spin 3s linear infinite' }} />
            </div>
        </div>
    )
}

export default function Dashboard() {
    const [stats, setStats] = useState(null)
    const [history, setHistory] = useState([])

    useEffect(() => { loadData() }, [])

    const loadData = async () => {
        try {
            const [s, h] = await Promise.all([getStats(), getHistory(10)])
            setStats(s)
            setHistory(h.history || [])
        } catch { setStats({ total_analyses: 0, safe: 0, suspicious: 0, phishing: 0, by_type: { url: 0, email: 0, qr: 0 } }) }
    }

    const pieData = stats ? [
        { name: 'Қауіпсіз', value: stats.safe || 0 },
        { name: 'Күдікті', value: stats.suspicious || 0 },
        { name: 'Фишинг', value: stats.phishing || 0 },
    ].filter(d => d.value > 0) : []

    const barData = stats ? [
        { name: 'URL', value: stats.by_type?.url || 0, fill: '#818cf8', icon: '⬡' },
        { name: 'Email', value: stats.by_type?.email || 0, fill: '#a855f7', icon: '✉' },
        { name: 'QR', value: stats.by_type?.qr || 0, fill: '#22d3ee', icon: '⬢' },
    ] : []

    return (
        <div className="pb-10">
            <style>{`
                @keyframes gridMove { 0% { transform: perspective(500px) rotateX(60deg) translateY(-100px) translateZ(-200px); } 100% { transform: perspective(500px) rotateX(60deg) translateY(0px) translateZ(-200px); } }
                @keyframes spin { 100% { transform: rotate(360deg); } }
                .hex-bg { clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%); }
            `}</style>

            {/* Hero Header */}
            <div className="relative glass rounded-[2rem] p-8 mb-8 overflow-hidden fade-up border-t border-indigo-500/30 shadow-[0_0_40px_rgba(79,70,229,0.15)] group">
                <CyberGrid />
                <RadarScan />

                <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
                    <div>
                        <div className="flex items-center gap-4 mb-3">
                            <div className="relative flex items-center justify-center w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20">
                                <span className="absolute inset-0 rounded-xl bg-indigo-500/20 blur-md animate-pulse"></span>
                                <span className="text-2xl" style={{ animation: 'float 3s ease-in-out infinite' }}>🛡️</span>
                            </div>
                            <div>
                                <h2 className="text-3xl md:text-4xl font-black tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-indigo-300 via-purple-300 to-cyan-300 drop-shadow-[0_0_15px_rgba(129,140,248,0.5)]">
                                    БАСҚАРУ ОРТАЛЫҒЫ
                                </h2>
                            </div>
                        </div>
                        <div className="flex items-center gap-3 bg-black/40 backdrop-blur-md border border-white/5 rounded-full px-4 py-1.5 w-fit">
                            <span className="relative flex h-2.5 w-2.5">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500 shadow-[0_0_10px_#34d399]"></span>
                            </span>
                            <span className="text-emerald-400/80 text-xs font-mono uppercase tracking-widest font-semibold flex items-center">
                                Жүйе белсенді <span className="cursor-blink ml-1"></span>
                            </span>
                        </div>
                    </div>

                    <div className="flex gap-4">
                        <div className="text-right flex flex-col items-end justify-center p-4 rounded-xl bg-white/5 border border-white/10 backdrop-blur-md">
                            <div className="text-[0.65rem] font-mono text-indigo-300/70 tracking-widest mb-1">ЖЕЛІЛІК КҮЙ</div>
                            <div className="font-mono text-sm text-white flex items-center gap-2">
                                SECURE_CONNECTION <span className="text-indigo-400 animate-pulse">●</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Action Cards — 3D hover */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
                {[
                    { to: '/url', icon: '⬡', label: 'URL ТЕКСЕРУ', desc: 'Сілтемелерді нейрожелімен талдау', grad: 'from-blue-900/40 to-indigo-900/40', border: 'border-blue-500/30', glow: 'shadow-[0_0_30px_rgba(59,130,246,0.15)]', hoverGlow: 'hover:shadow-[0_0_40px_rgba(59,130,246,0.3)] hover:border-blue-400/50', tag: 'URL_SCAN' },
                    { to: '/email', icon: '✉', label: 'EMAIL ТАЛДАУ', desc: 'Хат мазмұнын AI-мен сканерлеу', grad: 'from-purple-900/40 to-fuchsia-900/40', border: 'border-purple-500/30', glow: 'shadow-[0_0_30px_rgba(168,85,247,0.15)]', hoverGlow: 'hover:shadow-[0_0_40px_rgba(168,85,247,0.3)] hover:border-purple-400/50', tag: 'MAIL_SCAN' },
                    { to: '/qr', icon: '⬢', label: 'QR КОД', desc: 'QR кодты декодтап тексеру', grad: 'from-cyan-900/40 to-teal-900/40', border: 'border-cyan-500/30', glow: 'shadow-[0_0_30px_rgba(6,182,212,0.15)]', hoverGlow: 'hover:shadow-[0_0_40px_rgba(6,182,212,0.3)] hover:border-cyan-400/50', tag: 'QR_DECODE' },
                    { to: '/chat', icon: '💬', label: 'КИБЕР КЕҢЕСШІ', desc: 'AI-дан қауіпсіздік бойынша кеңес алу', grad: 'from-emerald-900/40 to-green-900/40', border: 'border-emerald-500/30', glow: 'shadow-[0_0_30px_rgba(16,185,129,0.15)]', hoverGlow: 'hover:shadow-[0_0_40px_rgba(16,185,129,0.3)] hover:border-emerald-400/50', tag: 'AI_AGENT' },
                ].map((a, i) => (
                    <Link key={a.to} to={a.to} className={`group block fade-up stagger-${i + 1}`}>
                        <div className={`relative rounded-2xl bg-gradient-to-br ${a.grad} p-6 h-full overflow-hidden
                            backdrop-blur-xl border ${a.border} ${a.glow} ${a.hoverGlow} transition-all duration-500
                            hover:-translate-y-2 hover:scale-[1.02] cursor-pointer`}
                            style={{ transformStyle: 'preserve-3d' }}>

                            {/* Animated background highlights */}
                            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-1000 ease-in-out" />

                            <div className="absolute -top-10 -right-10 w-32 h-32 bg-white/5 rounded-full blur-2xl group-hover:bg-white/10 transition-colors duration-700" />

                            <div className="relative z-10 flex flex-col h-full">
                                <div className="flex items-start justify-between mb-4">
                                    <div className="w-12 h-12 flex items-center justify-center hex-bg bg-white/10 border border-white/20 backdrop-blur-sm group-hover:scale-110 transition-transform duration-500 shadow-inner">
                                        <span className="text-2xl text-white drop-shadow-[0_0_8px_rgba(255,255,255,0.8)]" style={{ animation: `float ${3 + i * 0.5}s ease-in-out infinite` }}>{a.icon}</span>
                                    </div>
                                    <span className="font-mono text-[0.55rem] px-2 py-1 rounded bg-white/5 border border-white/10 text-white/50 tracking-widest group-hover:text-white/80 group-hover:border-white/30 transition-colors uppercase">{a.tag}</span>
                                </div>
                                <h3 className="text-white font-bold text-lg tracking-wide mb-2 group-hover:text-transparent group-hover:bg-clip-text group-hover:bg-gradient-to-r group-hover:from-white group-hover:to-white/60 transition-all">{a.label}</h3>
                                <p className="text-slate-400 text-sm mb-6 flex-grow leading-relaxed">{a.desc}</p>

                                <div className="mt-auto flex items-center justify-between w-full border-t border-white/10 pt-4">
                                    <span className="text-xs font-mono text-white/40 uppercase tracking-widest group-hover:text-white/80 transition-colors">Init Module</span>
                                    <div className="w-6 h-6 rounded-full bg-white/5 flex items-center justify-center group-hover:bg-white/20 transition-colors group-hover:shadow-[0_0_10px_rgba(255,255,255,0.3)]">
                                        <span className="text-white/60 text-xs group-hover:translate-x-0.5 transition-transform group-hover:text-white">→</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </Link>
                ))}
            </div>

            {/* Stats with dynamic cyber borders */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                {[
                    { label: 'БАРЛЫҚ ЖАЗБА', value: stats?.total_analyses || 0, color: 'text-indigo-300', glow: 'shadow-[0_0_15px_rgba(99,102,241,0.2)]', border: 'border-indigo-500/30', bg: 'bg-indigo-500/5', startHex: '#818cf8', icon: '◈' },
                    { label: 'ТАЗА КӨЗДЕР', value: stats?.safe || 0, color: 'text-emerald-300', glow: 'shadow-[0_0_15px_rgba(52,211,153,0.2)]', border: 'border-emerald-500/30', bg: 'bg-emerald-500/5', startHex: '#34d399', icon: '◇' },
                    { label: 'КҮДІКТІ', value: stats?.suspicious || 0, color: 'text-amber-300', glow: 'shadow-[0_0_15px_rgba(251,191,36,0.2)]', border: 'border-amber-500/30', bg: 'bg-amber-500/5', startHex: '#fbbf24', icon: '△' },
                    { label: 'БҰҒАТТАЛҒАН', value: stats?.phishing || 0, color: 'text-rose-300', glow: 'shadow-[0_0_15px_rgba(244,113,133,0.2)]', border: 'border-rose-500/30', bg: 'bg-rose-500/5', startHex: '#fb7185', icon: '◆' },
                ].map((s, i) => (
                    <div key={s.label} className={`relative glass rounded-2xl p-5 border ${s.border} ${s.bg} overflow-hidden fade-up stagger-${i + 1} group hover:scale-[1.03] transition-transform duration-300`}>
                        {/* Shimmer top border */}
                        <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-white/40 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />

                        <div className="flex items-center justify-between mb-3 relative z-10">
                            <div className="flex items-center gap-2">
                                <span className={`text-sm ${s.color} drop-shadow-[0_0_5px_${s.startHex}]`}>{s.icon}</span>
                                <span className="text-[0.65rem] text-slate-400 font-mono tracking-widest font-semibold">{s.label}</span>
                            </div>
                        </div>
                        <div className={`text-4xl font-black ${s.color} tracking-tighter ${s.glow} relative z-10 mt-1`} style={{ textShadow: `0 0 20px ${s.startHex}40` }}>
                            <AnimatedCounter value={s.value} />
                        </div>
                        {/* Decorative graph in background */}
                        <div className="absolute -bottom-4 -right-4 w-24 h-24 opacity-10">
                            <svg viewBox="0 0 100 100" className="w-full h-full text-white" fill="currentColor">
                                <path d="M0,100 L0,50 Q25,30 50,60 T100,20 L100,100 Z" />
                            </svg>
                        </div>
                    </div>
                ))}
            </div>

            {/* Charts & Graphs */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-8 text-white">
                <div className="glass rounded-3xl p-7 fade-up stagger-1 border border-white/5 relative overflow-hidden group">
                    <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 to-transparent pointer-events-none" />
                    <div className="flex items-center justify-between mb-6 relative z-10">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/40 flex items-center justify-center">
                                <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse"></span>
                            </div>
                            <div>
                                <h3 className="text-base font-bold text-slate-200 tracking-wide uppercase">Қауіп Таралу Радары</h3>
                                <p className="text-[0.65rem] font-mono text-slate-500 mt-0.5">THREAT_DISTRIBUTION_MAP</p>
                            </div>
                        </div>
                        <div className="text-xs font-mono text-indigo-300 bg-indigo-500/10 px-3 py-1 rounded-full border border-indigo-500/20">LIVE</div>
                    </div>
                    {pieData.length > 0 ? (
                        <div className="relative h-[260px]">
                            {/* Inner target circle */}
                            <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-0">
                                <div className="w-24 h-24 rounded-full border border-white/5 flex items-center justify-center">
                                    <div className="w-16 h-16 rounded-full border border-white/10 flex items-center justify-center">
                                        <div className="w-8 h-8 rounded-full bg-indigo-500/10" />
                                    </div>
                                </div>
                            </div>
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={70} outerRadius={110}
                                        dataKey="value" stroke="rgba(255,255,255,0.05)" strokeWidth={2} animationDuration={1500}
                                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                                        labelLine={{ stroke: 'rgba(255,255,255,0.2)', strokeWidth: 1 }}>
                                        <Cell fill={COLORS.safe} className="drop-shadow-[0_0_10px_rgba(52,211,153,0.5)]" style={{ filter: 'drop-shadow(0 0 10px rgba(52,211,153,0.4))' }} />
                                        <Cell fill={COLORS.suspicious} className="drop-shadow-[0_0_10px_rgba(251,191,36,0.5)]" style={{ filter: 'drop-shadow(0 0 10px rgba(251,191,36,0.4))' }} />
                                        <Cell fill={COLORS.phishing} className="drop-shadow-[0_0_10px_rgba(244,113,133,0.5)]" style={{ filter: 'drop-shadow(0 0 10px rgba(244,113,133,0.4))' }} />
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{ background: 'rgba(10,10,15,0.95)', backdropFilter: 'blur(20px)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 16, fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: '#e2e8f0', boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }}
                                        itemStyle={{ color: '#fff' }} />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    ) : (
                        <div className="h-[260px] flex flex-col items-center justify-center text-slate-500 text-sm font-mono border border-dashed border-white/10 rounded-2xl bg-black/20">
                            <span className="text-3xl mb-3 opacity-50" style={{ animation: 'float 3s ease-in-out infinite' }}>🎯</span>
                            NO_DATA_AVAILABLE
                        </div>
                    )}
                </div>

                <div className="glass rounded-3xl p-7 fade-up stagger-2 border border-white/5 relative overflow-hidden group">
                    <div className="absolute inset-0 bg-gradient-to-bl from-cyan-500/5 to-transparent pointer-events-none" />
                    <div className="flex items-center justify-between mb-6 relative z-10">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center">
                                <span className="w-4 h-0.5 bg-cyan-400 rounded-full mb-1"></span>
                                <span className="w-2 h-0.5 bg-cyan-400 rounded-full absolute mt-2 mr-2"></span>
                                <span className="w-2 h-0.5 bg-cyan-400 rounded-full absolute mt-2 ml-2"></span>
                            </div>
                            <div>
                                <h3 className="text-base font-bold text-slate-200 tracking-wide uppercase">Векторлық Талдау</h3>
                                <p className="text-[0.65rem] font-mono text-slate-500 mt-0.5">SCAN_VECTORS_VOL</p>
                            </div>
                        </div>
                        <div className="text-xs font-mono text-cyan-300 bg-cyan-500/10 px-3 py-1 rounded-full border border-cyan-500/20 shadow-[0_0_10px_rgba(6,182,212,0.2)]">VOLUMETRICS</div>
                    </div>
                    {stats?.total_analyses > 0 ? (
                        <div className="relative h-[260px]">
                            {/* Gridlines bg */}
                            <div className="absolute inset-0 flex flex-col justify-between pointer-events-none z-0 px-8 py-2 opacity-20">
                                {[...Array(5)].map((_, i) => <div key={i} className="w-full h-px bg-slate-600" />)}
                            </div>
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={barData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} fontFamily="JetBrains Mono" tickLine={false} axisLine={false} />
                                    <YAxis stroke="#64748b" fontSize={11} fontFamily="JetBrains Mono" tickLine={false} axisLine={false} />
                                    <Tooltip
                                        cursor={{ fill: 'rgba(255,255,255,0.02)' }}
                                        contentStyle={{ background: 'rgba(10,10,15,0.95)', backdropFilter: 'blur(20px)', border: '1px solid rgba(6,182,212,0.3)', borderRadius: 16, fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: '#e2e8f0', boxShadow: '0 10px 30px rgba(0,0,0,0.5)' }} />
                                    <Bar dataKey="value" radius={[6, 6, 6, 6]} animationDuration={1500} barSize={40}>
                                        {barData.map((e, i) => (
                                            <Cell key={i} fill={e.fill} style={{ filter: `drop-shadow(0 0 12px ${e.fill}60)` }} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    ) : (
                        <div className="h-[260px] flex flex-col items-center justify-center text-slate-500 text-sm font-mono border border-dashed border-white/10 rounded-2xl bg-black/20">
                            <span className="text-3xl mb-3 opacity-50" style={{ animation: 'float 3s ease-in-out infinite', animationDelay: '0.5s' }}>📊</span>
                            SYSTEM_AWAITING_INPUT
                        </div>
                    )}
                </div>
            </div>

            {/* Recent History Table - High Tech Style */}
            {history.length > 0 && (
                <div className="glass rounded-3xl p-1 fade-up shadow-2xl relative border border-white/10">
                    <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent"></div>
                    <div className="bg-[#0b0b12]/60 rounded-[1.4rem] p-6 lg:p-8 backdrop-blur-2xl">
                        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
                            <div className="flex items-center gap-4">
                                <div className="p-2.5 bg-white/5 rounded-xl border border-white/10 shadow-inner">
                                    <svg className="w-5 h-5 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                </div>
                                <div>
                                    <h3 className="text-lg font-bold text-white tracking-wide">Операциялық Журнал</h3>
                                    <p className="font-mono text-[0.65rem] text-slate-400 mt-0.5">LATEST_SCAN_LOGS</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-2 bg-black/40 px-4 py-2 rounded-full border border-white/5">
                                <span className="relative flex h-2 w-2">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span>
                                    <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-500"></span>
                                </span>
                                <span className="font-mono text-xs text-indigo-300">{history.length} ЖАЗБА</span>
                            </div>
                        </div>

                        <div className="overflow-x-auto rounded-xl border border-white/5 bg-black/20">
                            <table className="w-full text-left border-collapse min-w-[600px]">
                                <thead>
                                    <tr className="border-b border-white/10 bg-white/[0.02]">
                                        <th className="py-4 px-5 text-[0.65rem] font-mono text-slate-400 tracking-widest uppercase">Түрі</th>
                                        <th className="py-4 px-5 text-[0.65rem] font-mono text-slate-400 tracking-widest uppercase">Нысана (Таргет)</th>
                                        <th className="py-4 px-5 text-[0.65rem] font-mono text-slate-400 tracking-widest uppercase">Қауіп Деңгейі</th>
                                        <th className="py-4 px-5 text-[0.65rem] font-mono text-slate-400 tracking-widest uppercase text-right">Статус</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/5 font-mono text-sm">
                                    {history.slice(0, 8).map((item, i) => {
                                        const typeIcon = item.type === 'url' ? '⬡' : item.type === 'email' ? '✉' : '⬢';
                                        const typeColor = item.type === 'url' ? 'text-blue-400' : item.type === 'email' ? 'text-purple-400' : 'text-cyan-400';
                                        const statusColor = item.verdict === 'safe' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                            : item.verdict === 'suspicious' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                                                : 'bg-rose-500/10 text-rose-400 border-rose-500/20 shadow-[0_0_10px_rgba(244,63,94,0.2)]';

                                        return (
                                            <tr key={item.id || i} className="group hover:bg-white/[0.03] transition-colors duration-200">
                                                <td className="py-3.5 px-5">
                                                    <div className="flex items-center gap-3">
                                                        <span className={`text-lg ${typeColor}`}>{typeIcon}</span>
                                                        <span className={`text-xs font-bold uppercase ${typeColor} bg-white/5 px-2 py-1 rounded shadow-inner`}>{item.type}</span>
                                                    </div>
                                                </td>
                                                <td className="py-3.5 px-5">
                                                    <div className="flex items-center gap-2 max-w-[250px] sm:max-w-md">
                                                        <span className="text-slate-300 truncate group-hover:text-white transition-colors">{item.input}</span>
                                                    </div>
                                                </td>
                                                <td className="py-3.5 px-5">
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-16 h-1.5 bg-black/40 rounded-full overflow-hidden">
                                                            <div className="h-full rounded-full"
                                                                style={{
                                                                    width: `${item.score * 100}%`,
                                                                    backgroundColor: item.verdict === 'safe' ? '#34d399' : item.verdict === 'suspicious' ? '#fbbf24' : '#fb7185',
                                                                    boxShadow: `0 0 8px ${item.verdict === 'safe' ? '#34d399' : item.verdict === 'suspicious' ? '#fbbf24' : '#fb7185'}`
                                                                }} />
                                                        </div>
                                                        <span className="text-xs font-bold" style={{ color: item.verdict === 'safe' ? '#34d399' : item.verdict === 'suspicious' ? '#fbbf24' : '#fb7185' }}>
                                                            {(item.score * 100).toFixed(0)}%
                                                        </span>
                                                    </div>
                                                </td>
                                                <td className="py-3.5 px-5 text-right">
                                                    <span className={`inline-flex items-center justify-center px-3 py-1 text-[0.65rem] font-bold rounded-md border uppercase tracking-widest ${statusColor}`}>
                                                        {item.verdict === 'safe' ? 'SECURE' : item.verdict === 'suspicious' ? 'WARNING' : 'THREAT'}
                                                    </span>
                                                </td>
                                            </tr>
                                        )
                                    })}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}
