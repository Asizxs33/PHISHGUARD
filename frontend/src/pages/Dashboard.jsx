import { useState, useEffect, useRef } from 'react'
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

function Particles() {
    return (
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
            {[...Array(6)].map((_, i) => (
                <div key={i} className="absolute rounded-full bg-indigo-500/20"
                    style={{
                        width: 4 + Math.random() * 6,
                        height: 4 + Math.random() * 6,
                        left: `${10 + Math.random() * 80}%`,
                        top: `${10 + Math.random() * 80}%`,
                        animation: `float ${3 + Math.random() * 4}s ease-in-out infinite`,
                        animationDelay: `${Math.random() * 3}s`,
                    }} />
            ))}
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
        { name: 'URL', value: stats.by_type?.url || 0, fill: '#818cf8' },
        { name: 'Email', value: stats.by_type?.email || 0, fill: '#a855f7' },
        { name: 'QR', value: stats.by_type?.qr || 0, fill: '#22d3ee' },
    ] : []

    return (
        <div>
            {/* Hero Header */}
            <div className="relative glass rounded-3xl p-8 mb-6 overflow-hidden fade-up">
                <Particles />
                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-1 h-8 rounded-full bg-gradient-to-b from-indigo-400 to-purple-400" />
                        <h2 className="text-3xl font-black tracking-tight gradient-text">БАСҚАРУ ОРТАЛЫҒЫ</h2>
                    </div>
                    <p className="text-slate-500 text-sm ml-4 font-mono">
                        <span className="text-emerald-400/60">●</span> Қауіпті мониторинг жүйесі белсенді
                        <span className="cursor-blink ml-1"></span>
                    </p>
                </div>
            </div>

            {/* Action Cards — 3D hover */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                {[
                    { to: '/url', icon: '⬡', label: 'URL ТЕКСЕРУ', desc: 'Сілтемелерді нейрожелімен талдау', grad: 'from-blue-600 to-indigo-700', glow: 'shadow-blue-500/20', tag: '28 FEATURES' },
                    { to: '/email', icon: '✉', label: 'EMAIL ТАЛДАУ', desc: 'Хат мазмұнын AI-мен сканерлеу', grad: 'from-purple-600 to-fuchsia-700', glow: 'shadow-purple-500/20', tag: '22 VECTORS' },
                    { to: '/qr', icon: '⬢', label: 'QR КОД', desc: 'QR кодты декодтап тексеру', grad: 'from-cyan-600 to-blue-700', glow: 'shadow-cyan-500/20', tag: 'QUISHING' },
                    { to: '/chat', icon: '💬', label: 'КИБЕР КЕҢЕСШІ', desc: 'AI-дан қауіпсіздік бойынша кеңес алу', grad: 'from-emerald-600 to-teal-700', glow: 'shadow-emerald-500/20', tag: 'AI ADVISOR' },
                ].map((a, i) => (
                    <Link key={a.to} to={a.to} className={`group block fade-up stagger-${i + 1}`}>
                        <div className={`relative rounded-2xl bg-gradient-to-br ${a.grad} p-6 overflow-hidden
                            shadow-xl ${a.glow} hover:shadow-2xl transition-all duration-500
                            hover:-translate-y-2 hover:scale-[1.02] cursor-pointer`}
                            style={{ transformStyle: 'preserve-3d' }}>
                            {/* Decorative circles */}
                            <div className="absolute -top-6 -right-6 w-24 h-24 bg-white/5 rounded-full group-hover:scale-[2] transition-transform duration-700" />
                            <div className="absolute -bottom-4 -left-4 w-16 h-16 bg-white/5 rounded-full" />

                            <div className="relative z-10">
                                <div className="flex items-center justify-between mb-4">
                                    <span className="text-3xl text-white/90" style={{ animation: `float ${3 + i * 0.5}s ease-in-out infinite` }}>{a.icon}</span>
                                    <span className="font-mono text-[0.55rem] text-white/30 tracking-widest">{a.tag}</span>
                                </div>
                                <h3 className="text-white font-bold text-base tracking-wide mb-1">{a.label}</h3>
                                <p className="text-white/60 text-sm">{a.desc}</p>
                                <div className="mt-4 flex items-center gap-2 text-white/40 text-xs group-hover:text-white/70 transition-colors">
                                    <span>Бастау</span>
                                    <span className="group-hover:translate-x-1 transition-transform">→</span>
                                </div>
                            </div>
                        </div>
                    </Link>
                ))}
            </div>

            {/* Stats with animated counters */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
                {[
                    { label: 'БАРЛЫҚ СКАНЕРЛЕУ', value: stats?.total_analyses || 0, color: 'text-indigo-400', border: 'border-indigo-500/20', icon: '◈' },
                    { label: 'ҚАУІПСІЗ', value: stats?.safe || 0, color: 'text-emerald-400', border: 'border-emerald-500/20', icon: '◇' },
                    { label: 'КҮДІКТІ', value: stats?.suspicious || 0, color: 'text-amber-400', border: 'border-amber-500/20', icon: '△' },
                    { label: 'ФИШИНГ', value: stats?.phishing || 0, color: 'text-rose-400', border: 'border-rose-500/20', icon: '◆' },
                ].map((s, i) => (
                    <div key={s.label} className={`glass glass-hover rounded-2xl p-5 ${s.border} border fade-up stagger-${i + 1}`}>
                        <div className="flex items-center gap-2 mb-2">
                            <span className={`text-xs ${s.color}`}>{s.icon}</span>
                            <span className="text-[0.6rem] text-slate-500 font-mono tracking-wider">{s.label}</span>
                        </div>
                        <div className={`text-3xl font-black ${s.color} tracking-tighter neon-text`}>
                            <AnimatedCounter value={s.value} />
                        </div>
                    </div>
                ))}
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <div className="glass glass-hover rounded-2xl p-6 fade-up stagger-1">
                    <div className="flex items-center gap-2 mb-4">
                        <div className="w-1 h-4 rounded-full bg-gradient-to-b from-indigo-400 to-purple-400" />
                        <h3 className="text-sm font-bold text-slate-300 tracking-tight">Қауіп таралуы</h3>
                    </div>
                    {pieData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={220}>
                            <PieChart>
                                <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={80}
                                    dataKey="value" stroke="none" animationDuration={1000}
                                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                                    <Cell fill={COLORS.safe} />
                                    <Cell fill={COLORS.suspicious} />
                                    <Cell fill={COLORS.phishing} />
                                </Pie>
                                <Tooltip contentStyle={{ background: 'rgba(15,15,25,0.95)', backdropFilter: 'blur(20px)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: 12, fontFamily: 'Space Grotesk', fontSize: 13, color: '#e2e8f0' }} />
                            </PieChart>
                        </ResponsiveContainer>
                    ) : (
                        <div className="h-[220px] flex flex-col items-center justify-center text-slate-600 text-sm">
                            <span className="text-2xl mb-2" style={{ animation: 'float 3s ease-in-out infinite' }}>◎</span>
                            Деректер жоқ — сканерлеу жасаңыз
                        </div>
                    )}
                </div>
                <div className="glass glass-hover rounded-2xl p-6 fade-up stagger-2">
                    <div className="flex items-center gap-2 mb-4">
                        <div className="w-1 h-4 rounded-full bg-gradient-to-b from-cyan-400 to-blue-400" />
                        <h3 className="text-sm font-bold text-slate-300 tracking-tight">Сканерлеу түрлері</h3>
                    </div>
                    {stats?.total_analyses > 0 ? (
                        <ResponsiveContainer width="100%" height={220}>
                            <BarChart data={barData}>
                                <XAxis dataKey="name" stroke="#475569" fontSize={12} fontFamily="Space Grotesk" />
                                <YAxis stroke="#475569" fontSize={12} fontFamily="Space Grotesk" />
                                <Tooltip contentStyle={{ background: 'rgba(15,15,25,0.95)', backdropFilter: 'blur(20px)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: 12, fontFamily: 'Space Grotesk', fontSize: 13, color: '#e2e8f0' }} />
                                <Bar dataKey="value" radius={[8, 8, 0, 0]} animationDuration={1000}>
                                    {barData.map((e, i) => <Cell key={i} fill={e.fill} />)}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    ) : (
                        <div className="h-[220px] flex flex-col items-center justify-center text-slate-600 text-sm">
                            <span className="text-2xl mb-2" style={{ animation: 'float 3s ease-in-out infinite', animationDelay: '0.5s' }}>📊</span>
                            Деректер күтілуде...
                        </div>
                    )}
                </div>
            </div>

            {/* Recent History */}
            {history.length > 0 && (
                <div className="glass rounded-2xl p-6 fade-up">
                    <div className="flex items-center gap-2 mb-4">
                        <div className="w-1 h-4 rounded-full bg-gradient-to-b from-emerald-400 to-cyan-400" />
                        <h3 className="text-sm font-bold text-slate-300 tracking-tight">Соңғы сканерлеулер</h3>
                        <span className="ml-auto font-mono text-[0.55rem] text-slate-600">{history.length} ЖАЗБА</span>
                    </div>
                    <div className="space-y-1">
                        {history.slice(0, 5).map((item, i) => (
                            <div key={item.id} className="flex items-center gap-4 px-4 py-3 rounded-xl hover:bg-white/[0.02] transition-colors group">
                                <span className="text-base">{item.type === 'url' ? '⬡' : item.type === 'email' ? '✉' : '⬢'}</span>
                                <span className="font-mono text-[0.6rem] text-slate-600 uppercase w-10">{item.type}</span>
                                <span className="flex-1 font-mono text-xs text-slate-500 truncate group-hover:text-slate-300 transition-colors">{item.input}</span>
                                <span className="font-mono text-sm font-bold" style={{
                                    color: item.verdict === 'safe' ? '#34d399' : item.verdict === 'suspicious' ? '#fbbf24' : '#fb7185'
                                }}>{(item.score * 100).toFixed(0)}%</span>
                                <span className={`font-mono text-[0.6rem] px-2 py-0.5 rounded-md
                                    ${item.verdict === 'safe' ? 'badge-safe' : item.verdict === 'suspicious' ? 'badge-warn' : 'badge-danger'}`}>
                                    {item.verdict === 'safe' ? 'SAFE' : item.verdict === 'suspicious' ? 'WARN' : 'THREAT'}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    )
}
