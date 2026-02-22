import { useState, useEffect } from 'react'
import { NavLink, useLocation } from 'react-router-dom'

const navItems = [
    { path: '/', icon: '◈', label: 'Басқару орталығы', tag: 'DASHBOARD' },
    { path: '/url', icon: '⬡', label: 'URL тексеру', tag: 'URL SCAN' },
    { path: '/email', icon: '✉', label: 'Email талдау', tag: 'EMAIL INTEL' },
    { path: '/qr', icon: '⬢', label: 'QR код', tag: 'QR DECODE' },
    { path: '/chat', icon: '💬', label: 'Кибер кеңесші', tag: 'AI CHAT' },
    { path: '/history', icon: '◎', label: 'Тарих', tag: 'HISTORY' },
]

export default function Layout({ children }) {
    const [open, setOpen] = useState(false)
    const [time, setTime] = useState(new Date())
    const location = useLocation()

    useEffect(() => {
        const t = setInterval(() => setTime(new Date()), 1000)
        return () => clearInterval(t)
    }, [])

    return (
        <>
            <div className="scan-line" />

            {/* Mobile */}
            <button onClick={() => setOpen(!open)}
                className="mob-btn fixed top-4 left-4 z-[100] px-4 py-2 rounded-xl
                    bg-[rgba(10,10,20,0.9)] backdrop-blur-xl border border-indigo-500/20
                    text-indigo-400 text-sm font-mono cursor-pointer hover:border-indigo-500/50 transition-all">
                {open ? '[X] ЖАБУ' : '[≡] МӘЗІР'}
            </button>

            {/* Sidebar */}
            <aside className={`sidebar-wrap ${open ? 'open' : ''} w-[270px] h-screen fixed flex flex-col`}>
                {/* Logo Area */}
                <div className="p-6 border-b border-indigo-500/10">
                    <div className="flex items-center gap-3">
                        <div className="relative">
                            <div className="w-11 h-11 rounded-2xl bg-gradient-to-br from-indigo-500 via-purple-500 to-cyan-500
                                flex items-center justify-center text-white text-lg font-black
                                shadow-lg shadow-indigo-500/30" style={{ animation: 'glowPulse 3s infinite' }}>
                                CQ
                            </div>
                            <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-emerald-400
                                border-2 border-[#08080f] animate-pulse" />
                        </div>
                        <div>
                            <h1 className="text-base font-extrabold tracking-tight gradient-text">CYBERQALQAN</h1>
                            <p className="text-[0.6rem] text-slate-500 font-mono tracking-[0.2em]">AI DEFENCE SYSTEM</p>
                        </div>
                    </div>
                </div>

                {/* Navigation */}
                <nav className="flex-1 py-3 px-3 space-y-0.5 overflow-y-auto">
                    {navItems.map(item => (
                        <NavLink key={item.path} to={item.path} end={item.path === '/'}
                            onClick={() => setOpen(false)}
                            className={({ isActive }) =>
                                `group flex items-center gap-3 px-4 py-3.5 rounded-xl text-sm transition-all duration-300 relative overflow-hidden
                                ${isActive
                                    ? 'bg-gradient-to-r from-indigo-500/15 to-purple-500/10 text-indigo-300 font-semibold'
                                    : 'text-slate-500 hover:text-slate-300 hover:bg-white/[0.02]'}`
                            }>
                            {({ isActive }) => (
                                <>
                                    {isActive && <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 rounded-r-full bg-gradient-to-b from-indigo-400 to-purple-400" />}
                                    <span className={`text-base ${isActive ? 'text-indigo-400' : 'text-slate-600 group-hover:text-slate-400'} transition-colors`}>
                                        {item.icon}
                                    </span>
                                    <span className="flex-1">{item.label}</span>
                                    <span className={`font-mono text-[0.55rem] tracking-wider ${isActive ? 'text-indigo-500/50' : 'text-slate-700 group-hover:text-slate-600'}`}>
                                        {item.tag}
                                    </span>
                                </>
                            )}
                        </NavLink>
                    ))}

                    <div className="pt-4 pb-2 px-4">
                        <div className="h-px bg-indigo-500/10 w-full mb-4" />
                        <a href="https://t.me/CyberQalqanBot" target="_blank" rel="noopener noreferrer"
                            className="flex items-center gap-3 px-4 py-3.5 rounded-xl text-sm text-cyan-400 bg-cyan-500/5 
                                border border-cyan-500/10 hover:bg-cyan-500/10 hover:border-cyan-500/30 transition-all group">
                            <span className="text-lg group-hover:scale-110 transition-transform">✈</span>
                            <span className="flex-1 font-semibold">Telegram Bot</span>
                            <span className="text-[0.6rem] bg-cyan-500/20 text-cyan-300 px-1.5 py-0.5 rounded uppercase tracking-wider">Join</span>
                        </a>
                    </div>
                </nav>

                {/* Status panel */}
                <div className="px-4 pb-4 space-y-3">
                    {/* Time */}
                    <div className="text-center font-mono text-xs text-slate-600">
                        <div className="text-indigo-400/60 text-lg font-bold tracking-wider">{time.toLocaleTimeString()}</div>
                        <div className="text-[0.6rem] text-slate-600">{time.toLocaleDateString('kk-KZ', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</div>
                    </div>

                    {/* System status */}
                    <div className="rounded-xl bg-gradient-to-br from-emerald-500/5 to-cyan-500/5 border border-emerald-500/10 p-3">
                        <div className="flex items-center justify-center gap-2">
                            <span className="relative flex h-2 w-2">
                                <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75 animate-ping" />
                                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400 shadow-lg shadow-emerald-500/50" />
                            </span>
                            <span className="text-emerald-400 text-xs font-semibold">ЖҮЙЕ БЕЛСЕНДІ</span>
                        </div>
                        <p className="text-center text-[0.6rem] text-emerald-500/40 mt-1 font-mono">NEURAL ENGINE v2.0 · PYTORCH</p>
                    </div>
                </div>
            </aside>

            {/* Main */}
            <main className="main-wrap ml-[270px] p-8 flex-1 min-h-screen">
                <div key={location.pathname} className="fade-up max-w-[1050px]">
                    {children}
                </div>

                {/* Telegram FAB for mobile/small screens */}
                <a href="https://t.me/CyberQalqanBot" target="_blank" rel="noopener noreferrer"
                    className="fixed bottom-6 right-6 z-[90] w-14 h-14 rounded-2xl 
                        bg-[#229ED9] flex items-center justify-center shadow-lg shadow-[#229ED9]/40
                        hover:scale-110 active:scale-95 transition-all md:hidden group">
                    <span className="text-white text-2xl group-hover:rotate-12 transition-transform">✈</span>
                    <div className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 rounded-full border-2 border-[#08080f] animate-bounce" />
                </a>
            </main>

            {/* Overlay */}
            {open && <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 md:hidden" onClick={() => setOpen(false)} />}
        </>
    )
}
