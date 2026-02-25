import { Link } from 'react-router-dom'
import { useState, useEffect } from 'react'

export default function Landing() {
    const [mousePos, setMousePos] = useState({ x: 0, y: 0 })
    const [scrolled, setScrolled] = useState(false)

    useEffect(() => {
        const handleMouseMove = (e) => {
            setMousePos({ x: e.clientX, y: e.clientY })
        }

        const handleScroll = () => {
            setScrolled(window.scrollY > 50)
        }

        window.addEventListener('mousemove', handleMouseMove)
        window.addEventListener('scroll', handleScroll)
        return () => {
            window.removeEventListener('mousemove', handleMouseMove)
            window.removeEventListener('scroll', handleScroll)
        }
    }, [])

    return (
        <div className="relative min-h-screen bg-[#0a0a0f] text-slate-300 font-sans selection:bg-indigo-500/30 overflow-x-hidden pt-20">

            {/* Dynamic Background Effects - Added overflow-hidden to prevent horizontal scrolling */}
            <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
                <div
                    className="absolute w-[600px] h-[600px] rounded-full blur-[100px] opacity-20 transition-transform duration-1000 ease-out hidden lg:block"
                    style={{
                        background: 'radial-gradient(circle, rgba(99,102,241,0.5) 0%, rgba(168,85,247,0) 70%)',
                        transform: `translate(${mousePos.x - 300}px, ${mousePos.y - 300}px)`
                    }}
                />
                <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:40px_40px] [mask-image:radial-gradient(ellipse_70%_70%_at_50%_50%,black,transparent)] w-full h-full" />
            </div>

            {/* Navbar */}
            <nav className={`fixed top-0 w-full z-50 transition-all duration-300 ${scrolled ? 'bg-[#0a0a0f]/80 backdrop-blur-md border-b border-indigo-500/10 py-3' : 'bg-transparent py-4'}`}>
                <div className="max-w-6xl mx-auto px-6 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="w-9 h-9 text-xs rounded-xl bg-gradient-to-br from-indigo-500 via-purple-500 to-cyan-500
                            flex items-center justify-center text-white font-black shadow-lg shadow-indigo-500/20" style={{ animation: 'glowPulse 3s infinite' }}>
                            CQ
                        </div>
                        <span className="text-lg font-bold tracking-tight text-white uppercase">Cyber<span className="text-indigo-400">Qalqan</span></span>
                    </div>
                    <div className="flex items-center gap-4">
                        <a href="#features" className="hidden md:block text-sm font-semibold text-slate-400 hover:text-white transition-colors">
                            Мүмкіндіктер
                        </a>
                        <a href="https://t.me/CyberQalqanBot" target="_blank" rel="noopener noreferrer" className="hidden sm:flex text-sm font-semibold text-slate-400 hover:text-cyan-400 transition-colors">
                            Telegram Bot
                        </a>
                        <a href="/CyberQalqan_Extension.zip" download="CyberQalqan_Extension.zip" className="hidden lg:flex text-sm font-semibold text-slate-400 hover:text-purple-400 transition-colors">
                            Кеңейтім
                        </a>
                        <Link to="/dashboard" className="px-4 py-2 rounded-xl bg-indigo-500 hover:bg-indigo-600 text-white text-sm font-semibold transition-all shadow-[0_0_15px_rgba(99,102,241,0.3)] hover:shadow-[0_0_20px_rgba(99,102,241,0.5)] border border-indigo-400/50">
                            Жүйеге кіру
                        </Link>
                    </div>
                </div>
            </nav>

            <main className="relative z-10">
                {/* Hero Section */}
                <section className="max-w-6xl mx-auto px-4 md:px-6 pt-16 pb-16 text-center">
                    <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/5 border border-emerald-500/20 text-emerald-400 text-xs font-semibold uppercase tracking-wide mb-6 fade-up stagger-1 backdrop-blur-sm shadow-[0_0_10px_rgba(16,185,129,0.1)]">
                        <span className="relative flex h-1.5 w-1.5">
                            <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75 animate-ping" />
                            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
                        </span>
                        Киберқауіпсіздік жүйесі белсенді
                    </div>

                    <h1 className="text-4xl md:text-5xl lg:text-6xl font-black text-white mb-6 tracking-tight leading-[1.2] fade-up stagger-2">
                        Жасанды Интеллектпен <br className="hidden md:block" />
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 via-purple-400 to-cyan-400 drop-shadow-md filter">
                            Қорғалған Кеңістік
                        </span>
                    </h1>

                    <p className="max-w-2xl mx-auto text-base md:text-lg text-slate-400 mb-10 leading-relaxed fade-up stagger-3 font-medium">
                        CyberQalqan — бұл фишингтік шабуылдарды, зиянды сілтемелерді және алаяқтық хаттарды нейрондық желілердің көмегімен нақты уақытта анықтайтын кешенді қауіпсіздік платформасы.
                    </p>

                    <div className="flex flex-col sm:flex-row items-center justify-center gap-4 fade-up stagger-4 max-w-sm sm:max-w-none mx-auto w-full">
                        <Link to="/dashboard" className="w-full sm:w-auto px-6 py-3.5 rounded-xl bg-indigo-600/90 backdrop-blur-md border border-indigo-400/30 text-white font-bold text-base hover:bg-indigo-500 hover:-translate-y-0.5 transition-all shadow-[0_5px_20px_-5px_rgba(99,102,241,0.5)]">
                            Талдауды бастау →
                        </Link>
                        <a href="/CyberQalqan_Extension.zip" download="CyberQalqan_Extension.zip" className="w-full sm:w-auto px-6 py-3.5 rounded-xl bg-purple-500/10 backdrop-blur-md border border-purple-500/30 text-purple-300 font-bold text-base hover:bg-purple-500/20 hover:border-purple-500/50 hover:-translate-y-0.5 transition-all shadow-[0_5px_20px_-5px_rgba(168,85,247,0.15)] flex items-center justify-center gap-2">
                            <span className="text-xl">🧩</span> Кеңейтімді жүктеу
                        </a>
                        <a href="#features" className="w-full sm:w-auto px-6 py-3.5 rounded-xl bg-slate-800/50 backdrop-blur-md border border-slate-700/50 text-white font-bold text-base hover:bg-slate-700/50 transition-colors">
                            Толығырақ білу
                        </a>
                    </div>
                </section>

                {/* Features Section */}
                <section id="features" className="max-w-6xl mx-auto px-4 md:px-6 py-16 relative">
                    <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-xl h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent"></div>

                    <div className="text-center mb-12">
                        <h2 className="text-2xl md:text-4xl font-black text-white mb-3 tracking-tight">Жүйенің мүмкіндіктері</h2>
                        <p className="text-slate-400 max-w-xl mx-auto text-base font-medium">Сіздің цифрлық қауіпсіздігіңізді қамтамасыз ететін негізгі құралдар</p>
                    </div>

                    <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
                        {/* Feature 1 */}
                        <div className="glass p-6 rounded-2xl group hover:-translate-y-1 transition-transform duration-500 cursor-default border border-indigo-500/10 hover:border-indigo-500/30">
                            <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-2xl mb-4 text-indigo-400 group-hover:scale-110 group-hover:bg-indigo-500/20 transition-all shadow-[0_0_15px_rgba(99,102,241,0.1)]">
                                ⬡
                            </div>
                            <h3 className="text-lg font-bold text-white mb-2 tracking-wide">URL Талдау (DL)</h3>
                            <p className="text-slate-400 text-sm leading-relaxed font-medium">
                                Жасанды интеллект сілтемелерді сканерлеп, фишингтік немесе зиянды сайттарды дәлдікпен таниды. PyTorch негізінде қызмет етеді.
                            </p>
                        </div>

                        {/* Feature 2 */}
                        <div className="glass p-6 rounded-2xl group hover:-translate-y-1 transition-transform duration-500 cursor-default border border-amber-500/10 hover:border-amber-500/30">
                            <div className="w-12 h-12 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-2xl mb-4 text-amber-400 group-hover:scale-110 group-hover:bg-amber-500/20 transition-all shadow-[0_0_15px_rgba(245,158,11,0.1)]">
                                ✉
                            </div>
                            <h3 className="text-lg font-bold text-white mb-2 tracking-wide">Email Intel</h3>
                            <p className="text-slate-400 text-sm leading-relaxed font-medium">
                                Келген хаттардағы психологиялық манипуляцияларды және алаяқтыққа тән мәтіндерді тауып, анализ жасайды.
                            </p>
                        </div>

                        {/* Feature 3 */}
                        <div className="glass p-6 rounded-2xl group hover:-translate-y-1 transition-transform duration-500 cursor-default border border-emerald-500/10 hover:border-emerald-500/30">
                            <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-2xl mb-4 text-emerald-400 group-hover:scale-110 group-hover:bg-emerald-500/20 transition-all shadow-[0_0_15px_rgba(16,185,129,0.1)]">
                                ⬢
                            </div>
                            <h3 className="text-lg font-bold text-white mb-2 tracking-wide">QR Quishing Қорғанысы</h3>
                            <p className="text-slate-400 text-sm leading-relaxed font-medium">
                                "Quishing" шабуылдарынан қорғау үшін сканерленген QR кодтарды оқып, ішінде жасырылған сілтемелерді тексереді.
                            </p>
                        </div>

                        {/* Feature 4 */}
                        <div className="glass p-6 rounded-2xl group hover:-translate-y-1 transition-transform duration-500 cursor-default border border-cyan-500/10 hover:border-cyan-500/30">
                            <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-2xl mb-4 text-cyan-400 group-hover:scale-110 group-hover:bg-cyan-500/20 transition-all shadow-[0_0_15px_rgba(6,182,212,0.1)]">
                                💬
                            </div>
                            <h3 className="text-lg font-bold text-white mb-2 tracking-wide">AI Кибер Кеңесші</h3>
                            <p className="text-slate-400 text-sm leading-relaxed font-medium">
                                Кез келген киберқауіпсіздік сұрақтарына интеллектуалды түрде жауап беретін жеке чат-бот ассистентіңіз.
                            </p>
                        </div>

                        {/* Feature 5 */}
                        <div className="glass p-6 rounded-2xl group hover:-translate-y-1 transition-transform duration-500 cursor-default lg:col-span-2 relative overflow-hidden border border-purple-500/10 hover:border-purple-500/30">
                            <div className="absolute -top-10 -right-10 w-32 h-32 bg-purple-500/20 rounded-full blur-[40px] pointer-events-none"></div>
                            <div className="relative z-10 w-full flex flex-col sm:flex-row items-start sm:items-center gap-5">
                                <div className="w-12 h-12 shrink-0 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-2xl text-purple-400 group-hover:scale-110 group-hover:bg-purple-500/20 transition-all shadow-[0_0_15px_rgba(168,85,247,0.1)]">
                                    ◎
                                </div>
                                <div>
                                    <h3 className="text-lg font-bold text-white mb-2 tracking-wide">Heuristic Engine & Тарих</h3>
                                    <p className="text-slate-400 text-sm leading-relaxed font-medium w-full">
                                        Жүйе танымал брендтердің (Kaspi, Halyk, Google) атын жамылу әрекеттерін (тайпосквоттинг) лезде байқайды. Барлық талдау тарихы бұлтты қауіпсіз дерекқорда (Neon DB) сақталады.
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Banner */}
                <section className="max-w-6xl mx-auto px-4 md:px-6 py-10">
                    <div className="relative rounded-3xl bg-[#0a1128] border border-cyan-500/30 p-6 md:p-10 overflow-hidden flex flex-col md:flex-row items-center justify-between gap-8 text-white shadow-[0_0_30px_rgba(6,182,212,0.1)] group hover:shadow-[0_0_50px_rgba(6,182,212,0.15)] transition-shadow duration-500">
                        <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/10 to-blue-600/10 pointer-events-none"></div>
                        <div className="absolute -top-32 -right-32 w-64 h-64 bg-cyan-500/20 rounded-full blur-3xl group-hover:bg-cyan-500/30 transition-colors duration-700 pointer-events-none"></div>
                        <div className="absolute -bottom-32 -left-32 w-64 h-64 bg-blue-600/20 rounded-full blur-3xl group-hover:bg-blue-600/30 transition-colors duration-700 pointer-events-none"></div>

                        <div className="relative z-10 md:w-2/3 text-center md:text-left">
                            <h2 className="text-2xl md:text-3xl font-black mb-3 tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-cyan-300 to-blue-400">
                                Телеграм арқылы тексеру
                            </h2>
                            <p className="text-cyan-100/80 text-sm md:text-base font-medium leading-relaxed max-w-xl mx-auto md:mx-0">
                                Telegram қосымшасында біздің ботқа күдікті сілтемені, мәтінді немесе QR-кодты жіберіп, дәл сол сәтте ЖИ арқылы сараптама нәтижесін алыңыз.
                            </p>
                        </div>
                        <div className="relative z-10 w-full md:w-auto shrink-0 flex justify-center">
                            <a href="https://t.me/CyberQalqanBot" target="_blank" rel="noopener noreferrer"
                                className="inline-flex items-center justify-center gap-2 bg-cyan-500 hover:bg-cyan-400 text-slate-900 px-6 py-3.5 rounded-xl font-bold text-base transition-all shadow-[0_0_20px_rgba(6,182,212,0.3)] hover:shadow-[0_0_30px_rgba(6,182,212,0.5)] hover:-translate-y-0.5 w-full sm:w-auto">
                                <span className="text-xl animate-bounce">✈</span>
                                Ботқа қосылу
                            </a>
                        </div>
                    </div>
                </section>
            </main>

            {/* Footer */}
            <footer className="border-t border-indigo-500/10 bg-[#06060a] py-8 mt-10">
                <div className="max-w-6xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4 text-slate-500 text-xs font-medium">
                    <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded bg-indigo-500/20 flex items-center justify-center text-indigo-400 font-bold text-[10px]">
                            CQ
                        </div>
                        <p className="tracking-wide">© 2026 CyberQalqan AI</p>
                    </div>
                    <div className="flex gap-4">
                        <span className="hover:text-indigo-400 cursor-pointer transition-colors">Құпиялық саясаты</span>
                        <span className="hover:text-indigo-400 cursor-pointer transition-colors">Ережелер</span>
                    </div>
                </div>
            </footer>

        </div>
    )
}
