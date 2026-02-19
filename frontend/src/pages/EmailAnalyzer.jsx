import { useState } from 'react'
import { analyzeEmail } from '../api'
import { ResultCard } from '../components/ResultCard'

export default function EmailAnalyzer() {
    const [sender, setSender] = useState('')
    const [subject, setSubject] = useState('')
    const [body, setBody] = useState('')
    const [loading, setLoading] = useState(false)
    const [result, setResult] = useState(null)
    const [error, setError] = useState('')

    const handleAnalyze = async (e) => {
        e.preventDefault()
        if (!body.trim()) return
        setLoading(true); setError(''); setResult(null)
        try { setResult(await analyzeEmail(subject, body, sender)) }
        catch (err) { setError(err.response?.data?.detail || 'Серверге қосылу мүмкін болмады.') }
        setLoading(false)
    }

    const fillExample = (type) => {
        if (type === 'phishing') {
            setSender('security-alert-x92@verify-account.tk')
            setSubject('ШҰҒЫЛ: Аккаунтыңыз тоқтатылды!')
            setBody('Құрметті клиент!\n\nСіздің аккаунтыңызда рұқсатсыз кіру анықталды. 24 сағат ішінде растамасаңыз, аккаунтыңыз біржола тоқтатылады.\n\nДереу растау: http://bank-secure-login.tk/verify\n\nҚауіпсіздік қызметі')
        } else {
            setSender('newsletter@google.com')
            setSubject('Апталық жаңалықтар')
            setBody('Сәлеметсіз бе!\n\nОсы аптаның үздік жаңалықтары:\n1. Жаңа өнім мүмкіндіктері\n2. Қоғамдастық жаңалықтары\n\nТолығырақ: https://blog.google.com\n\nҚұрметпен,\nGoogle тобы')
        }
    }

    const vectors = [
        { icon: '🚨', label: 'URGENCY DETECTION', desc: 'ҚЗ/РУ/EN шұғыл сөздерді анықтау', color: 'border-rose-500/20' },
        { icon: '🔗', label: 'URL ANALYSIS', desc: 'Ендірілген сілтемелердің қауіпін бағалау', color: 'border-blue-500/20' },
        { icon: '📊', label: 'HTML RATIO', desc: 'HTML тег пен мәтін арақатынасын талдау', color: 'border-purple-500/20' },
        { icon: '💰', label: 'FINANCIAL CUES', desc: 'Валюта, сома, банк сілтемелерін іздеу', color: 'border-amber-500/20' },
        { icon: '📎', label: 'ATTACHMENT SIGNALS', desc: 'Тіркеме кілт сөздерін анықтау', color: 'border-cyan-500/20' },
        { icon: '🔠', label: 'CAPS ANALYSIS', desc: 'БАС ӘРІП сөздерінің жиілігін талдау', color: 'border-indigo-500/20' },
    ]

    return (
        <div>
            {/* Header */}
            <div className="relative glass rounded-3xl p-8 mb-6 overflow-hidden fade-up">
                <div className="absolute inset-0 dot-pattern opacity-20" />
                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-1 h-8 rounded-full bg-gradient-to-b from-purple-400 to-fuchsia-400" />
                        <h2 className="text-3xl font-black tracking-tight gradient-text">EMAIL ТАЛДАУ</h2>
                    </div>
                    <p className="text-slate-500 text-sm ml-4 font-mono">
                        ХАТ МАЗМҰНЫН ҚОЙУ → НЕЙРОЖЕЛІ ТАЛДАУЫ → ФИШИНГ АНЫҚТАУ
                    </p>
                </div>
            </div>

            {/* Form */}
            <div className="glass glow-border rounded-2xl p-6 mb-4 fade-up stagger-1">
                <form onSubmit={handleAnalyze} className="space-y-4">
                    <div>
                        <div className="flex items-center gap-2 mb-2">
                            <span className="text-purple-500/60 text-xs font-mono">[FROM]</span>
                            <label className="text-sm font-medium text-slate-400">Жіберуші мекенжайы</label>
                        </div>
                        <input type="text" className="input-dark" placeholder="sender@example.com"
                            value={sender} onChange={e => setSender(e.target.value)} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2 mb-2">
                            <span className="text-purple-500/60 text-xs font-mono">[SUBJECT]</span>
                            <label className="text-sm font-medium text-slate-400">Хат тақырыбы</label>
                        </div>
                        <input type="text" className="input-dark" placeholder="Хат тақырыбын жазыңыз"
                            value={subject} onChange={e => setSubject(e.target.value)} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2 mb-2">
                            <span className="text-purple-500/60 text-xs font-mono">[BODY]</span>
                            <label className="text-sm font-medium text-slate-400">Хат мәтіні <span className="text-rose-400">*</span></label>
                        </div>
                        <textarea className="input-dark min-h-[150px] resize-y"
                            placeholder="Хат мазмұнын осында қойыңыз..."
                            value={body} onChange={e => setBody(e.target.value)} required />
                    </div>

                    <div className="flex gap-3 flex-wrap items-center pt-2">
                        <button type="submit" disabled={loading || !body.trim()}
                            className="px-8 py-3.5 rounded-xl bg-gradient-to-r from-purple-500 to-fuchsia-600 text-white
                                font-bold shadow-lg shadow-purple-500/25 hover:shadow-xl hover:shadow-purple-500/35
                                hover:-translate-y-1 active:translate-y-0 transition-all
                                disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer text-sm tracking-wide">
                            {loading ? '⏳ ТАЛДАУДА...' : '✉ СКАНЕРЛЕУ'}
                        </button>
                        <div className="flex gap-2 ml-auto">
                            <button type="button" onClick={() => fillExample('phishing')}
                                className="px-3 py-2 rounded-xl text-xs font-mono bg-rose-500/5 border border-rose-500/15
                                    text-rose-400 hover:border-rose-500/40 transition-all cursor-pointer hover:-translate-y-0.5">
                                ◆ ФИШИНГ ҮЛГІСІ
                            </button>
                            <button type="button" onClick={() => fillExample('safe')}
                                className="px-3 py-2 rounded-xl text-xs font-mono bg-emerald-500/5 border border-emerald-500/15
                                    text-emerald-400 hover:border-emerald-500/40 transition-all cursor-pointer hover:-translate-y-0.5">
                                ◇ ҚАУІПСІЗ ҮЛГІ
                            </button>
                        </div>
                    </div>
                </form>
            </div>

            {error && (
                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm fade-up font-mono">
                    [ERROR] {error}
                </div>
            )}

            {loading && (
                <div className="glass rounded-2xl p-8 text-center fade-up">
                    <div className="shimmer mb-6 mx-auto max-w-[350px]"></div>
                    <div className="text-purple-400 font-bold tracking-wide text-sm">EMAIL ТАЛДАУ ЖҮРГІЗІЛУДЕ</div>
                    <div className="text-slate-600 text-xs font-mono mt-2 cursor-blink">
                        urgency_scan → link_analysis → classification
                    </div>
                </div>
            )}

            <ResultCard result={result} />

            {/* Vectors */}
            <div className="glass rounded-2xl p-6 mt-5 fade-up stagger-2">
                <div className="flex items-center gap-2 mb-5">
                    <div className="w-1 h-4 rounded-full bg-gradient-to-b from-purple-400 to-fuchsia-400" />
                    <h3 className="text-sm font-bold text-slate-300">АНЫҚТАУ VECTORЛАРЫ</h3>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {vectors.map((v, i) => (
                        <div key={i} className={`group glass glass-hover rounded-xl p-4 border-l-2 ${v.color}`}>
                            <div className="flex items-center gap-2.5 mb-2">
                                <span className="text-lg">{v.icon}</span>
                                <span className="text-[0.7rem] font-bold text-slate-300 tracking-wide font-mono">{v.label}</span>
                            </div>
                            <p className="text-xs text-slate-500">{v.desc}</p>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    )
}
