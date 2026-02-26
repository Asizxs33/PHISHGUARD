import { useState, useRef } from 'react'
import { analyzeImage } from '../api'

export default function ImageAnalyzer() {
    const [file, setFile] = useState(null)
    const [preview, setPreview] = useState(null)
    const [loading, setLoading] = useState(false)
    const [result, setResult] = useState(null)
    const [error, setError] = useState('')
    const [dragOver, setDragOver] = useState(false)
    const [scanStep, setScanStep] = useState(-1)
    const [activeLang, setActiveLang] = useState('ru')
    const fileInputRef = useRef(null)

    const handleFileChange = (e) => {
        const f = e.target.files[0]
        if (f) { setFile(f); setPreview(URL.createObjectURL(f)); setResult(null); setError('') }
    }

    const handleDrop = (e) => {
        e.preventDefault(); setDragOver(false)
        const f = e.dataTransfer.files[0]
        if (f?.type.startsWith('image/')) { setFile(f); setPreview(URL.createObjectURL(f)); setResult(null); setError('') }
    }

    const handleAnalyze = async () => {
        if (!file) return
        setLoading(true); setError(''); setResult(null); setScanStep(0);

        const steps = 3;
        const stepDuration = 1000;

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
            const apiPromise = analyzeImage(file);
            const [data] = await Promise.all([apiPromise, minDelay]);
            setResult(data);
        } catch (err) {
            setError(err.response?.data?.detail || 'Талдау мүмкін болмады / Ошибка анализа')
        } finally {
            clearInterval(animationInterval);
            setLoading(false);
            setScanStep(-1);
        }
    }

    const scanStepsUI = [
        { icon: '📸', text: 'Суретті жүктеу / Загрузка фото...' },
        { icon: '👁️', text: 'Мәтінді оқу (OCR) / Распознавание текста...' },
        { icon: '🧠', text: 'Нейрожелі арқылы талдау / Анализ нейросетью...' },
    ]

    return (
        <div>
            {/* Header */}
            <div className="relative glass rounded-3xl p-8 mb-6 overflow-hidden fade-up">
                <div className="absolute inset-0 dot-pattern opacity-20" />
                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-1 h-8 rounded-full bg-gradient-to-b from-orange-400 to-rose-400" />
                        <h2 className="text-3xl font-black tracking-tight gradient-text">ФОТО ТАЛДАУ / СУРЕТ ТЕКСЕРУ</h2>
                    </div>
                    <p className="text-slate-500 text-sm ml-4 font-mono uppercase tracking-widest">
                        OCR → LLM SCAM DETECTION
                    </p>
                </div>
            </div>

            <div className="glass glow-border rounded-2xl p-6 mb-4 fade-up stagger-2 border-orange-500/10">
                <div onDrop={handleDrop}
                    onDragOver={e => { e.preventDefault(); setDragOver(true) }}
                    onDragLeave={() => setDragOver(false)}
                    onClick={() => fileInputRef.current?.click()}
                    className={`border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer
                        transition-all duration-300 relative overflow-hidden
                        ${dragOver
                            ? 'border-orange-400/50 bg-orange-500/5'
                            : 'border-white/10 hover:border-orange-500/30 hover:bg-orange-500/[0.02]'}`}>

                    {/* Animated corner decorations */}
                    <div className="absolute top-3 left-3 w-4 h-4 border-t-2 border-l-2 border-orange-500/30 rounded-tl-md" />
                    <div className="absolute top-3 right-3 w-4 h-4 border-t-2 border-r-2 border-orange-500/30 rounded-tr-md" />
                    <div className="absolute bottom-3 left-3 w-4 h-4 border-b-2 border-l-2 border-orange-500/30 rounded-bl-md" />
                    <div className="absolute bottom-3 right-3 w-4 h-4 border-b-2 border-r-2 border-orange-500/30 rounded-br-md" />

                    {preview ? (
                        <div className="flex flex-col items-center">
                            <div className="relative inline-block rounded-xl overflow-hidden border border-white/10 shadow-2xl shadow-orange-500/10 bg-black/50">
                                <img src={preview} alt="Upload Preview" className="max-w-[300px] max-h-[300px] object-contain block" />

                                {loading && (
                                    <div className="absolute inset-0 z-20 pointer-events-none rounded-xl overflow-hidden">
                                        <div className="absolute inset-0 bg-orange-500/10 animate-pulse mix-blend-overlay"></div>

                                        {/* Grid background */}
                                        <div className="absolute inset-0 opacity-50 bg-[linear-gradient(rgba(249,115,22,0.15)_1px,transparent_1px),linear-gradient(90deg,rgba(249,115,22,0.15)_1px,transparent_1px)] bg-[size:20px_20px]"></div>

                                        {/* Animated scanner line */}
                                        <div className="absolute top-0 left-0 right-0 h-full w-full opacity-0"
                                            style={{ animation: 'scanImage 2.5s ease-in-out infinite' }}>
                                            <div className="absolute bottom-0 left-0 right-0 h-32 w-full bg-gradient-to-t from-orange-500/40 to-transparent"></div>
                                            <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-orange-400 shadow-[0_0_15px_3px_rgba(249,115,22,1)]"></div>
                                        </div>

                                        {/* Targeted corners */}
                                        <div className="absolute top-2 left-2 w-6 h-6 border-t-2 border-l-2 border-orange-500 opacity-80" />
                                        <div className="absolute top-2 right-2 w-6 h-6 border-t-2 border-r-2 border-orange-500 opacity-80" />
                                        <div className="absolute bottom-2 left-2 w-6 h-6 border-b-2 border-l-2 border-orange-500 opacity-80" />
                                        <div className="absolute bottom-2 right-2 w-6 h-6 border-b-2 border-r-2 border-orange-500 opacity-80" />
                                    </div>
                                )}
                            </div>
                            <div className="text-slate-500 text-xs font-mono mt-3">{file?.name}</div>

                            <style>{`
                                @keyframes scanImage {
                                    0% { transform: translateY(-100%); opacity: 0; }
                                    10% { opacity: 1; }
                                    90% { opacity: 1; }
                                    100% { transform: translateY(0%); opacity: 0; }
                                }
                            `}</style>
                        </div>
                    ) : (
                        <div>
                            <div className="text-5xl mb-4" style={{ animation: 'float 3s ease-in-out infinite' }}>🖼️</div>
                            <div className="text-slate-400 font-medium">Скриншот немесе чекті осында тастаңыз (Drop image here)</div>
                            <div className="text-slate-600 text-sm mt-2 font-mono">немесе файлды таңдау үшін басыңыз (Click to select)</div>
                        </div>
                    )}
                </div>

                <input ref={fileInputRef} type="file" accept="image/*" className="hidden" onChange={handleFileChange} />

                <button onClick={handleAnalyze} disabled={!file || loading}
                    className="w-full mt-4 py-3.5 rounded-xl bg-gradient-to-r from-orange-500 to-rose-600 text-white
                        font-bold shadow-lg shadow-orange-500/25 hover:shadow-xl hover:shadow-orange-500/35
                        hover:-translate-y-1 transition-all disabled:opacity-30 disabled:cursor-not-allowed
                        cursor-pointer text-sm tracking-wide">
                    {loading ? '⏳ ТАЛДАУ ЖҮРІП ЖАТЫР...' : '🔮 СУРЕТТІ ТАЛДАУ (ANALYZE)'}
                </button>
            </div>

            {error && (
                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm fade-up font-mono mb-4">
                    [ERROR] {error}
                </div>
            )}

            {loading && (
                <div className="glass glow-border border-orange-500/20 rounded-2xl p-8 mb-6 fade-up">
                    <div className="flex flex-col items-center justify-center">
                        <div className="relative w-16 h-16 mb-6">
                            <div className="absolute inset-0 border-4 border-orange-500/20 rounded-full"></div>
                            <div className="absolute inset-0 border-4 border-orange-500 rounded-full border-t-transparent animate-spin"></div>
                            <div className="absolute inset-0 flex items-center justify-center text-2xl">
                                {scanStep >= 0 && scanStepsUI[Math.min(scanStep, scanStepsUI.length - 1)].icon}
                            </div>
                        </div>

                        <h3 className="text-xl font-bold text-white mb-6 tracking-wide">СУРЕТТІ ТАЛДАУ...</h3>

                        <div className="w-full max-w-sm space-y-4">
                            {scanStepsUI.map((step, index) => (
                                <div key={index} className={`flex items-center gap-4 transition-all duration-500 
                                    ${index === scanStep ? 'opacity-100 translate-x-0' :
                                        index < scanStep ? 'opacity-50 translate-x-0' : 'opacity-20 translate-x-4'}`}>
                                    <div className={`w-8 h-8 shrink-0 rounded-full flex items-center justify-center text-sm
                                        ${index < scanStep ? 'bg-emerald-500/20 text-emerald-400' :
                                            index === scanStep ? 'bg-orange-500/20 text-orange-400 animate-pulse shadow-[0_0_15px_rgba(249,115,22,0.5)]' :
                                                'bg-slate-800 text-slate-500'}`}>
                                        {index < scanStep ? '✓' : index + 1}
                                    </div>
                                    <span className={`text-sm font-medium
                                        ${index === scanStep ? 'text-orange-300' :
                                            index < scanStep ? 'text-emerald-400/70' : 'text-slate-500'}`}>
                                        {step.text}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {result && (
                <div className="glass rounded-2xl p-8 mt-6 fade-up glow-border border-rose-500/20">
                    <div className="flex items-center gap-3 mb-6 pb-4 border-b border-white/5">
                        <div className="w-1 h-6 rounded-full bg-gradient-to-b from-orange-400 to-rose-400" />
                        <h3 className="text-lg font-bold text-slate-200 tracking-tight">AI Кеңесшінің жауабы (CyberQalqan LLM)</h3>
                        <div className="ml-auto flex gap-2">
                            {['kz', 'ru', 'en'].map(lang => (
                                <button key={lang} onClick={() => setActiveLang(lang)}
                                    className={`px-3 py-1 rounded-lg text-xs font-bold uppercase transition-all
                                        ${activeLang === lang ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' : 'bg-white/5 text-slate-500 hover:text-slate-300'}`}>
                                    {lang}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* AI Answer Card */}
                    <div className="bg-slate-900/50 border border-slate-700/50 rounded-xl p-6 mb-6">
                        <div className="flex items-start gap-4">
                            <div className="text-4xl">🤖</div>
                            <div className="text-slate-300 whitespace-pre-line text-lg leading-relaxed">
                                {result.analysis?.answer?.[activeLang] || typeof result.analysis?.answer === 'string' ? result.analysis?.answer : 'Жауап табылмады.'}
                            </div>
                        </div>
                    </div>

                    {/* Extracted Text */}
                    <details className="group">
                        <summary className="cursor-pointer text-sm font-medium text-slate-400 hover:text-slate-300 py-2 transition-colors select-none font-mono text-xs tracking-wider">
                            [+] СУРЕТТЕН ОҚЫЛҒАН МӘТІН (OCR EXTRACTED TEXT)
                        </summary>
                        <div className="mt-3 bg-black/40 border border-white/5 rounded-xl p-4 font-mono text-sm text-slate-300 whitespace-pre-wrap max-h-60 overflow-y-auto">
                            {result.extracted_text || 'Мәтін оқылмады.'}
                        </div>
                    </details>
                </div>
            )}
        </div>
    )
}
