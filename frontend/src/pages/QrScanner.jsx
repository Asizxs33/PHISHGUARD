import { useState, useRef } from 'react'
import { analyzeUrl, analyzeQr } from '../api'
import { ResultCard } from '../components/ResultCard'

export default function QrScanner() {
    const [mode, setMode] = useState('upload')
    const [file, setFile] = useState(null)
    const [preview, setPreview] = useState(null)
    const [decodedUrl, setDecodedUrl] = useState('')
    const [loading, setLoading] = useState(false)
    const [result, setResult] = useState(null)
    const [error, setError] = useState('')
    const [dragOver, setDragOver] = useState(false)
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

    const handleAnalyzeQr = async () => {
        if (!file) return
        setLoading(true); setError(''); setResult(null); setDecodedUrl('')
        try { const d = await analyzeQr(file); setDecodedUrl(d.decoded_url || ''); setResult(d) }
        catch (err) { setError(err.response?.data?.detail || 'QR кодты декодтау мүмкін болмады') }
        setLoading(false)
    }

    const handleAnalyzeUrl = async () => {
        if (!decodedUrl.trim()) return
        setLoading(true); setError(''); setResult(null)
        try { setResult(await analyzeUrl(decodedUrl.trim())) }
        catch (err) { setError(err.response?.data?.detail || 'Талдау мүмкін болмады') }
        setLoading(false)
    }

    return (
        <div>
            {/* Header */}
            <div className="relative glass rounded-3xl p-8 mb-6 overflow-hidden fade-up">
                <div className="absolute inset-0 dot-pattern opacity-20" />
                <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-1 h-8 rounded-full bg-gradient-to-b from-cyan-400 to-blue-400" />
                        <h2 className="text-3xl font-black tracking-tight gradient-text">QR КОД ТЕКСЕРУ</h2>
                    </div>
                    <p className="text-slate-500 text-sm ml-4 font-mono">
                        SCAN QR → CYBERQALQAN AI DECODE → URL INTEL
                    </p>
                </div>
            </div>

            {/* Mode tabs */}
            <div className="flex gap-2 mb-5 fade-up stagger-1">
                {[{ key: 'upload', label: '◈ СУРЕТ ЖҮКТЕУ', icon: '📷' }, { key: 'url', label: '◈ URL ЕНГІЗУ', icon: '🔗' }].map(m => (
                    <button key={m.key} onClick={() => setMode(m.key)}
                        className={`px-4 py-2.5 rounded-xl text-xs font-mono border transition-all cursor-pointer
                            ${mode === m.key
                                ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400 shadow-sm shadow-cyan-500/10'
                                : 'bg-transparent border-white/5 text-slate-600 hover:text-slate-400 hover:border-white/10'}`}>
                        {m.label}
                    </button>
                ))}
            </div>

            {mode === 'upload' ? (
                <div className="glass glow-border rounded-2xl p-6 mb-4 fade-up stagger-2">
                    <div onDrop={handleDrop}
                        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
                        onDragLeave={() => setDragOver(false)}
                        onClick={() => fileInputRef.current?.click()}
                        className={`border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer
                            transition-all duration-300 relative overflow-hidden
                            ${dragOver
                                ? 'border-cyan-400/50 bg-cyan-500/5'
                                : 'border-white/10 hover:border-cyan-500/30 hover:bg-cyan-500/[0.02]'}`}>

                        {/* Animated corner decorations */}
                        <div className="absolute top-3 left-3 w-4 h-4 border-t-2 border-l-2 border-cyan-500/30 rounded-tl-md" />
                        <div className="absolute top-3 right-3 w-4 h-4 border-t-2 border-r-2 border-cyan-500/30 rounded-tr-md" />
                        <div className="absolute bottom-3 left-3 w-4 h-4 border-b-2 border-l-2 border-cyan-500/30 rounded-bl-md" />
                        <div className="absolute bottom-3 right-3 w-4 h-4 border-b-2 border-r-2 border-cyan-500/30 rounded-br-md" />

                        {preview ? (
                            <div>
                                <img src={preview} alt="QR" className="max-w-[200px] max-h-[200px] rounded-xl border border-white/10 mx-auto shadow-2xl shadow-cyan-500/10" />
                                <div className="text-slate-500 text-xs font-mono mt-3">{file?.name}</div>
                            </div>
                        ) : (
                            <div>
                                <div className="text-5xl mb-4" style={{ animation: 'float 3s ease-in-out infinite' }}>📷</div>
                                <div className="text-slate-400 font-medium">QR код суретін осында тастаңыз</div>
                                <div className="text-slate-600 text-sm mt-2 font-mono">немесе файлды таңдау үшін басыңыз</div>
                            </div>
                        )}
                    </div>
                    <input ref={fileInputRef} type="file" accept="image/*" className="hidden" onChange={handleFileChange} />
                    <button onClick={handleAnalyzeQr} disabled={!file || loading}
                        className="w-full mt-4 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white
                            font-bold shadow-lg shadow-cyan-500/25 hover:shadow-xl hover:shadow-cyan-500/35
                            hover:-translate-y-1 transition-all disabled:opacity-30 disabled:cursor-not-allowed
                            cursor-pointer text-sm tracking-wide">
                        {loading ? '⏳ ДЕКОДТАУДА...' : '⬢ ДЕКОДТАУ & ТАЛДАУ'}
                    </button>
                </div>
            ) : (
                <div className="glass glow-border rounded-2xl p-6 mb-4 fade-up stagger-2">
                    <div className="flex items-center gap-2 mb-3">
                        <span className="text-cyan-500/60 text-xs font-mono">[URL]</span>
                        <label className="text-sm font-medium text-slate-400">Декодталған URL</label>
                    </div>
                    <div className="flex gap-3">
                        <input type="text" value={decodedUrl} onChange={e => setDecodedUrl(e.target.value)}
                            placeholder="https://example.com" className="input-dark flex-1" />
                        <button onClick={handleAnalyzeUrl} disabled={!decodedUrl.trim() || loading}
                            className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white
                                font-bold shadow-lg shadow-cyan-500/25 transition-all disabled:opacity-30
                                disabled:cursor-not-allowed cursor-pointer text-sm">
                            {loading ? '⏳' : '⬢ ТАЛДАУ'}
                        </button>
                    </div>
                </div>
            )}

            {decodedUrl && mode === 'upload' && (
                <div className="p-4 rounded-xl bg-indigo-500/5 border border-indigo-500/15 fade-up
                    flex items-center gap-3 mb-4">
                    <span className="text-indigo-400 font-mono text-xs">[DECODED]</span>
                    <span className="font-mono text-sm text-slate-300 break-all">{decodedUrl}</span>
                </div>
            )}

            {error && (
                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm fade-up font-mono mb-4">
                    [ERROR] {error}
                </div>
            )}

            {loading && (
                <div className="glass rounded-2xl p-8 text-center fade-up">
                    <div className="shimmer mb-6 mx-auto max-w-[350px]"></div>
                    <div className="text-cyan-400 font-bold tracking-wide text-sm">QR КОДТЫ ӨҢДЕУ ЖҮРГІЗІЛУДЕ</div>
                    <div className="text-slate-600 text-xs font-mono mt-2 cursor-blink">decode → extract_url → analyze</div>
                </div>
            )}

            <ResultCard result={result} />

            {/* Warning */}
            <div className="glass rounded-2xl p-6 mt-5 fade-up border-l-2 border-amber-500/30">
                <div className="flex items-center gap-2 mb-3">
                    <span className="text-amber-400 text-lg">⚠️</span>
                    <h3 className="text-sm font-bold text-slate-300 tracking-wide">QUISHING ЕСКЕРТУІ</h3>
                </div>
                <p className="text-sm text-slate-500 leading-relaxed">
                    QR-код арқылы фишинг (quishing) — зиянды URL-дерді QR кодтардың ішіне жасыру тәсілі.
                    Шабуылшылар жалған QR кодтарды мейрамханаларда, паркингтерде және хаттарда орналастырады.
                    <span className="text-amber-400/60"> Белгісіз QR кодтарды сканерлеу алдында дереккөзді тексеріңіз.</span>
                </p>
            </div>
        </div>
    )
}
