import { useState } from 'react';

// Hardcoded Training Scenarios
const SCENARIOS = [
    {
        id: 1,
        type: 'url',
        content: 'https://kaspi.kz-login.secure-auth.com/verify',
        isPhishing: true,
        explanation: {
            kz: 'Бұл фишинг! Нағыз Kaspi адресі тек "kaspi.kz" деп аяқталады. Алаяқтар "kz-login.secure-auth.com" деген ұзын домен жасап, алдауға тырысқан.',
            ru: 'Это фишинг! Настоящий адрес Kaspi всегда заканчивается на "kaspi.kz", а здесь домен — "secure-auth.com". Это обман.',
            en: 'Phishing! The real Kaspi domain is "kaspi.kz". The actual domain here is "secure-auth.com". This is a scam.'
        }
    },
    {
        id: 2,
        type: 'email',
        sender: 'support@egov.kz',
        subject: 'Налог по задолженности',
        content: `Уважаемый налогоплательщик!\n\nУ вас имеется задолженность в размере 45 600 тг. Оплатите по ссылке ниже до конца дня, иначе ваши счета будут заблокированы:\n\nhttp://egov-pay-kz.site/invoice/49281`,
        isPhishing: true,
        explanation: {
            kz: 'Фишинг! Біріншіден, сізді қорқытып, асықтыруда ("счета будут заблокированы" - срочность). Екіншіден, сілтеме egov.kz емес, "egov-pay-kz.site" деген жалған сайтқа апарады.',
            ru: 'Фишинг! Во-первых, манипуляция страхом (срочность). Во-вторых, ссылка ведет не на egov.kz, а на подозрительный сайт "egov-pay-kz.site".',
            en: 'Phishing! It uses urgency/fear tactics ("accounts blocked") and the link points to a fake domain "egov-pay-kz.site".'
        }
    },
    {
        id: 3,
        type: 'sms',
        sender: '1414',
        content: 'Sizdin EGOV paroliniz ozgertildi. Eger bul siz emes bolsaniz, toktatu ushin siltemege otiniz: https://egov.kz/cms/ru',
        isPhishing: false,
        explanation: {
            kz: 'Қауіпсіз! Бұл ресми 1414 нөмірінен келген хабарлама, ал сілтеме нағыз "egov.kz" мемлекеттік сайтына апарады.',
            ru: 'Безопасно! Сообщение от официального номера 1414, а ссылка ведет на настоящий домен "egov.kz".',
            en: 'Safe! The message is from the official 1414 number, and the link leads to the real "egov.kz" domain.'
        }
    },
    {
        id: 4,
        type: 'url',
        content: 'https://paypal.com@192.168.1.55/login',
        isPhishing: true,
        explanation: {
            kz: 'Бұл өте қауіпті фишинг! "@" белгісіне дейінгі мәтін (paypal.com) елемеуге арналған, ал сіз шын мәнінде 192.168.1.55 деген IP-адреске кіресіз.',
            ru: 'Критическая угроза! Символ "@" в адресе скрывает настоящий путь. Вы попадете не на PayPal, а на IP-адрес мошенника (192.168.1.55).',
            en: 'Critical threat! The "@" symbol tricks the browser. You are not going to PayPal, but to the IP address 192.168.1.55.'
        }
    },
    {
        id: 5,
        type: 'url',
        content: 'https://homebank.kz/login',
        isPhishing: false,
        explanation: {
            kz: 'Қауіпсіз! Бұл Halyk Bank-тің ресми, дұрыс жазылған интернет-банкинг адресі. (HTTPS бар, домен дұрыс).',
            ru: 'Безопасно! Это официальный адрес интернет-банкинга Halyk Bank (домен правильный, передача данных защищена HTTPS).',
            en: 'Safe! This is the official and correct domain for Halyk Bank. HTTPS is active and the URL is clean.'
        }
    }
];

export default function CyberTraining() {
    const [currentIndex, setCurrentIndex] = useState(0);
    const [score, setScore] = useState(0);
    const [showExplanation, setShowExplanation] = useState(false);
    const [userAnswer, setUserAnswer] = useState(null); // 'phishing' | 'safe'
    const [isGameOver, setIsGameOver] = useState(false);
    const [lang, setLang] = useState('ru'); // Default language

    const currentScenario = SCENARIOS[currentIndex];

    // Languages support
    const t = {
        kz: {
            title: '🎯 Cyber Training (Тренажер)',
            desc: 'Бұл мысал фишинг пе, әлде қауіпсіз бе? Өз біліміңізді тексеріңіз.',
            btnPhish: 'Бұл Фишинг ⚠️',
            btnSafe: 'Бұл Қауіпсіз ✅',
            next: 'Келесі сұрақ ➔',
            correct: 'Дұрыс!',
            wrong: 'Қате!',
            score: 'Ұпай',
            gameover: 'Ойын Аяқталды!',
            restart: 'Қайта бастау 🔄',
        },
        ru: {
            title: '🎯 Cyber Training (Тренажер)',
            desc: 'Является ли этот пример фишингом или он безопасен? Проверьте себя.',
            btnPhish: 'Это Фишинг ⚠️',
            btnSafe: 'Это Безопасно ✅',
            next: 'Следующий вопрос ➔',
            correct: 'Верно!',
            wrong: 'Ошибка!',
            score: 'Счет',
            gameover: 'Тренировка завершена!',
            restart: 'Начать заново 🔄',
        },
        en: {
            title: '🎯 Cyber Training Module',
            desc: 'Is this example phishing or safe? Test your digital literacy.',
            btnPhish: 'This is Phishing ⚠️',
            btnSafe: 'This is Safe ✅',
            next: 'Next Question ➔',
            correct: 'Correct!',
            wrong: 'Wrong!',
            score: 'Score',
            gameover: 'Training Complete!',
            restart: 'Restart Training 🔄',
        }
    }[lang];

    const handleAnswer = (answer) => {
        setUserAnswer(answer);
        setShowExplanation(true);

        const isCorrect = (answer === 'phishing' && currentScenario.isPhishing) ||
            (answer === 'safe' && !currentScenario.isPhishing);

        if (isCorrect) {
            setScore(prev => prev + 1);
        }
    };

    const nextQuestion = () => {
        setShowExplanation(false);
        setUserAnswer(null);

        if (currentIndex < SCENARIOS.length - 1) {
            setCurrentIndex(prev => prev + 1);
        } else {
            setIsGameOver(true);
        }
    };

    const restartGame = () => {
        setCurrentIndex(0);
        setScore(0);
        setShowExplanation(false);
        setUserAnswer(null);
        setIsGameOver(false);
    };

    return (
        <div className="space-y-6">
            <header className="flex justify-between items-center bg-[rgba(15,23,42,0.4)] border border-indigo-500/20 p-6 rounded-3xl backdrop-blur-md">
                <div>
                    <h1 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-cyan-400 to-indigo-400">
                        {t.title}
                    </h1>
                    <p className="text-slate-400 mt-2">{t.desc}</p>
                </div>

                {/* Language Selector & Score */}
                <div className="flex flex-col items-end gap-3">
                    <div className="flex bg-black/40 rounded-xl p-1 border border-white/5">
                        {['kz', 'ru', 'en'].map(l => (
                            <button key={l} onClick={() => setLang(l)}
                                className={`px-3 py-1 text-xs font-bold rounded-lg uppercase transition-all ${lang === l ? 'bg-indigo-500 text-white' : 'text-slate-500 hover:text-slate-300'}`}>
                                {l}
                            </button>
                        ))}
                    </div>
                    <div className="bg-gradient-to-r from-indigo-500/20 to-purple-500/20 border border-indigo-500/30 px-4 py-2 rounded-xl text-lg font-black text-indigo-300">
                        {t.score}: {score}/{SCENARIOS.length}
                    </div>
                </div>
            </header>

            {isGameOver ? (
                /* GAME OVER UI */
                <div className="bg-[rgba(15,23,42,0.4)] border border-indigo-500/20 p-12 rounded-3xl backdrop-blur-md text-center fade-in">
                    <h2 className="text-5xl font-black mb-6 text-white">{t.gameover}</h2>
                    <div className="text-8xl mb-6">
                        {score === SCENARIOS.length ? '🏆' : score >= SCENARIOS.length / 2 ? '👍' : '📚'}
                    </div>
                    <p className="text-2xl text-slate-300 mb-8">
                        {t.score}: <span className="text-emerald-400 font-bold">{score} / {SCENARIOS.length}</span>
                    </p>
                    <button onClick={restartGame}
                        className="bg-indigo-600 hover:bg-indigo-500 text-white px-8 py-4 rounded-xl font-bold text-lg transition-transform hover:scale-105 active:scale-95 shadow-lg shadow-indigo-500/25">
                        {t.restart}
                    </button>
                </div>
            ) : (
                /* GAME UI */
                <div className="bg-[rgba(15,23,42,0.4)] border border-indigo-500/20 rounded-3xl backdrop-blur-md overflow-hidden fade-in">

                    {/* Progress bar */}
                    <div className="w-full h-1 bg-slate-800">
                        <div className="h-full bg-gradient-to-r from-cyan-400 to-indigo-500 transition-all duration-500"
                            style={{ width: `${((currentIndex) / SCENARIOS.length) * 100}%` }} />
                    </div>

                    <div className="p-8 lg:p-12">
                        {/* Scenario Presenter */}
                        <div className="bg-[#0a0f1c] border border-slate-800/80 rounded-2xl p-6 mb-8 shadow-inner font-mono text-sm relative">
                            <span className="absolute -top-3 left-6 bg-indigo-500/20 border border-indigo-500/50 text-indigo-300 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider backdrop-blur-md">
                                {currentScenario.type}
                            </span>

                            {currentScenario.type === 'url' && (
                                <div className="mt-4 text-emerald-400 break-all text-lg">
                                    {currentScenario.content}
                                </div>
                            )}

                            {currentScenario.type === 'email' && (
                                <div className="mt-4 text-slate-300 space-y-4">
                                    <div className="border-b border-slate-800 pb-3">
                                        <div><span className="text-slate-500">From:</span> <span className="text-cyan-400">{currentScenario.sender}</span></div>
                                        <div><span className="text-slate-500">Subject:</span> <span className="text-white font-semibold">{currentScenario.subject}</span></div>
                                    </div>
                                    <div className="whitespace-pre-wrap leading-relaxed">
                                        {currentScenario.content}
                                    </div>
                                </div>
                            )}

                            {currentScenario.type === 'sms' && (
                                <div className="mt-4 text-slate-300 flex items-start gap-4">
                                    <div className="w-10 h-10 rounded-full bg-emerald-500/20 flex items-center justify-center shrink-0">
                                        <span className="text-emerald-400 font-bold">SMS</span>
                                    </div>
                                    <div className="bg-slate-800/50 rounded-2xl rounded-tl-none p-4 max-w-lg shadow-sm border border-slate-700/50">
                                        <div className="text-cyan-400 text-xs mb-1 font-bold">{currentScenario.sender}</div>
                                        <div>{currentScenario.content}</div>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Controls / Feedback */}
                        {!showExplanation ? (
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <button onClick={() => handleAnswer('phishing')}
                                    className="group relative overflow-hidden bg-gradient-to-br from-red-500/10 to-rose-600/5 border border-red-500/30 hover:border-red-400 p-6 rounded-2xl transition-all hover:scale-[1.02] active:scale-[0.98]">
                                    <div className="absolute inset-0 bg-red-500/10 group-hover:bg-red-500/20 transition-colors" />
                                    <span className="relative z-10 text-red-400 font-black text-xl tracking-wide">{t.btnPhish}</span>
                                </button>

                                <button onClick={() => handleAnswer('safe')}
                                    className="group relative overflow-hidden bg-gradient-to-br from-emerald-500/10 to-teal-600/5 border border-emerald-500/30 hover:border-emerald-400 p-6 rounded-2xl transition-all hover:scale-[1.02] active:scale-[0.98]">
                                    <div className="absolute inset-0 bg-emerald-500/10 group-hover:bg-emerald-500/20 transition-colors" />
                                    <span className="relative z-10 text-emerald-400 font-black text-xl tracking-wide">{t.btnSafe}</span>
                                </button>
                            </div>
                        ) : (
                            <div className="fade-in space-y-6">
                                {/* Result Banner */}
                                {((userAnswer === 'phishing' && currentScenario.isPhishing) || (userAnswer === 'safe' && !currentScenario.isPhishing)) ? (
                                    <div className="bg-emerald-500/10 border-l-4 border-emerald-500 p-4 rounded-r-xl">
                                        <h3 className="text-emerald-400 font-bold text-xl flex items-center gap-2">
                                            ✅ {t.correct}
                                        </h3>
                                    </div>
                                ) : (
                                    <div className="bg-red-500/10 border-l-4 border-red-500 p-4 rounded-r-xl">
                                        <h3 className="text-red-400 font-bold text-xl flex items-center gap-2">
                                            ❌ {t.wrong}
                                        </h3>
                                    </div>
                                )}

                                {/* Explanation Text */}
                                <div className="bg-indigo-500/5 border border-indigo-500/20 p-6 rounded-2xl">
                                    <h4 className="text-indigo-300 font-semibold mb-2 uppercase text-sm tracking-wider">CyberQalqan AI Analysis:</h4>
                                    <p className="text-slate-200 text-lg leading-relaxed">
                                        {currentScenario.explanation[lang]}
                                    </p>
                                </div>

                                <button onClick={nextQuestion}
                                    className="w-full bg-slate-800 hover:bg-slate-700 text-white font-bold py-4 rounded-xl transition-colors border border-slate-600">
                                    {t.next}
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
