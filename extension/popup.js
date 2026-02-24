import { config } from './config.js';

document.addEventListener('DOMContentLoaded', () => {
    const statusCard = document.getElementById('status-card');
    const statusIcon = document.getElementById('status-icon');
    const statusTitle = document.getElementById('status-title');
    const statusDesc = document.getElementById('status-desc');
    const confidenceRow = document.getElementById('confidence-row');
    const confidenceValue = document.getElementById('confidence-value');

    const rescanBtn = document.getElementById('rescan-btn');
    const dashboardBtn = document.getElementById('dashboard-btn');
    const linkPhishguard = document.getElementById('link-phishguard');

    // Simple URL parser
    const getDomain = (urlStr) => {
        try {
            const url = new URL(urlStr);
            return url.hostname;
        } catch {
            return urlStr;
        }
    };

    const updateUI = (state, data = null, url = "") => {
        // Reset classes
        statusCard.className = 'status-card';

        if (state === 'loading') {
            statusCard.classList.add('loading');
            statusIcon.textContent = '🔄';
            statusTitle.textContent = 'Анализируем...';
            statusDesc.textContent = url ? getDomain(url) : 'Ожидание страницы';
            confidenceRow.style.display = 'none';
            return;
        }

        if (state === 'safe') {
            statusCard.classList.add('safe');
            statusIcon.textContent = '✓';
            statusTitle.textContent = 'Сайт Безопасен';
            statusTitle.style.color = '#10b981';
            statusDesc.textContent = getDomain(url);
        } else if (state === 'danger') {
            statusCard.classList.add('danger');
            statusIcon.textContent = '⚠️';
            statusTitle.textContent = 'Фишинг Обнаружен!';
            statusTitle.style.color = '#ef4444';
            statusDesc.textContent = getDomain(url);
        }

        if (data && data.confidence !== undefined) {
            confidenceRow.style.display = 'flex';
            const confPercent = (data.confidence * 100).toFixed(1);
            confidenceValue.textContent = `${confPercent}%`;
            confidenceValue.style.color = state === 'danger' ? '#ef4444' : '#10b981';
        }
    };

    const scanCurrentTab = async () => {
        try {
            // Get current active tab
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

            if (!tab || !tab.url || !tab.url.startsWith('http')) {
                statusCard.className = 'status-card';
                statusIcon.textContent = 'ℹ️';
                statusTitle.textContent = 'Системная страница';
                statusTitle.style.color = '#94a3b8';
                statusDesc.textContent = 'Анализ недоступен для этого URL';
                return;
            }

            updateUI('loading', null, tab.url);

            // Call API directly for manual scan
            const response = await fetch(`${config.API_URL}/api/analyze-url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: tab.url })
            });

            if (!response.ok) throw new Error('API Error');

            const data = await response.json();

            updateUI(data.is_phishing ? 'danger' : 'safe', data, tab.url);

        } catch (error) {
            console.error(error);
            statusCard.className = 'status-card';
            statusIcon.textContent = '❌';
            statusTitle.textContent = 'Ошибка сервиса';
            statusTitle.style.color = '#ef4444';
            statusDesc.textContent = 'Не удалось связаться с сервером AI';
        }
    };

    // Initial Scan
    scanCurrentTab();

    // Event Listeners
    rescanBtn.addEventListener('click', scanCurrentTab);

    dashboardBtn.addEventListener('click', () => {
        // Open localhost or deployed dashboard
        const dashboardUrl = config.API_URL.includes('localhost') || config.API_URL.includes('127.0.0.1')
            ? 'http://localhost:5173'
            : 'https://cyberqalqan.netlify.app'; // Or replace with your actual frontend domain
        chrome.tabs.create({ url: dashboardUrl });
    });

    linkPhishguard.addEventListener('click', (e) => {
        e.preventDefault();
        dashboardBtn.click();
    });
});
