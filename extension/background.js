import { config } from './config.js';

// Simple in-memory cache to avoid repeated API calls for the same URL
const urlCache = new Map();

// Helper to check if URL should be ignored (e.g., chrome://, localhost)
function shouldIgnoreUrl(url) {
    if (!url || !url.startsWith('http')) return true;

    // Ignore local development domains if needed, though they might be useful to test
    // if (url.includes('localhost') || url.includes('127.0.0.1')) return true;

    return false;
}

// Function to extract HTML from the page
function getHtmlContent() {
    return document.documentElement.outerHTML;
}

// Function to analyze URL via PhishGuard backend
async function analyzeUrl(url, tabId) {
    if (shouldIgnoreUrl(url)) return;

    // Check cache first
    if (urlCache.has(url)) {
        const cachedResult = urlCache.get(url);
        if (Date.now() - cachedResult.timestamp < config.CACHE_TTL) {
            handleAnalysisResult(cachedResult.data, tabId, url);
            return;
        } else {
            urlCache.delete(url); // Expired
        }
    }

    try {
        let htmlContent = null;
        try {
            // Attempt to extract HTML from the page using scripting API
            const results = await chrome.scripting.executeScript({
                target: { tabId: tabId },
                func: getHtmlContent
            });
            if (results && results[0] && results[0].result) {
                htmlContent = results[0].result;
            }
        } catch (e) {
            console.log("Could not extract HTML from tab:", e);
        }

        const requestBody = { url: url, skip_db: true };
        if (htmlContent) {
            requestBody.html_content = htmlContent;
        }

        const response = await fetch(`${config.API_URL}/api/analyze-url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            throw new Error(`API returned status: ${response.status}`);
        }

        const data = await response.json();

        // Cache the result
        urlCache.set(url, {
            data: data,
            timestamp: Date.now()
        });

        handleAnalysisResult(data, tabId, url);

    } catch (error) {
        console.error("CyberQalqan AI Extension Error:", error);
        // Optionally update icon to show error state
        chrome.action.setBadgeText({ text: 'ERR', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#ffcc00', tabId: tabId });
    }
}

// Process the result and notify the content script if it's phishing
function handleAnalysisResult(data, tabId, url) {
    const isDangerous = data.verdict === 'phishing' || data.verdict === 'suspicious' || data.score >= 0.5;

    if (isDangerous) {
        // Red badge for danger
        chrome.action.setBadgeText({ text: '!', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#ff4d4f', tabId: tabId });

        // Notify the content script to display the injected warning overlay
        chrome.tabs.sendMessage(tabId, {
            action: "show_warning",
            data: data,
            url: url
        }).catch(err => {
            // Content script might not be injected yet or page is still loading
            console.log("Could not send message to content script:", err);
        });

        // Show a system-level popup notification
        chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon128.png", // Fallback to default if icon doesn't exist, Chrome handles it
            title: "Угроза безопасности!",
            message: `Сайт ${new URL(url).hostname} был заблокирован CyberQalqan AI как фишинговый.`,
            priority: 2
        });
    } else {
        // Green badge for safe
        chrome.action.setBadgeText({ text: '✓', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#52c41a', tabId: tabId });
    }
}

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // We want to analyze as soon as we have a URL, but also ensure content script is ready.
    // We'll analyze on 'loading' if URL changed, and again on 'complete' just in case.
    if (changeInfo.url) {
        analyzeUrl(changeInfo.url, tabId);
    } else if (changeInfo.status === 'complete' && tab.url) {
        analyzeUrl(tab.url, tabId);
    }
});

// Also analyze when the active tab changes
chrome.tabs.onActivated.addListener((activeInfo) => {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (tab && tab.url) {
            analyzeUrl(tab.url, tab.id);
        }
    });
});
