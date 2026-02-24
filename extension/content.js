// Listen for messages from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "show_warning") {
        injectWarningScreen(request.data, request.url);
    }
});

function injectWarningScreen(data, url) {
    // Prevent duplicate overlays
    if (document.getElementById('cq-phishguard-overlay')) {
        return;
    }

    // Create the overlay container
    const overlay = document.createElement('div');
    overlay.id = 'cq-phishguard-overlay';

    // Format the reasons array to an HTML list
    const reasonsHtml = data.reasons
        ? data.reasons.map(r => `<li>${r}</li>`).join('')
        : '<li>High risk features detected by ML engine</li>';

    overlay.innerHTML = `
    <div class="cq-container">
      <div class="cq-header">
        <div class="cq-icon">⚠️</div>
        <h1 class="cq-title">Угроза Безопасности!</h1>
      </div>
      <div class="cq-body">
        <p class="cq-subtitle">Сайт <strong>${url}</strong> идентифицирован как фишинговый.</p>
        
        <div class="cq-details">
          <h3>CyberQalqan AI Анализ:</h3>
          <p class="cq-confidence">Уверенность сети: <span>${(data.confidence * 100).toFixed(1)}%</span></p>
          <ul class="cq-reasons">
            ${reasonsHtml}
          </ul>
        </div>
        
        <p class="cq-recommendation">Рекомендуется немедленно покинуть эту страницу. Мы заблокировали её загрузку для вашей безопасности.</p>
      </div>
      <div class="cq-actions">
        <button id="cq-btn-leave" class="cq-btn cq-btn-primary">Покинуть сайт (Рекомендуется)</button>
        <button id="cq-btn-proceed" class="cq-btn cq-btn-secondary">Всё равно перейти (На свой страх и риск)</button>
      </div>
    </div>
  `;

    // Append to body
    document.body.appendChild(overlay);

    // Attempt to stop the rest of the page from executing/loading by covering it fully
    document.body.style.overflow = 'hidden';

    // Add event listeners for buttons
    document.getElementById('cq-btn-leave').addEventListener('click', () => {
        window.location.href = "about:blank"; // Or navigate back
    });

    document.getElementById('cq-btn-proceed').addEventListener('click', () => {
        overlay.remove();
        document.body.style.overflow = '';
    });
}
