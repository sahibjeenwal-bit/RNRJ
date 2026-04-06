const currentUrl = window.location.href;

chrome.runtime.sendMessage({ action: "scanURL", url: currentUrl }, (response) => {
    if (response && response.success) {
        const data = response.result;
        
        if (data.is_phishing || data.risk_level === "High") {
            blockPage(data);
        } else if (data.risk_level === "Medium") {
            showWarningPopup(data);
        } else {
            // Optional: Safe toaster could be added, but not strictly needed 
            // since users usually don't want popups on every single safe site.
            console.log("PhishShield: This page is secure.");
        }
    } else {
        console.warn("PhishShield: Failed to scan url. Is the backend running?", response.error);
    }
});

function blockPage(data) {
    // Stop webpage from loading further and stop execution
    window.stop();
    
    // Create new HTML to replace the entire document body
    document.documentElement.innerHTML = `
        <head>
            <title>Blocked by PhishShield</title>
            <style>
                body, html {
                    margin: 0; padding: 0; height: 100%; width: 100%;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    background-color: #fce4e4;
                    color: #d10000;
                    display: flex; flex-direction: column; align-items: center; justify-content: center;
                }
                .phishshield-block-container {
                    background: white; border-radius: 12px;
                    box-shadow: 0 10px 30px rgba(209, 0, 0, 0.2);
                    padding: 40px; max-width: 600px; text-align: center;
                    border: 2px solid #ff4d4d;
                }
                h1 { font-size: 32px; margin-bottom: 20px; }
                p { font-size: 18px; line-height: 1.5; color: #333; margin-bottom: 25px; }
                .details {
                    background: #f9f9f9; padding: 15px; border-radius: 8px; text-align: left;
                    font-size: 14px; color: #555; margin-bottom: 30px;
                }
                ul { margin-top: 10px; padding-left: 20px; }
                li { margin-bottom: 5px; }
                button {
                    background: #d10000; color: white; border: none; padding: 12px 24px;
                    font-size: 16px; font-weight: bold; border-radius: 6px; cursor: pointer;
                    transition: background 0.3s ease;
                }
                button:hover { background: #a30000; }
                .ignore-link {
                    display: block; margin-top: 15px; color: #888; font-size: 12px; text-decoration: underline; cursor: pointer;
                }
            </style>
        </head>
        <body>
            <div class="phishshield-block-container">
                <h1>🚨 DECEPTIVE SITE AHEAD 🚨</h1>
                <p>PhishShield has blocked access to this page because it matches known phishing patterns. Attackers might be trying to trick you into doing something dangerous like installing software or revealing your personal information.</p>
                <div class="details">
                    <strong>URL:</strong> ${data.url} <br/>
                    <strong>Risk Score:</strong> ${data.risk_score} / 100 <br/>
                    <strong>Reasons Detected:</strong>
                    <ul>
                        ${data.reasons && data.reasons.length > 0 ? data.reasons.map(r => `<li>${r}</li>`).join("") : "<li>Suspicious domain patterns detected.</li>"}
                    </ul>
                </div>
                <button onclick="window.history.length > 1 ? window.history.back() : window.close()">Go Back to Safety</button>
            </div>
        </body>
    `;
}

function showWarningPopup(data) {
    const popup = document.createElement("div");
    popup.id = "phishshield-warning-popup";
    popup.innerHTML = `
        <div class="phishshield-popup-icon">⚠️</div>
        <div class="phishshield-popup-content">
            <div class="phishshield-popup-title">Suspicious Site Warning</div>
            <div class="phishshield-popup-body">
                PhishShield detected suspicious characteristics (Score: ${data.risk_score}/100) on this site. Please be careful when entering sensitive information.
            </div>
        </div>
        <button id="phishshield-popup-close">&times;</button>
    `;
    document.body.appendChild(popup);
    
    document.getElementById("phishshield-popup-close").addEventListener("click", () => {
        popup.style.opacity = '0';
        setTimeout(() => popup.remove(), 300);
    });
}
