chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    let url = tabs[0].url;

    // Send message to background script to avoid any popup CORS issues and ensure reuse
    chrome.runtime.sendMessage({ action: "scanURL", url: url }, function(response) {
        let status = document.getElementById("status");
        let details = document.getElementById("details");
        let spinner = document.getElementById("loadingSpinner");
        let resultIcon = document.getElementById("resultIcon");
        let card = document.getElementById("statusCard");

        spinner.style.display = "none";
        resultIcon.style.display = "block";

        if (response && response.success) {
            const data = response.result;
            
            details.innerText = `Score: ${data.risk_score}/100`;

            if (data.is_phishing || data.risk_level === "High") {
                status.innerHTML = "Phishing Website Detected";
                status.className = "high";
                resultIcon.innerHTML = "❌";
                document.body.className = "high-bg";
            } else if (data.risk_level === "Medium") {
                status.innerHTML = "Suspicious Website";
                status.className = "medium";
                resultIcon.innerHTML = "⚠️";
                document.body.className = "medium-bg";
            } else {
                status.innerHTML = "Safe Website";
                status.className = "safe";
                resultIcon.innerHTML = "✅";
                document.body.className = "safe-bg";
            }
        } else {
            status.innerHTML = "Analysis Failed";
            details.innerText = "Is the backend API running?";
            resultIcon.innerHTML = "🔌";
            status.className = "medium";
        }
    });
});
