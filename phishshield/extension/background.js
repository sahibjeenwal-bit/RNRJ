chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scanURL") {
        fetch("http://127.0.0.1:5001/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: request.url })
        })
        .then(response => response.json())
        .then(data => sendResponse({ result: data, success: true }))
        .catch(error => sendResponse({ success: false, error: error.message }));
        return true;  // Keep the message channel open for the async response
    }
});
