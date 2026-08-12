// extension/popup.js

document.getElementById('scanBtn').addEventListener('click', async () => {
    const resultContainer = document.getElementById('resultContainer');
    const scoreDisplay = document.getElementById('scoreDisplay');
    const reasonsList = document.getElementById('reasonsList');
    const btn = document.getElementById('scanBtn');
    
    // UI Loading State
    btn.textContent = "Scanning...";
    resultContainer.style.display = "block";
    resultContainer.className = "";
    scoreDisplay.textContent = "Analyzing threat vectors...";
    reasonsList.innerHTML = "";

    try {
        // 1. Get the current active tab
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        // 2. Ask content.js for the webpage DOM features
        chrome.tabs.sendMessage(tab.id, { action: "get_dom_features" }, async (features) => {
            
            // If the content script hasn't loaded (e.g., on a chrome:// settings page)
            if (chrome.runtime.lastError || !features) {
                scoreDisplay.textContent = "Cannot scan this specific system page.";
                btn.textContent = "Analyze Current Page";
                return;
            }

            // 3. Send the payload to our FastAPI Python Backend
            try {
                const response = await fetch('http://127.0.0.1:8000/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url: tab.url,
                        page_features: features
                    })
                });

                const data = await response.json();

                // 4. Update the UI with the final Backend Decision
                scoreDisplay.textContent = `${data.action} (Score: ${data.score})`;
                resultContainer.className = data.action; // Applies SAFE, WARN, or BLOCK css class

                // Format the indicator reasons cleanly
                data.reasons.forEach(reason => {
                    let li = document.createElement('li');
                    // Replace underscores with spaces for readability
                    li.textContent = reason.replace(/_/g, ' ');
                    reasonsList.appendChild(li);
                });

            } catch (error) {
                scoreDisplay.textContent = "Backend Offline. Is Uvicorn running?";
                resultContainer.className = "BLOCK";
            }
            
            btn.textContent = "Analyze Current Page";
        });
    } catch (err) {
        console.error(err);
    }
});