// extension/content.js

function extractPageFeatures() {
    // 1. Count total forms on the page
    const formCount = document.querySelectorAll('form').length;
    
    // 2. Count password input fields
    const passwordFields = document.querySelectorAll('input[type="password"]').length;
    
    // 3. Detect hidden iframes (often used for stealthy redirects or malware)
    let hiddenIframes = 0;
    document.querySelectorAll('iframe').forEach(iframe => {
        const style = window.getComputedStyle(iframe);
        if (style.display === 'none' || 
            style.visibility === 'hidden' || 
            iframe.width === '0' || 
            iframe.height === '0') {
            hiddenIframes++;
        }
    });

    // 4. Check if any form submits data to a different external server
    let hasExternalAction = false;
    const currentDomain = window.location.hostname;
    
    document.querySelectorAll('form').forEach(form => {
        const actionUrl = form.getAttribute('action');
        if (actionUrl && actionUrl.startsWith('http')) {
            try {
                const actionDomain = new URL(actionUrl).hostname;
                if (actionDomain !== currentDomain) {
                    hasExternalAction = true;
                }
            } catch (e) {
                // Ignore invalid URLs
            }
        }
    });

    // Return the exact JSON structure expected by the FastAPI backend
    return {
        form_count: formCount,
        password_fields: passwordFields,
        hidden_iframes: hiddenIframes,
        has_external_action: hasExternalAction
    };
}

// Listen for a message from our extension popup asking for this data
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "get_dom_features") {
        console.log("Phishing Shield: Extracting page features...");
        const features = extractPageFeatures();
        sendResponse(features);
    }
});