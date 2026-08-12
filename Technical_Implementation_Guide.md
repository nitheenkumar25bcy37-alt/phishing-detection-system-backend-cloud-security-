# TECHNICAL IMPLEMENTATION GUIDE
## Building Your Phishing Detection System - Code Examples

---

## 🛠️ TECH STACK RECOMMENDED

```
Backend:
- Python 3.10+
- PyTorch / TensorFlow (ML models)
- FastAPI (API server)
- Redis (caching)

Frontend:
- React / Vue.js
- Browser Extension APIs (Chrome, Firefox)

Data:
- MongoDB (phishing patterns DB)
- Elasticsearch (fast search)

ML/NLP:
- Transformers (BERT/RoBERTa)
- scikit-learn
- NLTK / spaCy

Deployment:
- Docker / Kubernetes
- AWS / GCP / Azure
```

---

## 📝 CORE COMPONENT 1: URL ANALYZER

```python
import re
from urllib.parse import urlparse
import whois
import requests
from difflib import SequenceMatcher
import dns.resolver

class URLPhishingDetector:
    def __init__(self):
        self.suspicious_keywords = [
            'verify', 'confirm', 'login', 'secure', 'update',
            'alert', 'action', 'urgent', 'click'
        ]
        self.known_legitimate_domains = {
            'paypal.com', 'amazon.com', 'apple.com', 'microsoft.com',
            'google.com', 'opensea.io', 'uniswap.org', 'metamask.io'
        }
    
    def analyze_url(self, url):
        """
        Comprehensive URL analysis for phishing indicators
        Returns: {risk_score: 0-100, reasons: [], verdict: str}
        """
        risk_score = 0
        reasons = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Check 1: Homoglyph Attack Detection
            homoglyph_risk = self._detect_homoglyphs(domain)
            if homoglyph_risk > 0:
                risk_score += homoglyph_risk
                reasons.append(f"Homoglyph detected: Domain mimics legitimate site")
            
            # Check 2: Domain Age
            domain_age = self._check_domain_age(domain)
            if domain_age < 30:  # Less than 30 days old
                risk_score += 25
                reasons.append(f"Domain registered only {domain_age} days ago")
            
            # Check 3: SSL Certificate Validation
            ssl_valid = self._validate_ssl_cert(domain)
            if not ssl_valid:
                risk_score += 20
                reasons.append("Invalid or missing SSL certificate")
            
            # Check 4: Known Phishing Patterns
            pattern_match = self._check_phishing_patterns(url)
            if pattern_match:
                risk_score += 30
                reasons.append(f"URL matches known phishing pattern: {pattern_match}")
            
            # Check 5: Suspicious Redirects
            redirect_risk = self._check_redirects(url)
            if redirect_risk > 0:
                risk_score += redirect_risk
                reasons.append("URL contains suspicious redirects")
            
            # Normalize risk score to 0-100
            risk_score = min(100, risk_score)
            
            # Determine verdict
            if risk_score >= 70:
                verdict = "PHISHING"
            elif risk_score >= 40:
                verdict = "SUSPICIOUS"
            else:
                verdict = "SAFE"
            
            return {
                'risk_score': risk_score,
                'reasons': reasons,
                'verdict': verdict,
                'url': url,
                'domain': domain
            }
        
        except Exception as e:
            return {
                'risk_score': 50,
                'reasons': [f"Error analyzing URL: {str(e)}"],
                'verdict': "SUSPICIOUS",
                'url': url
            }
    
    def _detect_homoglyphs(self, domain):
        """
        Detect similar-looking domains (e.g., opensea.io vs openssea.io)
        Uses fuzzy string matching
        """
        for legit_domain in self.known_legitimate_domains:
            similarity = SequenceMatcher(None, domain, legit_domain).ratio()
            
            if 0.85 <= similarity < 1.0:  # Very similar but not identical
                return 40  # High risk score for homoglyph
        
        return 0
    
    def _check_domain_age(self, domain):
        """
        Check how old the domain is (newly created = suspicious)
        """
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            from datetime import datetime
            age_days = (datetime.now() - creation_date).days
            return age_days
        
        except:
            return 0  # Can't determine, assume okay
    
    def _validate_ssl_cert(self, domain):
        """
        Verify SSL certificate validity
        """
        try:
            response = requests.get(f"https://{domain}", timeout=5, verify=True)
            return True
        except:
            return False
    
    def _check_phishing_patterns(self, url):
        """
        Match against known phishing URL patterns
        """
        # Suspicious URL patterns from research
        patterns = [
            r'verify|confirm|login|secure|update',  # Urgency words in URL
            r'(\d+\.\d+\.\d+\.\d+)',  # IP addresses instead of domains
            r'%2e',  # URL encoded dot
            r'@',  # @ character (can hide true domain)
        ]
        
        for pattern in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return pattern
        
        return None
    
    def _check_redirects(self, url):
        """
        Check if URL redirects through suspicious intermediaries
        """
        try:
            response = requests.head(url, allow_redirects=False, timeout=5)
            if response.status_code in [301, 302, 307, 308]:  # Redirect
                redirect_url = response.headers.get('Location', '')
                if 'phish' in redirect_url or 'verify' in redirect_url:
                    return 35
            return 0
        except:
            return 0
```

---

## 📝 CORE COMPONENT 2: EMAIL CONTENT ANALYZER (NLP-Based)

```python
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer

class EmailPhishingDetector:
    def __init__(self):
        # Load pre-trained BERT model for phishing detection
        self.model_name = "bert-base-uncased"
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name, 
            num_labels=2  # Binary: phishing or not
        )
        
        # Sentiment analyzer for urgency detection
        self.sia = SentimentIntensityAnalyzer()
        
        # Known phishing keywords
        self.phishing_keywords = {
            'urgent': 10,
            'verify': 15,
            'confirm': 12,
            'unusual activity': 18,
            'click here': 14,
            'act now': 16,
            'suspended': 15,
            'authenticate': 12,
            'update information': 14,
            'limited time': 13,
            'secure your account': 14,
            'immediate action': 15
        }
    
    def analyze_email(self, email_subject, email_body, sender_email):
        """
        Comprehensive email analysis
        Returns: {risk_score: 0-100, reasons: [], verdict: str}
        """
        risk_score = 0
        reasons = []
        
        # Check 1: Keyword Analysis
        keyword_risk = self._analyze_keywords(email_subject, email_body)
        risk_score += keyword_risk['score']
        reasons.extend(keyword_risk['reasons'])
        
        # Check 2: Sentiment Analysis (Urgency)
        sentiment_risk = self._analyze_sentiment(email_body)
        risk_score += sentiment_risk['score']
        reasons.extend(sentiment_risk['reasons'])
        
        # Check 3: BERT Transformer Analysis
        bert_risk = self._bert_classification(email_body)
        risk_score += bert_risk['score']
        reasons.extend(bert_risk['reasons'])
        
        # Check 4: Sender Reputation
        sender_risk = self._check_sender_reputation(sender_email)
        risk_score += sender_risk['score']
        reasons.extend(sender_risk['reasons'])
        
        # Check 5: Permission/Authorization Requests
        permission_risk = self._check_suspicious_requests(email_body)
        risk_score += permission_risk['score']
        reasons.extend(permission_risk['reasons'])
        
        # Normalize
        risk_score = min(100, risk_score)
        
        # Verdict
        if risk_score >= 70:
            verdict = "PHISHING"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        
        return {
            'risk_score': risk_score,
            'reasons': reasons,
            'verdict': verdict,
            'sender': sender_email,
            'subject': email_subject
        }
    
    def _analyze_keywords(self, subject, body):
        """Detect known phishing keywords"""
        combined_text = (subject + " " + body).lower()
        score = 0
        matched_keywords = []
        
        for keyword, weight in self.phishing_keywords.items():
            if keyword in combined_text:
                score += weight
                matched_keywords.append(keyword)
        
        reasons = []
        if matched_keywords:
            reasons.append(f"Phishing keywords detected: {', '.join(matched_keywords)}")
        
        return {'score': min(40, score), 'reasons': reasons}
    
    def _analyze_sentiment(self, text):
        """Detect fear/urgency-based emotional manipulation"""
        scores = self.sia.polarity_scores(text)
        
        # Compound score: -1 (negative) to 1 (positive)
        # Phishing often uses negative emotions (fear)
        
        if scores['neg'] > 0.6:  # High negative sentiment
            return {
                'score': 25,
                'reasons': ["Email uses fear/negative emotions to pressure action"]
            }
        
        return {'score': 0, 'reasons': []}
    
    def _bert_classification(self, text):
        """
        Use BERT transformer for semantic understanding
        Trained on phishing/legitimate email dataset
        """
        try:
            # Tokenize and prepare text
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                max_length=512,
                truncation=True,
                padding=True
            )
            
            # Get predictions
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
            
            # Get probability
            probs = torch.softmax(logits, dim=1)
            phishing_prob = probs[0][1].item()  # Probability of phishing class
            
            score = int(phishing_prob * 40)  # Scale to 0-40
            
            reasons = []
            if phishing_prob > 0.7:
                reasons.append(f"Email content semantic analysis: {phishing_prob*100:.1f}% match to phishing patterns")
            
            return {'score': score, 'reasons': reasons}
        
        except Exception as e:
            return {'score': 0, 'reasons': []}
    
    def _check_sender_reputation(self, sender_email):
        """
        Check if sender's email domain is legitimate
        """
        domain = sender_email.split('@')[1] if '@' in sender_email else ''
        
        # Common legitimate domains (would connect to real-time verification in production)
        legitimate_domains = {
            'gmail.com', 'yahoo.com', 'outlook.com',  # Personal
            'paypal.com', 'amazon.com', 'apple.com',  # Companies
            'microsoft.com', 'google.com'
        }
        
        # Suspicious: free email claiming to be from company
        if domain not in legitimate_domains and any(keyword in sender_email 
            for keyword in ['paypal', 'amazon', 'apple', 'microsoft', 'stripe']):
            return {
                'score': 25,
                'reasons': [f"Sender claims to be from company but uses {domain} email"]
            }
        
        return {'score': 0, 'reasons': []}
    
    def _check_suspicious_requests(self, text):
        """
        Check for requests that legitimate companies never make
        """
        text_lower = text.lower()
        
        critical_requests = {
            'seed phrase': 50,      # NEVER ask for this
            'private key': 50,
            'password': 40,
            'credit card': 45,
            'social security': 45,
            'bank account': 40
        }
        
        score = 0
        detected = []
        
        for request, weight in critical_requests.items():
            if request in text_lower:
                score = max(score, weight)
                detected.append(request)
        
        reasons = []
        if detected:
            reasons.append(f"Email requests sensitive information: {', '.join(detected)}")
        
        return {'score': score, 'reasons': reasons}
```

---

## 📝 CORE COMPONENT 3: BLOCKCHAIN TRANSACTION ANALYZER

```python
from web3 import Web3
import json

class BlockchainPhishingDetector:
    def __init__(self, rpc_url="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.known_scam_addresses = set()  # Would load from database
        self.known_safe_contracts = {
            '0x1111111254fb6c44bac0bed2854e76f90643097d': 'OneInch',  # DEX aggregator
            '0xe592427a0aece92de3edee1f18e0157c05861564': 'Uniswap V3',
            '0x68b3465833fb72B5a828cCEEF89B87caba25bcD8': 'Uniswap V3 Router',
        }
        self.erc20_abi = [  # Minimal ERC20 ABI for checking transfers
            {
                "constant": True,
                "inputs": [],
                "name": "decimals",
                "outputs": [{"name": "", "type": "uint8"}],
                "type": "function"
            }
        ]
    
    def analyze_transaction(self, tx_data, user_address):
        """
        Simulate and analyze a pending transaction for phishing
        tx_data: {to, data, value} from transaction request
        """
        risk_score = 0
        reasons = []
        
        to_address = tx_data.get('to', '').lower()
        data = tx_data.get('data', '0x')
        value = tx_data.get('value', '0')
        
        # Check 1: Known Scam Contract
        if to_address in self.known_scam_addresses:
            risk_score += 50
            reasons.append("Destination contract is on phishing blacklist")
        
        # Check 2: Infinite Approval Detection
        approval_risk = self._detect_infinite_approvals(data)
        if approval_risk > 0:
            risk_score += approval_risk
            reasons.append("Transaction grants unlimited token approval (common phishing trick)")
        
        # Check 3: Transfer to Unusual Address
        if not to_address in self.known_safe_contracts:
            transfer_risk = self._analyze_transfer_risk(to_address)
            risk_score += transfer_risk['score']
            reasons.extend(transfer_risk['reasons'])
        
        # Check 4: Anomalous Value Transfer
        if int(value, 16) > 0:  # Value transfer detected
            value_wei = int(value, 16)
            if value_wei > Web3.to_wei(10, 'ether'):  # Large transfer
                risk_score += 30
                reasons.append(f"Large value transfer: {Web3.from_wei(value_wei, 'ether')} ETH")
        
        # Check 5: Function Signature Analysis
        sig_risk = self._analyze_function_signature(data)
        risk_score += sig_risk['score']
        reasons.extend(sig_risk['reasons'])
        
        risk_score = min(100, risk_score)
        
        # Verdict
        if risk_score >= 70:
            verdict = "DO NOT SIGN"
        elif risk_score >= 40:
            verdict = "REVIEW CAREFULLY"
        else:
            verdict = "LIKELY SAFE"
        
        return {
            'risk_score': risk_score,
            'reasons': reasons,
            'verdict': verdict,
            'to_address': to_address,
            'transaction_preview': self._format_transaction_preview(tx_data)
        }
    
    def _detect_infinite_approvals(self, data):
        """
        Detect ERC20 approve() calls with max uint256 (infinite approval)
        This is a common phishing pattern
        """
        # ERC20 approve function signature: approve(address spender, uint256 amount)
        if data.startswith('0x095ea7b3'):  # approve() selector
            # Extract amount (last 64 hex chars = 32 bytes)
            if len(data) >= 138:  # 0x + 8 + 64 + 64
                amount_hex = data[-64:]
                # Max uint256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                if amount_hex == 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff':
                    return 40  # High risk for infinite approval
        
        return 0
    
    def _analyze_transfer_risk(self, address):
        """Analyze if destination address looks suspicious"""
        score = 0
        reasons = []
        
        # Check if address is in user's contact list (would connect to wallet data)
        # For now, just check basic patterns
        
        # Red flag: Address created very recently
        try:
            account = self.w3.eth.get_balance(Web3.to_checksum_address(address))
            # Would check creation time on Etherscan API
        except:
            pass
        
        return {'score': score, 'reasons': reasons}
    
    def _analyze_function_signature(self, data):
        """
        Analyze what function is being called
        """
        if len(data) < 10:
            return {'score': 0, 'reasons': []}
        
        function_sig = data[:10]  # First 4 bytes (8 hex chars)
        
        # Known dangerous function signatures
        dangerous_sigs = {
            '0x095ea7b3': 'approve',          # ERC20 approve
            '0x095ea7b8': 'transferFrom',     # ERC20 transferFrom
            '0xa9059cbb': 'transfer',         # ERC20 transfer
            '0x23b872dd': 'transferFrom',     # ERC20 transferFrom (alternative)
        }
        
        if function_sig in dangerous_sigs:
            return {
                'score': 15,
                'reasons': [f"Calling potentially dangerous function: {dangerous_sigs[function_sig]}"]
            }
        
        return {'score': 0, 'reasons': []}
    
    def _format_transaction_preview(self, tx_data):
        """Human-readable transaction summary"""
        return {
            'destination': tx_data.get('to', 'N/A'),
            'value': Web3.from_wei(int(tx_data.get('value', '0'), 16), 'ether'),
            'data_length': len(tx_data.get('data', '0x')),
            'function_call': 'Complex contract interaction' if len(tx_data.get('data', '0x')) > 138 else 'Simple transaction'
        }
```

---

## 🔌 CORE COMPONENT 4: BROWSER EXTENSION (Frontend)

```javascript
// manifest.json
{
  "manifest_version": 3,
  "name": "Phishing Guard",
  "version": "1.0",
  "permissions": [
    "activeTab",
    "scripting",
    "storage",
    "tabs"
  ],
  "host_permissions": [
    "<all_urls>"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"]
    }
  ],
  "action": {
    "default_popup": "popup.html",
    "default_icon": "icon.png"
  }
}
```

```javascript
// content.js - Detects and analyzes emails on Gmail, Outlook, etc.

class PhishingGuard {
    constructor() {
        this.api_url = "https://your-api.com/analyze";
        this.cache = {};
    }
    
    async analyzeEmail(emailElement) {
        try {
            // Extract email components
            const email = this.extractEmailData(emailElement);
            
            // Send to backend API
            const response = await fetch(this.api_url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    subject: email.subject,
                    body: email.body,
                    sender: email.sender,
                    urls: email.urls
                })
            });
            
            const result = await response.json();
            
            // Display warning if phishing detected
            if (result.verdict === 'PHISHING') {
                this.displayPhishingWarning(emailElement, result);
            } else if (result.verdict === 'SUSPICIOUS') {
                this.displaySuspiciousWarning(emailElement, result);
            }
            
        } catch (error) {
            console.error('Phishing analysis error:', error);
        }
    }
    
    extractEmailData(emailElement) {
        return {
            subject: emailElement.querySelector('.subject')?.textContent || '',
            body: emailElement.querySelector('.body')?.textContent || '',
            sender: emailElement.querySelector('.sender')?.textContent || '',
            urls: Array.from(emailElement.querySelectorAll('a'))
                .map(a => a.href)
        };
    }
    
    displayPhishingWarning(emailElement, result) {
        const warning = document.createElement('div');
        warning.className = 'phishing-guard-warning critical';
        warning.innerHTML = `
            <div class="warning-header">
                🚨 PHISHING DETECTED (${result.risk_score}% confidence)
            </div>
            <div class="warning-reasons">
                ${result.reasons.map(r => `<p>• ${r}</p>`).join('')}
            </div>
            <div class="warning-actions">
                <button onclick="this.parentElement.style.display='none'">Dismiss</button>
                <button onclick="this.reportPhishing()">Report to Community</button>
            </div>
        `;
        
        emailElement.insertBefore(warning, emailElement.firstChild);
    }
    
    displaySuspiciousWarning(emailElement, result) {
        // Similar to above but with yellow/caution styling
    }
}

// Initialize on page load
const guard = new PhishingGuard();
guard.analyzeEmail(document.querySelector('.email'));
```

---

## 🚀 QUICK START: Setting Up Backend API

```python
# main.py - FastAPI server

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from url_analyzer import URLPhishingDetector
from email_analyzer import EmailPhishingDetector
from blockchain_analyzer import BlockchainPhishingDetector

app = FastAPI()

# Add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize detectors
url_detector = URLPhishingDetector()
email_detector = EmailPhishingDetector()
blockchain_detector = BlockchainPhishingDetector()

class EmailAnalysisRequest(BaseModel):
    subject: str
    body: str
    sender: str
    urls: list[str]

class TransactionAnalysisRequest(BaseModel):
    to: str
    data: str
    value: str
    user_address: str

@app.post("/analyze/email")
async def analyze_email(request: EmailAnalysisRequest):
    """Analyze email for phishing"""
    result = email_detector.analyze_email(
        request.subject,
        request.body,
        request.sender
    )
    
    # Also analyze URLs in email
    url_results = []
    for url in request.urls:
        url_result = url_detector.analyze_url(url)
        url_results.append(url_result)
        result['risk_score'] = max(result['risk_score'], url_result['risk_score'])
    
    result['url_analysis'] = url_results
    return result

@app.post("/analyze/transaction")
async def analyze_transaction(request: TransactionAnalysisRequest):
    """Analyze blockchain transaction for phishing"""
    result = blockchain_detector.analyze_transaction(
        {
            'to': request.to,
            'data': request.data,
            'value': request.value
        },
        request.user_address
    )
    return result

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---

## 📦 Installation & Deployment

```bash
# Install dependencies
pip install fastapi uvicorn transformers torch scikit-learn nltk
pip install python-whois requests

# Run locally
python main.py

# Deploy with Docker
docker build -t phishing-guard .
docker run -p 8000:8000 phishing-guard
```

---

## ✅ Testing the System

```python
# test_detector.py

from url_analyzer import URLPhishingDetector
from email_analyzer import EmailPhishingDetector

# Test 1: Homoglyph URL Detection
url_detector = URLPhishingDetector()
result = url_detector.analyze_url("https://openssea.io/verify")
print(f"Risk Score: {result['risk_score']}")  # Should be ~70+ (PHISHING)

# Test 2: Phishing Email
email_detector = EmailPhishingDetector()
result = email_detector.analyze_email(
    subject="URGENT: Verify Your Account Now",
    body="Your account has suspicious activity. Click here to verify: https://fake-paypal.com",
    sender="support@paypal-secure.com"
)
print(f"Verdict: {result['verdict']}")  # Should be PHISHING

# Test 3: Legitimate Email
result = email_detector.analyze_email(
    subject="Your Order Confirmation",
    body="Thank you for your purchase. Your order will be shipped within 2 business days.",
    sender="noreply@amazon.com"
)
print(f"Verdict: {result['verdict']}")  # Should be SAFE
```

---

## 🎯 Next Steps

1. **Train Custom Model**: Fine-tune BERT on phishing dataset (https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning)
2. **Build Database**: Collect known phishing URLs and emails
3. **Develop Frontend**: Create React dashboard
4. **Beta Test**: Release to 1,000 users
5. **Iterate**: Improve based on feedback

---

**Ready to start building? This code provides the foundation. Adapt to your needs!**
