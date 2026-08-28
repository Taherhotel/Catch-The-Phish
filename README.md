🎣 Catch The Phish

AI-Powered Phishing Detection System

Catch The Phish is an intelligent phishing detection system that combines Machine Learning, web crawling, URL analysis, and threat intelligence to identify potentially malicious websites and URLs.

The project is designed to analyze URLs using multiple security signals rather than relying on a single indicator—helping detect phishing attempts through both static analysis and real-time threat intelligence.

⸻

🚨 The Problem

Phishing remains one of the most common cybersecurity threats, with attackers creating deceptive URLs and websites designed to steal credentials and sensitive information.

Traditional blacklist-based approaches can struggle to identify new or previously unseen phishing websites. Catch The Phish aims to address this challenge by combining AI/ML-based detection with real-time security intelligence.

⸻

🧠 How It Works

User URL
   │
   ▼
URL & Website Analysis
   │
   ├── 🔍 Feature Extraction
   ├── 🕷️ Content Analysis & Web Crawling
   ├── 🤖 ML Classification
   └── 🛡️ Threat Intelligence Checks
          │
          ▼
   Phishing Risk Assessment
          │
          ▼
     Safe / Suspicious / Malicious

The system analyzes multiple characteristics of a URL and website before generating a phishing assessment.

⸻

✨ Key Features

* 🤖 AI/ML-Based Detection — Uses machine learning classifiers to identify phishing URLs based on extracted features.
* 🔗 URL Feature Extraction — Analyzes URL characteristics and patterns associated with malicious websites.
* 🕷️ Dynamic Web Crawling — Examines website content to gather additional indicators for analysis.
* 🛡️ Threat Intelligence Integration — Leverages VirusTotal and AbuseIPDB to enrich detection with external security intelligence.
* ⚡ Static & Real-Time Analysis — Designed to work with both pre-existing datasets and live URL analysis.
* 🌐 Web-Based Interface — Provides an accessible interface for users to analyze potentially suspicious links.

⸻

🛠️ Tech Stack

* Python
* Machine Learning / AI
* Flask
* Web Scraping & Crawling
* VirusTotal API
* AbuseIPDB API
* HTML, CSS & JavaScript

⸻

📂 Project Structure

Catch-The-Phish/
│
├── app.py                  # Main application
├── features_extract.py     # URL and website feature extraction
├── myscrappy/              # Web crawling and scraping components
├── templates/              # Application templates
├── static/                 # Static assets
├── indian_banks.txt        # Reference data
└── requirements.txt        # Project dependencies

⸻

🚀 Getting Started

1. Clone the Repository

git clone https://github.com/Taherhotel/Catch-The-Phish.git
cd Catch-The-Phish

2. Install Dependencies

pip install -r requirements.txt

3. Configure API Keys

Configure the required API credentials for services such as VirusTotal and AbuseIPDB before running the application.

⚠️ Never commit API keys or sensitive credentials directly to the repository.

4. Run the Application

python app.py

Open the application in your browser and submit a URL for analysis.

⸻

🔐 Security Perspective

Catch The Phish was built with the idea that effective phishing detection requires a layered security approach.

Instead of trusting a single signal, the system combines:

* Machine learning predictions
* URL-based indicators
* Website and content analysis
* External threat intelligence

This approach helps create a more comprehensive view of potentially malicious URLs and demonstrates how AI can be applied to real-world cybersecurity problems.

⸻

🎯 What I Learned

Building Catch The Phish gave me hands-on experience with the intersection of AI and cybersecurity, including:

* Applying machine learning to security classification problems
* Extracting meaningful features from URLs and web content
* Working with real-world threat intelligence APIs
* Understanding phishing techniques and indicators of compromise
* Building an end-to-end security-focused web application

⸻

🔮 Future Improvements

* Improve model performance with larger and more diverse datasets
* Add explainable AI to show why a URL was flagged
* Develop a browser extension for real-time phishing protection
* Add continuous threat intelligence feeds
* Expand detection to include visual similarity and brand impersonation

⸻

👨‍💻 Author

Taher

If you found this project interesting, feel free to ⭐ the repository!
