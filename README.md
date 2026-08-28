🎣 Catch The Phish

An AI-powered phishing detection system that analyzes URLs, website content, and threat intelligence to identify potentially malicious websites.

Catch The Phish is a cybersecurity project built to detect phishing URLs using a combination of Machine Learning, URL feature extraction, web crawling, and real-time threat intelligence.

The system goes beyond simple blacklist checking by analyzing multiple indicators associated with phishing attacks and combining them to help identify suspicious or malicious websites.

⸻

🚨 The Problem

Phishing websites are designed to impersonate legitimate services and trick users into revealing sensitive information such as passwords, banking details, and personal data.

Many phishing websites are short-lived and constantly changing, making it difficult for traditional detection methods to identify previously unseen threats.

Catch The Phish explores how AI/ML and cybersecurity techniques can work together to detect these threats through automated analysis.

⸻

🔍 How It Works

                         ┌─────────────────┐
                         │   Input URL     │
                         └────────┬────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   URL & Content Analysis │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       ┌──────────────┐   ┌──────────────┐  ┌───────────────┐
       │ URL Features │   │ Web Crawling │  │ Threat Intel  │
       └──────┬───────┘   └──────┬───────┘  └───────┬───────┘
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 ▼
                       ┌──────────────────┐
                       │  ML Classifier   │
                       └────────┬─────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Phishing Risk Result  │
                    └───────────────────────┘

⸻

✨ Features

* 🤖 Machine Learning-Based Detection
    Uses ML classifiers to identify patterns commonly associated with phishing URLs.
* 🔗 URL Feature Extraction
    Extracts and analyzes characteristics from URLs to identify suspicious patterns.
* 🕷️ Website Content Analysis
    Crawls and analyzes website content to gather additional indicators for detection.
* 🛡️ Threat Intelligence Integration
    Integrates external security intelligence from VirusTotal and AbuseIPDB.
* ⚡ Static & Real-Time Analysis
    Supports analysis using both existing data and live URL-based information.

⸻

🛠️ Tech Stack

Category	Technologies
Language	Python
AI/ML	Machine Learning
Backend	Flask
Security	VirusTotal, AbuseIPDB
Analysis	Web Crawling & URL Feature Extraction
Frontend	HTML, CSS, JavaScript

⸻

🚀 Getting Started

1. Clone the Repository

git clone https://github.com/Taherhotel/Catch-The-Phish.git
cd Catch-The-Phish

2. Create a Virtual Environment (Recommended)

python -m venv venv

Activate it:

Windows

venv\Scripts\activate

macOS/Linux

source venv/bin/activate

3. Install Dependencies

pip install -r requirements.txt

4. Configure API Keys

This project uses external threat intelligence services. Configure your API credentials before running the application.

⚠️ Security Note: Never hardcode or commit API keys to a public repository. Use environment variables or a local configuration file excluded through .gitignore.

5. Run the Application

python app.py

⸻

🧠 Detection Approach

Catch The Phish uses a multi-layered approach to phishing detection.

Instead of relying on a single indicator, the system combines:

URL Characteristics
        +
Website Content Analysis
        +
Machine Learning Classification
        +
Real-Time Threat Intelligence
        ↓
  Phishing Detection Result

This approach helps provide a broader security assessment and demonstrates the application of AI to real-world cybersecurity problems.

⸻

📊 Key Learnings

Building this project provided hands-on experience with:

* Applying Machine Learning to cybersecurity problems
* Understanding phishing techniques and malicious URL patterns
* Feature extraction and data analysis
* Web crawling and website analysis
* Integrating third-party threat intelligence APIs
* Building an end-to-end AI-powered security application

⸻

🔮 Future Improvements

* Improve detection using larger and more diverse datasets
* Add explainable AI to provide reasons behind predictions
* Develop a browser extension for real-time protection
* Add additional threat intelligence sources
* Implement continuous monitoring for suspicious domains

⸻

⚠️ Disclaimer

Catch The Phish is developed for educational and research purposes. Detection results should be treated as an additional security signal and not as a guarantee that a website is completely safe or malicious.

Always exercise caution when visiting unknown links or websites.

⸻

👨‍💻 Author

Taher

🔗 GitHub: https://github.com/Taherhotel

⸻

⭐ If you found this project interesting, consider giving the repository a star!
