#  Website Reputation Checker

A **Website Reputation Checker** is a Flask-based cybersecurity application that analyzes a website and evaluates its trustworthiness by examining multiple security indicators. Instead of simply labeling a website as "safe" or "phishing," the application generates a comprehensive reputation report with a risk score to help users make informed decisions before visiting a website.

##  Features

*  URL Validation
*  HTTPS Detection
*  SSL/TLS Certificate Validation
*  WHOIS Lookup
*  Domain Age Analysis
*  DNS Lookup (IP, Name Servers, MX Records)
*  Blacklist Checking
*  IP Reputation Analysis
*  Risk Score Generation
*  Detailed Website Reputation Report

##  Project Workflow

```text
User Input
     │
     ▼
URL Validation
     │
     ▼
Security Analysis
 ├── HTTPS Check
 ├── SSL Certificate Check
 ├── WHOIS Information
 ├── Domain Age
 ├── DNS Lookup
 ├── Blacklist Check
 ├── IP Reputation
 └── Risk Score Calculation
     │
     ▼
Website Reputation Report
```

##  Technology Stack

* **Frontend:** HTML, CSS, JavaScript
* **Backend:** Flask (Python)
* **URL Validation:** validators
* **WHOIS:** python-whois
* **DNS Lookup:** dnspython
* **SSL Verification:** ssl, socket
* **Threat Intelligence:** Google Safe Browsing API, VirusTotal API (Optional)
* **Database:** SQLite (Optional)

##  Project Structure

```text
Website-Reputation-Checker/
│
├── app.py
├── requirements.txt
│
├── analyzer/
│   ├── ssl_checker.py
│   ├── whois_checker.py
│   ├── dns_checker.py
│   ├── blacklist_checker.py
│   └── reputation_checker.py
│
├── templates/
│   ├── index.html
│   └── result.html
│
├── static/
│   └── style.css
│
├── reports/
└── database/
```

##  Installation

1. Clone the repository:

```bash
git clone https://github.com/your-username/Website-Reputation-Checker.git
cd Website-Reputation-Checker
```

2. Create a virtual environment:

```bash
python -m venv venv
```

3. Activate the virtual environment:

**Windows**

```bash
venv\Scripts\activate
```

**Linux/macOS**

```bash
source venv/bin/activate
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Run the application:

```bash
python app.py
```

6. Open your browser and visit:

```text
http://127.0.0.1:5000
```

##  Sample Report

```text
Website Reputation Report

Website:
https://example.com

HTTPS:
Yes

SSL:
Valid

Domain Age:
5 Years

Blacklist:
No

DNS:
Working

IP Reputation:
Good

Overall Score:
95/100

Status:
Trusted
```

##  Learning Outcomes

This project demonstrates practical cybersecurity concepts, including:

* Website Security Analysis
* WHOIS Investigation
* DNS Enumeration
* SSL/TLS Certificate Validation
* Threat Intelligence Integration
* IP Reputation Analysis
* Risk Assessment
* Secure Web Application Development

##  Future Enhancements

* Machine Learning-based website classification
* PDF report generation
* User authentication
* Scan history dashboard
* Real-time threat intelligence integration
* REST API support
* Email alerts for malicious websites

##  Contributing

Contributions, feature requests, and bug reports are welcome. Feel free to fork this repository and submit a pull request.

##  License

This project is intended for educational and research purposes. Please use it responsibly and only analyze websites that you are authorized to inspect.
