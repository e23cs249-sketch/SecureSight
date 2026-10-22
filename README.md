# SecureSight AI — Web Security Configuration Assessment Platform

**A Python-based platform for assessing selected website security configurations through a dashboard, rule-based risk scoring, scan history, and report generation.**

| Project Information | Details |
|---|---|
| Project Name | SecureSight AI |
| Project Category | Cybersecurity |
| Developed By | Rajalakshmi S |
| Programming Language | Python 3.11 |
| Web Framework | Streamlit |
| Database | SQLite |
| Visualization | Plotly |
| Testing Framework | Python `unittest` |

## 1. Overview

SecureSight AI is a web-based cybersecurity assessment platform designed to help users understand selected security configurations of publicly accessible websites.

The application checks available website responses for HTTPS usage, TLS certificate information, HTTP security headers, and Cross-Origin Resource Sharing (CORS) configuration. It organizes the results into findings and calculates an indicative security score using predefined rules.

The platform also provides a dashboard, local scan-history storage, synthetic demonstration data, and report exports to support learning, assessment, and documentation.

> **Important:** SecureSight AI is a rule-based security assessment tool. It does not use a trained machine-learning model. Its score is an indicative summary of selected configuration checks, not a guarantee that a website is secure.

## 2. Problem Statement

Website security misconfigurations, such as missing security headers, inadequate HTTPS configuration, and overly permissive CORS settings, can be difficult for beginners to recognize and interpret.

SecureSight AI aims to make selected web security checks easier to understand by presenting findings, risk summaries, and assessment results through a centralized dashboard.

## 3. Objectives

- Assess selected security configurations of permitted public websites.
- Review HTTPS availability and available TLS certificate information.
- Inspect selected HTTP security headers.
- Identify potentially permissive CORS response configurations.
- Calculate an indicative security score using predefined rules.
- Store scan records and findings in a local SQLite database.
- Provide synthetic sample findings for demonstration and testing.
- Generate assessment reports in supported formats.
- Present findings through a Streamlit dashboard.

## 4. Key Features

- **Website security assessment:** Performs selected checks against a supplied website.
- **HTTPS and certificate checks:** Reviews HTTPS availability and verified TLS certificate metadata. When the TLS verifier provides evidence, it distinguishes expired certificates, hostname mismatches, and untrusted or invalid certificate chains; otherwise, it reports that verification could not be completed without assuming expiry.
- **HTTP security header analysis:** Checks selected response headers and reports potential configuration weaknesses.
- **CORS configuration review:** Evaluates response settings for potentially permissive cross-origin access.
- **Rule-based risk scoring:** Summarizes findings using predefined scoring rules.
- **Interactive dashboard:** Presents assessment results in a visual interface.
- **Scan history:** Uses SQLite for local storage of scan records and findings.
- **Report generation:** Supports CSV, Markdown, and HTML exports through the report-generation module.
- **Demo mode:** Uses synthetic sample findings to demonstrate the application without depending on a live scan.
- **Automated tests:** Includes unit tests for core functionality.

*Feature availability depends on the current implementation and configuration of the application.*

## 5. Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.11 | Core application logic |
| Streamlit | Web-based user interface |
| Requests | HTTP communication for website assessment |
| SQLite | Local storage for scan history and findings |
| Plotly | Data visualization |
| `unittest` | Automated testing using Python's standard library |

## 6. Project Structure

```text
SecureSight/
├── app.py
├── database.py
├── scanner.py
├── security_checks.py
├── risk_engine.py
├── report_generator.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
├── docs/
│   └── implementation_notes.md
├── sample_data/
│   └── demo_findings.json
└── tests/
    ├── __init__.py
    └── test_core.py
```

### Main Files and Directories

| File or Directory | Description |
|---|---|
| `app.py` | Launches the Streamlit application and manages the dashboard interface. |
| `database.py` | Handles SQLite database operations and persistence. |
| `scanner.py` | Contains website scanning and request-handling logic. |
| `security_checks.py` | Implements individual security configuration checks. |
| `risk_engine.py` | Calculates the assessment score and risk summary. |
| `report_generator.py` | Generates assessment reports in supported formats. |
| `requirements.txt` | Lists the Python dependencies required by the project. |
| `sample_data/demo_findings.json` | Contains synthetic findings for demonstrations. |
| `docs/implementation_notes.md` | Documents implementation details. |
| `tests/test_core.py` | Contains automated tests for core functionality. |

## 7. Dataset and Sample Data

SecureSight AI does not require an external machine-learning dataset because its assessment logic uses predefined security rules rather than model training.

The project includes synthetic demonstration findings in:

[`sample_data/demo_findings.json`](sample_data/demo_findings.json)

This file is intended for demonstration and testing. Its contents must not be interpreted as current security findings for real websites.

## 8. Installation and Setup

### Prerequisites

- Python 3.11 recommended
- `pip`
- A terminal or command prompt
- Internet access for permitted live website assessments

### Step 1: Obtain the Project

Clone the repository if it has been published to GitHub:

```bash
git clone https://github.com/e23cs249-sketch/SecureSight.git
cd SecureSight
```

Alternatively, download and extract the project files, then open a terminal in the directory containing `app.py` and `requirements.txt`.


### Step 2: Create a Virtual Environment

**Windows**

```bash
python -m venv .venv
.venv\Scripts\activate
```

If `python` is not recognized, try using the Python launcher:

```bash
py -m venv .venv
.venv\Scripts\activate
```

**macOS or Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If you used `py` to create the environment on Windows, you can also use `py -m pip` for package installation.

### Step 4: Run the Application

```bash
python -m streamlit run app.py
```

If Streamlit starts successfully, the terminal will display a local address, commonly:

`http://localhost:8501`

Open the displayed address in your browser. Keep the terminal running while using the application.

## 9. How to Use the Application

1. Start SecureSight AI using the command above.
2. Open the application in your browser.
3. Explore the dashboard and available features.
4. Use demonstration data to understand the interface without relying on a live website scan.
5. If performing a live assessment, enter a public website that you own or have explicit permission to assess.
6. Review the available security checks, findings, score, and risk summary.
7. Use scan history to review previously stored results, if available.
8. Export the assessment report in a supported format, if available.

The exact navigation and controls depend on the current implementation in `app.py`.

## 10. Running the Tests

The project uses Python's built-in `unittest` framework.

From the project root, run:

```bash
python -m unittest tests.test_core -v
```

This command runs the tests in `tests/test_core.py`.

To discover and run other compatible tests in the project, you can also use:

```bash
python -m unittest discover -v
```

Use the test output to determine whether the tests passed or failed. Do not report a test count or claim that all tests pass unless confirmed by an actual test run.

Automated tests help verify selected functionality but do not guarantee correct behavior for every website, network condition, or deployment environment.

## 11. Security, Privacy, and Responsible Use

- Assess only websites you own or have explicit permission to test.
- Use the platform for educational and authorized defensive security purposes.
- Do not treat the assessment score as a complete penetration test or a guarantee of security.
- Understand that findings may vary with server configuration, network conditions, redirects, and the responses available at scan time.
- Review findings manually before making security decisions.
- Keep local databases and files containing account or scan information private.
- Never commit passwords, access tokens, real user data, or other secrets to a public repository.
- Ensure `.gitignore` excludes virtual environments, local database files, generated sensitive reports, and other files that should not be published.
- Each redirect destination is validated before the scanner requests it. DNS rebinding and time-of-check/time-of-use risks are not fully mitigated because the validated IP address is not pinned to the connection.
- Review target-validation and redirect-handling protections before using the scanner in a deployed environment.

## 12. Limitations

- The platform checks selected web configuration indicators rather than every possible security weakness.
- Results depend on the responses and certificate information available during an assessment.
- Certificate expiry is reported only when verified certificate metadata or the TLS verifier's explicit expired-certificate result establishes it. If verification fails for another or unknown reason, the report identifies that reason when supported or states that certificate verification could not be completed.
- The risk score is rule-based and is not a statistically validated probability of compromise.
- Synthetic demonstration data does not represent a live assessment.
- The tool does not replace a professional security audit, penetration test, or comprehensive vulnerability assessment.
- Local SQLite storage is intended for the application's current storage design and may require additional configuration for multi-user production deployment.

## 13. Future Enhancements

Potential improvements include:

- Additional security configuration checks.
- More detailed and actionable remediation guidance.
- Expanded testing of network behavior and redirect-handling edge cases.
- Additional report formats and customization.
- Improved access control and deployment options.
- More comprehensive logging, monitoring, and assessment history management.

## 14. Conclusion

SecureSight AI provides an educational approach to understanding selected website security configurations. By combining automated checks, rule-based risk summaries, a dashboard, scan history, and report generation, the platform helps users interpret potential configuration weaknesses in a structured way.

The project demonstrates how Python, Streamlit, HTTP communication, local data storage, and automated testing can be combined to build a practical cybersecurity assessment application.

## 15. References

- [OWASP — Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Docs — HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [MDN Web Docs — Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [Python Documentation](https://docs.python.org/3/)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [Requests Documentation](https://requests.readthedocs.io/)
- [Plotly Python Documentation](https://plotly.com/python/)

---

**Project:** SecureSight AI  
**Category:** Cybersecurity  
**Developed by:** Rajalakshmi S
