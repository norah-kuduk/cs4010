# Credential Breach Analysis with Have I Been Pwned (HIBP)

This project explores credential breaches using data from the [Have I Been Pwned API](https://haveibeenpwned.com/API/v3). It includes:
- An **interactive Dash dashboard** for visualizing trends and breach metadata.
- A **Google Colab notebook** for exploratory data analysis and prototyping.

## Project Overview

Cybersecurity breaches are increasingly common, often exposing sensitive user data like email addresses, passwords, and IP addresses. This project analyzes and visualizes data from HIBP to raise awareness and highlight trends in data breaches.

### Key Questions:
- How have breaches changed over time?
- What types of data are most commonly compromised?
- Which breaches affected the most users?
- How many breaches are verified vs. unverified?

## Repository Contents
```plaintext
/breach-analysis/
│
├── app.py                   # Dash dashboard source code
├── requirements.txt         # Python dependencies
├── screenshots/             # Folder with dashboard screenshots
├── breach_analysis.ipynb    # Google Colab notebook for data exploration
└── README.md                # Project documentation
```

## Installation

To run the dashboard locally:

```bash
git clone https://github.com/norah-kuduk/cs4016.git
cd cs4016
pip install -r requirements.txt
python3 app.py
```
Then visit http://127.0.0.1:8050 in your browser.


