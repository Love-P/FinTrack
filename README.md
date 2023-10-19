# FinTrack - Financial Tracking Web Application

FinTrack is a web application for tracking your financial transactions and managing your accounts using Plaid's API. It allows users to securely link their bank accounts, retrieve transaction data, and view their financial information.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Database](#database)
- [Routes](#routes)
- [Plaid API Integration](/guides/https://plaid.com/docs/api/)


## Features

- User registration and authentication.
- Securely link bank accounts using Plaid.
- View account balances and transaction history.
- Reset forgotten passwords.
- Database storage for user data and transactions.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.9.6 installed.
- SQLite database (configured in `config.py`).
- Plaid API credentials (update in `app.py`).

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Love-P/FinTrack.git

## Activate & Run:

1. Activate the virtual environment using these commands:

   ```bash
   source myenv/bin/activate  # for Linux/Mac
   myenv\Scripts\activate.bat  # for Windows

2. Install the required packages from requirement.txt:

   ```bash
   pip3 install -r requirements.txt

3. Run the application:

   ```bash
   python3 app.py
   # The application will be available on 127.0.0.1:5000/home
