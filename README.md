# Phishing Detection Tool

A comprehensive web application for detecting phishing attempts through URL analysis, machine learning, and various security checks.

## Features

### URL Analysis
- PhishTank integration for known phishing URLs
- WHOIS domain age verification
- SSL certificate validation
- Dynamic DNS detection
- Brand similarity detection
- Suspicious redirect analysis
- Content analysis for login forms and sensitive data

### Machine Learning
- BERT-based phishing detection model
- Confidence scoring
- Multiple feature analysis (URL length, subdomains, special characters, etc.)

### User Interface
- Interactive dashboard with detailed analysis
- Visual indicators for safe/malicious URLs
- Analysis history with export functionality
- Charts and statistics visualization

## Setup

### Backend (Python/FastAPI)
1. Navigate to the backend directory:
   ```bash
   cd backend-python
   ```
2. Create and activate virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the server:
   ```bash
   uvicorn app.main:app --reload
   ```

### Frontend (React/TypeScript)
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the development server:
   ```bash
   npm run dev
   ```

## Testing
- Backend tests are located in `backend-python/tests/`
- Run tests using pytest:
  ```bash
  cd backend-python
  pytest
  ```

## API Keys
The application requires the following API keys:
- PhishTank API key (optional)

## Technologies
- Backend: Python, FastAPI
- Frontend: React, TypeScript, Tailwind CSS
- ML: BERT, Transformers
- Visualization: Recharts