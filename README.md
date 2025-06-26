# Cyber-Threat-Intelligence-Dashboard
# CTI Dashboard - Cyber Threat Intelligence Platform

## Overview
The CTI Dashboard is a comprehensive web application designed for cybersecurity professionals to manage, analyze, and visualize threat intelligence data. Built with Python Flask and MongoDB, this dashboard provides powerful capabilities for IOC lookup, threat trend visualization, and CTI data export.

![CTI Dashboard Screenshot](dashboard.png)

## Key Features
### 1. IOC Lookup
- Search for IP addresses, domains, and file hashes
- View detailed threat analysis results
- Add custom tags to IOCs for categorization
- Visual threat level indicators (High/Medium/Low)

### 2. Threat Trends
- Interactive charts showing daily IOC submissions
- Malicious score trends over time
- Filter by date range for custom analysis
- Recent high-severity IOCs table

### 3. Data Export
- Export full CTI database in JSON or CSV format
- Preview first 10 records before downloading
- Streamlined data sharing capabilities

### 4. Dashboard Analytics
- Daily IOC count visualization
- Average malicious score tracking
- Real-time threat intelligence monitoring

## Technology Stack
- **Backend**: Python Flask
- **Database**: MongoDB
- **Frontend**: HTML5, Bootstrap 5, Chart.js
- **Deployment**: Docker compatible
- **Environment**: Python 3.9+

## Installation Guide

### Prerequisites
- Python 3.9+
- MongoDB (local or cloud instance)
- pip package manager

### Setup Instructions
```bash
# Clone the repository
git clone https://github.com/yourusername/cti-dashboard.git
cd cti-dashboard

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/MacOS
venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
echo "MONGO_URI=mongodb://localhost:27017/" > .env
echo "SECRET_KEY=your_secret_key_here" >> .env

# Run the application
python run.py





## 📁 Repository Structure
cti-dashboard/
├── backend/
│   ├── __init__.py       # Flask app factory
│   ├── routes.py         # All application routes
│   └── ...
├── frontend/
│   ├── home.html         # Dashboard homepage
│   ├── lookup.html       # IOC lookup interface
│   ├── trends.html       # Threat trends page
│   ├── export.html       # Data export interface
│   └── ...
├── requirements.txt      # Python dependencies
├── run.py                # Application entry point
├── .env                  # Environment configuration
└── README.md             # Project documentation
