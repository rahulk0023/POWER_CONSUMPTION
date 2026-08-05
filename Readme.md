# ⚡ Power Consumption Monitoring & Anomaly Detection System

A Python-based desktop application for monitoring power consumption, detecting abnormal power usage, storing data in a local database, and visualizing trends through an interactive dashboard.

---

## 📌 Features

- 📊 Real-time power consumption monitoring
- 🚨 Automatic anomaly detection
- 📈 Interactive dashboard with graphs
- 💾 Local SQLite database support
- 📂 CSV data import and analysis
- 📝 Logging of detected anomalies
- 🖥️ Simple and user-friendly interface

---

## 🛠️ Technologies Used

- Python 3
- PyQt5
- Pandas
- NumPy
- Matplotlib
- SQLite
- Psutil

---

## 📁 Project Structure

```
POWER_CONSUMPTION/
│
├── assets/
├── data/
├── web/
├── app.py
├── dashboard.py
├── api_server.py
├── monitor.py
├── anomaly.py
├── database.py
├── logger.py
├── alert_system.py
├── utils.py
├── config.json
├── requirements.txt
└── README.md
```

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/rahulk0023/POWER_CONSUMPTION.git
```

### 2. Open the project

```bash
cd POWER_CONSUMPTION
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

**Windows**

```bash
venv\Scripts\activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the application

```bash
python app.py
```

---

## 📊 Dataset

The project uses CSV files stored inside the `data/` directory for monitoring and anomaly detection.

---

## 📷 Screenshots

Add screenshots of your application here.

Example:

```
screenshots/dashboard.png
screenshots/monitor.png
```

---

## 📌 Future Improvements

- User authentication
- Email alerts
- SMS notifications
- Machine Learning based anomaly detection
- Live IoT sensor integration
- Cloud database support

---

## 👨‍💻 Author

**Rahul Kumbhkar**

GitHub:
https://github.com/rahulk0023

---

## 📄 License

This project is developed for educational and learning purposes.