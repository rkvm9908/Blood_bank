# 🩸 Blood Bank Management System

![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-Framework-092E20?logo=django&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?logo=sqlite&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?logo=css3&logoColor=white)
![Status](https://img.shields.io/badge/Project-Completed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📖 Overview

The Blood Bank Management System is a web-based application developed using **Python, Django, and SQLite3** to efficiently manage blood donors, blood inventory, and blood requests. The system provides a centralized platform for maintaining donor records, tracking blood availability, and processing blood requests in a secure and organized manner.

This application helps reduce manual paperwork, improve inventory management, and ensure quick access to blood availability information during emergencies.

---

## ✨ Features

- Donor Registration and Management
- Blood Inventory Tracking
- Blood Group Availability Search
- Blood Request Management
- Admin Dashboard
- User Authentication
- Blood Stock Monitoring
- Secure Database Management
- Responsive User Interface
- Real-Time Record Updates

---

## 🛠️ Tech Stack

### Backend
- Python
- Django

### Frontend
- HTML5
- CSS3
- Bootstrap
- JavaScript

### Database
- SQLite3

### Tools
- VS Code
- Git & GitHub

---

## 📂 Project Structure

```bash
Blood_Bank_Management_System/
│
├── blood_bank/
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
│   └── asgi.py
│
├── donor/
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── forms.py
│   └── admin.py
│
├── templates/
│   ├── base.html
│   ├── home.html
│   ├── donor_register.html
│   ├── blood_request.html
│   └── dashboard.html
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── db.sqlite3
├── manage.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Clone the Repository

```bash
git clone https://github.com/rkvm9908/Blood_bank.git
```

### Navigate to Project Directory

```bash
cd Blood_bank
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Virtual Environment

#### Windows

```bash
venv\Scripts\activate
```

#### Linux / Mac

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Apply Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### Create Superuser

```bash
python manage.py createsuperuser
```

### Run Development Server

```bash
python manage.py runserver
```

### Open Browser

```bash
http://127.0.0.1:8000/
```

---

## 🔄 System Workflow

### 1️⃣ Donor Registration

- Register donor information.
- Store donor details securely.
- Maintain donor database.

### 2️⃣ Blood Stock Management

- Add available blood units.
- Update blood inventory.
- Monitor blood availability by blood group.

### 3️⃣ Blood Request Processing

- Users submit blood requests.
- Admin reviews and manages requests.
- Inventory is updated accordingly.

### 4️⃣ Administration

- Manage donors and requests.
- Monitor blood stock.
- Generate reports and maintain records.

---

## 📊 System Architecture

```text
Donor Registration
        │
        ▼
Database Storage
        │
        ▼
Blood Inventory Management
        │
        ▼
Blood Request Processing
        │
        ▼
Admin Dashboard
        │
        ▼
Report Generation
```

---

## 🎯 Key Benefits

- Efficient donor management.
- Centralized blood inventory tracking.
- Faster blood request processing.
- Reduced manual record keeping.
- Improved emergency response.
- Secure and reliable data management.
- User-friendly interface.

---

## 🔒 Security Features

- User Authentication and Authorization
- Admin Access Control
- Secure Data Storage
- Input Validation
- Database Integrity Maintenance

---

## 📈 Future Enhancements

- Email Notifications
- SMS Alerts
- Mobile Application Integration
- Hospital Connectivity
- Blood Donation Camp Management
- Real-Time Blood Availability Dashboard
- Cloud Database Integration

---

## 💡 Learning Outcomes

- Django Project Structure and Development
- Database Design using SQLite3
- CRUD Operations in Django
- Authentication and Authorization
- Template Rendering and Routing
- Frontend and Backend Integration

---

## Author

**Mathuprasanth R K**
M.Sc Information Technology

GitHub: https://github.com/rkvm9908

---

## ⭐ Support

If you found this project useful, consider giving it a **Star ⭐** on GitHub.

---

## 📌 Project Goal

To develop a centralized blood bank management platform that efficiently manages donor information, blood inventory, and blood requests, ensuring timely availability of blood during emergencies and improving healthcare support through digital transformation.
