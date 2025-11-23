# AI-Powered Phishing URL Detection Web Application

A complete full-stack web application designed to detect phishing URLs in real time using machine learning. This project integrates a **React.js frontend**, **FastAPI backend**, and a **Random Forest classifier** trained on **85+ lexical, structural, and technical URL features**.

---

## Features
- Extracts 85+ URL features (length, digits, symbols, subdomains, age, keywords, etc.)
- ML model: Random Forest (≈97% accuracy)
- Real-time prediction via FastAPI
- Clean and responsive React.js interface
- Secure URL validation and API communication
- JSON-based data exchange
- Detects:
  - **Phishing Websites (0)**
  - **Legitimate Websites (1)**

---

## 📌 System Architecture

![Capture](https://github.com/user-attachments/assets/708871fe-5e5e-4d14-b78d-08e8ecb93b7e)


---

## 🧩 Components

### **1. React Frontend**
- Captures user-entered URLs  
- Validates URL format  
- Sends POST requests to backend  
- Displays results + loading status  
- Handles API/connection errors  

### **2. FastAPI Backend**
- `/health` → status check  
- `/predict-url` → phishing prediction  
- Extracts features using:
  - `urllib`
  - `tldextract`
  - `re`
- Loads ML model (`model.pkl`)
- Returns prediction + probability  

### **3. Machine Learning Model**
- Random Forest Classifier  
- Trained on 80+ handcrafted URL features  
- Labels:
  - `0 = Phishing`
  - `1 = Legitimate`  
---

<img width="521" height="380" alt="image" src="https://github.com/user-attachments/assets/29b562ae-d408-4209-9741-f701129562c1" />
<img width="527" height="243" alt="image" src="https://github.com/user-attachments/assets/6183bfc6-047d-46b3-9fcf-0dab9f60149e" />

## 🎨 Frontend (React.js)
<img width="653" height="306" alt="image" src="https://github.com/user-attachments/assets/cfc7c4e9-aa65-4c34-b166-c344a331f378" />

The frontend includes:

- Modern UI  
- URL validation  
- Loading indicators  
- Clear red/green prediction output  

Example API request:

```javascript
const res = await fetch("http://127.0.0.1:8000/predict-url", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ url }),
});

