import numpy as np
import logging
import smtplib
import requests
import subprocess
from email.mime.text import MIMEText
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from scapy.all import sniff, IP, TCP
from scapy.layers.http import HTTPRequest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Настройка логирования
logging.basicConfig(filename='ids.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Настройка отправки email
def send_email_alert(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'your_email@example.com'
    msg['To'] = 'admin@example.com'

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login('your_email@example.com', 'your_password')
        server.sendmail('your_email@example.com', ['admin@example.com'], msg.as_string())

# Настройка Slack
slack_client = WebClient(token='your_slack_token')
def send_slack_alert(message):
    try:
        response = slack_client.chat_postMessage(channel='#security-alerts', text=message)
    except SlackApiError as e:
        logging.error(f"Slack API error: {e.response['error']}")

# Данные для машинного обучения
packet_data = []

# Функция для обработки пакетов
def packet_handler(packet):
    global packet_data
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_len = len(packet)

        packet_data.append([packet_len, ip_src, ip_dst])

        if TCP in packet:
            if packet[TCP].dport == 80 and HTTPRequest in packet:
                http_layer = packet[HTTPRequest]
                url = http_layer[HTTPRequest].Host.decode() + http_layer[HTTPRequest].Path.decode()
                logging.info(f"HTTP Request: {ip_src} -> {url}")

                # Проверка на SQL-инъекцию
                if "SELECT" in http_layer[HTTPRequest].Path.decode().upper():
                    alert_message = f"Possible SQL Injection Attack from {ip_src} to {url}"
                    logging.warning(alert_message)
                    send_email_alert("Alert: SQL Injection Attack Detected", alert_message)
                    send_slack_alert(alert_message)

                # Проверка на XSS
                if "<script>" in http_layer[HTTPRequest].Path.decode().lower():
                    alert_message = f"Possible XSS Attack from {ip_src} to {url}"
                    logging.warning(alert_message)
                    send_email_alert("Alert: XSS Attack Detected", alert_message)
                    send_slack_alert(alert_message)

                # Проверка на RFI
                if "http://" in http_layer[HTTPRequest].Path.decode().lower() or "https://" in http_layer[HTTPRequest].Path.decode().lower():
                    alert_message = f"Possible RFI Attack from {ip_src} to {url}"
                    logging.warning(alert_message)
                    send_email_alert("Alert: RFI Attack Detected", alert_message)
                    send_slack_alert(alert_message)

# Запуск захвата пакетов
def start_sniffing():
    sniff(prn=packet_handler, store=0)

# Обучение модели для обнаружения аномалий
def train_model():
    global packet_data
    X = np.array(packet_data)[:,0].reshape(-1, 1)  # Используем только длину пакетов для простоты
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_scaled, np.zeros(X_scaled.shape[0]))  # Используем dummy labels, так как это unsupervised learning
    return model, scaler

# Функция для обнаружения аномалий
def detect_anomalies(model, scaler):
    global packet_data
    X = np.array(packet_data)[:,0].reshape(-1, 1)
    X_scaled = scaler.transform(X)
    predictions = model.predict(X_scaled)

    for i, prediction in enumerate(predictions):
        if prediction == -1:
            ip_src = packet_data[i][1]
            ip_dst = packet_data[i][2]
            alert_message = f"Anomaly detected: {ip_src} -> {ip_dst}"
            logging.warning(alert_message)
            send_email_alert("Alert: Anomaly Detected", alert_message)
            send_slack_alert(alert_message)

            # Запуск Metasploit для анализа атаки
            subprocess.run(["msfconsole", "-x", f"use auxiliary/scanner/http/sql_injection; set RHOSTS {ip_dst}; run"])

            # Отправка данных в SIEM
            send_to_siemon("IDS/IPS", "Anomaly Detected", alert_message)

# Интеграция с SIEM
def send_to_siemon(source, event_type, message):
    siem_url = "http://your_siem_server/api/events"
    siem_token = "your_siem_token"
    
    headers = {
        "Authorization": f"Bearer {siem_token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "source": source,
        "event_type": event_type,
        "message": message
    }
    
    try:
        response = requests.post(siem_url, headers=headers, json=payload)
        if response.status_code == 200:
            logging.info("Data sent to SIEM successfully.")
        else:
            logging.error(f"Failed to send data to SIEM. Status code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error occurred while sending data to SIEM: {str(e)}")

# Главная функция
def main():
    start_sniffing()
    model, scaler = train_model()
    detect_anomalies(model, scaler)

if __name__ == "__main__":
    main()
