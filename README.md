# IDS
from scapy.all import sniff, IP, TCP
from scapy.layers.http import HTTPRequest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import logging
import smtplib
from email.mime.text import MIMEText
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logging.basicConfig(filename='ids.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def send_email_alert(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'your_email@example.com'
    msg['To'] = 'admin@example.com'

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login('your_email@example.com', 'your_password')
        server.sendmail('your_email@example.com', ['admin@example.com'], msg.as_string())

slack_client = WebClient(token='your_slack_token')
def send_slack_alert(message):
    try:
        response = slack_client.chat_postMessage(channel='#security-alerts', text=message)
    except SlackApiError as e:
        logging.error(f"Slack API error: {e.response['error']}")

packet_data = []

def packet_handler(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_len = len(packet)

        packet_data.append([packet_len, ip_src, ip_dst])

        if TCP in packet:
            if packet[TCP].dport == 80 and packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                url = http_layer.Host.decode() + http_layer.Path.decode()
                logging.info(f"HTTP Request: {ip_src} -> {url}")

            
                if "SELECT" in http_layer.Path.decode().upper():
                    alert_message = f"Possible SQL Injection Attack from {ip_src} to {url}"
                    logging.warning(alert_message)
                    send_email_alert("Alert: SQL Injection Attack Detected", alert_message)
                    send_slack_alert(alert_message)

              
                if "<script>" in http_layer.Path.decode().lower():
                    alert_message = f"Possible XSS Attack from {ip_src} to {url}"
                    logging.warning(alert_message)
                    send_email_alert("Alert: XSS Attack Detected", alert_message)
                    send_slack_alert(alert_message)

              
                if "http://" in http_layer.Path.decode().lower() or "https://" in http_layer.Path.decode().lower():
                    alert_message = f"Possible RFI Attack from {ip_src} to {url}"
                    logging.warning(alert_message)
                    send_email_alert("Alert: RFI Attack Detected", alert_message)
                    send_slack_alert(alert_message)


def start_sniffing():
    sniff(prn=packet_handler, store=0)


def train_model():
    global packet_data
    X = np.array(packet_data)[:,0].reshape(-1, 1) 
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_scaled, np.zeros(X_scaled.shape[0]))  
    return model, scaler


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

def main():
    start_sniffing()
    model, scaler = train_model()
    detect_anomalies(model, scaler)

if __name__ == "__main__":
    main()
