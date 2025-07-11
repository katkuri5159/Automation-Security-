import re
import time
from collections import defaultdict
from datetime import datetime
import smtplib
from email.message import EmailMessage
import os

# Configuration
LOG_FILE = "/var/log/auth.log"
CHECK_INTERVAL = 60  # seconds
ATTEMPT_THRESHOLD = 5  # Number of failed attempts to trigger alert
TIME_WINDOW = 300  # seconds (5 minutes)
ALERT_EMAIL = "admin@example.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "alerts@example.com"
SMTP_PASS = "your_password"

# Track failed attempts by IP
failed_attempts = defaultdict(list)

def send_alert(ip, attempts):
    msg = EmailMessage()
    msg.set_content(f"Potential brute-force attack detected from IP: {ip}\nAttempts: {attempts}")
    msg['Subject'] = f"SSH Brute-Force Alert from {ip}"
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"Alert sent for IP: {ip}")
    except Exception as e:
        print(f"Failed to send alert: {e}")

def parse_log_line(line):
    # Regex for failed SSH attempts
    pattern = r'(\S+\s+\d+\s+\d+:\d+:\d+)\s+.*sshd.*Failed password for.* from (\S+)'
    match = re.match(pattern, line)
    if match:
        timestamp_str, ip = match.groups()
        # Parse timestamp (format: Jul 10 17:30:45)
        try:
            timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            return ip, timestamp
        except ValueError:
            return None, None
    return None, None

def monitor_log():
    if not os.path.exists(LOG_FILE):
        print(f"Log file {LOG_FILE} not found")
        return

    while True:
        try:
            with open(LOG_FILE, 'r') as file:
                file.seek(0, os.SEEK_END)  # Go to end of file
                while True:
                    line = file.readline()
                    if not line:
                        time.sleep(1)  # Wait for new lines
                        continue

                    ip, timestamp = parse_log_line(line)
                    if ip and timestamp:
                        current_time = datetime.now()
                        # Clean up old attempts
                        failed_attempts[ip] = [t for t in failed_attempts[ip] if (current_time - t).total_seconds() <= TIME_WINDOW]
                        failed_attempts[ip].append(timestamp)
                        
                        # Check if threshold exceeded
                        if len(failed_attempts[ip]) >= ATTEMPT_THRESHOLD:
                            print(f"Warning: Potential brute-force from {ip} - {len(failed_attempts[ip])} attempts")
                            send_alert(ip, len(failed_attempts[ip]))
                            failed_attempts[ip].clear()  # Reset after alert

        except PermissionError:
            print(f"Permission denied accessing {LOG_FILE}. Run with sudo.")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    print(f"Starting SSH brute-force monitor on {LOG_FILE}")
    monitor_log()