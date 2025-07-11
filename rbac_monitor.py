import re
import time
from datetime import datetime
import smtplib
from email.message import EmailMessage
from kubernetes import client, config, watch
from collections import defaultdict

# Configuration
CHECK_INTERVAL = 60  # seconds
ATTEMPT_THRESHOLD = 3  # Number of denied attempts to trigger alert
TIME_WINDOW = 300  # seconds (5 minutes)
ALERT_EMAIL = "admin@example.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "alerts@example.com"
SMTP_PASS = "your_password"

# Track denied attempts by user
denied_attempts = defaultdict(list)

def send_alert(user, attempts, resource, verb):
    msg = EmailMessage()
    msg.set_content(f"Potential unauthorized access detected by user: {user}\n"
                    f"Attempts: {attempts}\nResource: {resource}\nAction: {verb}")
    msg['Subject'] = f"Kubernetes RBAC Alert: Unauthorized Access by {user}"
    msg['From'] = SMTP_USER
    msg['To'] = ALERT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"Alert sent for user: {user}")
    except Exception as e:
        print(f"Failed to send alert: {e}")

def parse_log_line(line):
    # Regex for RBAC DENY errors in API server logs
    pattern = r'(\S+\s+\d+\s+\d+:\d+:\d+)\s+.*RBAC DENY: user "([^"]+)"\s+.*resource "([^"]+)"\s+.*verb "([^"]+)"'
    match = re.match(pattern, line)
    if match:
        timestamp_str, user, resource, verb = match.groups()
        try:
            timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            return user, resource, verb, timestamp
        except ValueError:
            return None, None, None, None
    return None, None, None, None

def monitor_api_server_logs():
    try:
        # Load Kubernetes configuration
        config.load_kube_config()  # Assumes kubeconfig is set up
        v1 = client.CoreV1Api()
        pod_list = v1.list_namespaced_pod(namespace="kube-system", label_selector="component=kube-apiserver")
        
        if not pod_list.items:
            print("No API server pods found in kube-system namespace")
            return

        api_server_pod = pod_list.items[0].metadata.name
        w = watch.Watch()

        print(f"Monitoring API server logs from pod: {api_server_pod}")
        for event in w.stream(v1.read_namespaced_pod_log, name=api_server_pod, namespace="kube-system"):
            line = event
            user, resource, verb, timestamp = parse_log_line(line)
            if user and timestamp:
                current_time = datetime.now()
                # Clean up old attempts
                denied_attempts[user] = [t for t in denied_attempts[user] if (current_time - t).total_seconds() <= TIME_WINDOW]
                denied_attempts[user].append(timestamp)
                
                # Check if threshold exceeded
                if len(denied_attempts[user]) >= ATTEMPT_THRESHOLD:
                    print(f"Warning: Potential unauthorized access by {user} - {len(denied_attempts[user])} attempts on {resource} ({verb})")
                    send_alert(user, len(denied_attempts[user]), resource, verb)
                    denied_attempts[user].clear()  # Reset after alert

    except Exception as e:
        print(f"Error monitoring API server logs: {e}")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    print("Starting Kubernetes RBAC monitor")
    monitor_api_server_logs()