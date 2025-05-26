import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'user_data', 'login_activity.log')

def log_attempt(username, success):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    status = "SUCCESS" if success else "FAILED"
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.now().isoformat()} | {username} | {status}\n")
