import json
import os
import bcrypt
from datetime import datetime, timedelta

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'user_data', 'users.json')
PASSWORD_EXPIRY_DAYS = 30
PASSWORD_HISTORY_COUNT = 3

def load_users():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_users(users):
    with open(DATA_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def is_password_expired(user):
    if 'created_at' not in user:
        return True
    created = datetime.fromisoformat(user['created_at'])
    return datetime.now() > created + timedelta(days=PASSWORD_EXPIRY_DAYS)

def is_password_reused(username, new_plain_password):
    users = load_users()
    for user in users:
        if user['username'].lower() == username.lower():
            history = user.get("password_history", [])
            for old_hash in history[-PASSWORD_HISTORY_COUNT:]:
                if bcrypt.checkpw(new_plain_password.encode(), old_hash.encode()):
                    return True
    return False

def update_password_history(username, new_hashed_password):
    users = load_users()
    for user in users:
        if user['username'].lower() == username.lower():
            if 'password_history' not in user:
                user['password_history'] = []
            user['password_history'].append(new_hashed_password)
            user['created_at'] = datetime.now().isoformat()
            break
    save_users(users)
