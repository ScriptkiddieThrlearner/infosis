import json
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'user_data', 'users.json')

def load_users():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_user(username, hashed_password):
    users = load_users()

    for user in users:
        if user['username'].lower() == username.lower():
            return False  # User already exists

    users.append({
        "username": username,
        "password_hash": hashed_password
    })

    with open(DATA_FILE, 'w') as f:
        json.dump(users, f, indent=4)

    return True
