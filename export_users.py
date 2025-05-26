import sqlite3
import csv
import os

DB_PATH = os.path.join('user_data', 'users.db')
EXPORT_PATH = os.path.join('user_data', 'users_export.csv')

def export_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, fullname, username, email, created_at FROM users")
    rows = cursor.fetchall()
    conn.close()

    with open(EXPORT_PATH, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Full Name", "Username", "Email", "Created At"])
        writer.writerows(rows)

    print(f"✅ Export complete: {EXPORT_PATH}")

if __name__ == "__main__":
    export_users()
