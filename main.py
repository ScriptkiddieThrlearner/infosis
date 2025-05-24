import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import tkinter as tk
from tkinter import messagebox
import bcrypt

from utils.password_utils import check_password_strength
from utils.captcha_utils import generate_captcha, validate_captcha
from utils.db_utils import save_user, load_users
from utils.extras import is_password_reused, update_password_history, is_password_expired
from security import hash_password


class RegistrationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Infosis - Secure Registration")
        self.root.geometry("400x550")
        self.root.configure(bg="#0f0f1a")

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.captcha_answer_var = tk.StringVar()
        self.captcha_text = ""

        self.create_widgets()

    def styled_label(self, text, size=11, bold=False, color="#cfd3ec"):
        return tk.Label(self.root, text=text,
                        fg=color, bg="#0f0f1a",
                        font=("Segoe UI", size, "bold" if bold else "normal"))

    def styled_entry(self, variable, show=None):
        return tk.Entry(self.root, textvariable=variable,
                        show=show, bg="#1a1a2e", fg="white",
                        insertbackground="white", relief="flat",
                        font=("Consolas", 11), width=30)

    def styled_button(self, text, command):
        return tk.Button(self.root, text=text, command=command,
                         bg="#1e90ff", fg="white",
                         activebackground="#2c2c54", activeforeground="white",
                         relief="flat", width=20,
                         font=("Segoe UI", 10, "bold"))

    def create_widgets(self):
        self.styled_label("Register New Account", size=14, bold=True, color="#00ffe5").pack(pady=10)

        self.styled_label("Username").pack(pady=5)
        self.styled_entry(self.username_var).pack()

        self.styled_label("Password").pack(pady=5)
        self.password_entry = self.styled_entry(self.password_var, show="*")
        self.password_entry.pack()

        self.strength_label = self.styled_label("Password strength:")
        self.strength_label.pack()

        self.password_entry.bind("<KeyRelease>", self.update_strength)

        self.styled_label("CAPTCHA:").pack(pady=10)
        self.captcha_label = tk.Label(self.root, font=("Consolas", 16, "bold"),
                                      fg="#00ffcc", bg="#0f0f1a")
        self.captcha_label.pack()
        self.reload_captcha()

        self.styled_entry(self.captcha_answer_var).pack(pady=5)
        self.styled_button("Reload CAPTCHA", self.reload_captcha).pack(pady=5)
        self.styled_button("Register", self.register).pack(pady=10)
        self.styled_button("Go to Login", self.switch_to_login).pack(pady=5)

    def update_strength(self, event=None):
        password = self.password_var.get()
        strength, _ = check_password_strength(password)
        self.strength_label.config(text=f"Password strength: {strength}")

    def reload_captcha(self):
        self.captcha_text = generate_captcha()
        self.captcha_label.config(text=self.captcha_text)

    def register(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        captcha_input = self.captcha_answer_var.get().strip()

        if not username or not password or not captcha_input:
            messagebox.showerror("Error", "All fields are required.")
            return

        if not validate_captcha(self.captcha_text, captcha_input):
            messagebox.showerror("CAPTCHA", "Incorrect CAPTCHA.")
            self.reload_captcha()
            return

        if is_password_reused(username, password):
            messagebox.showerror("Error", "This password was recently used. Choose a new one.")
            return

        strength, feedback = check_password_strength(password)
        if strength == "Weak":
            messagebox.showwarning("Password Weak", "Your password is too weak:\n" + "\n".join(feedback))
            return

        hashed_pw = hash_password(password)
        success = save_user(username, hashed_pw)

        if success:
            update_password_history(username, hashed_pw)
            messagebox.showinfo("Success", "User registered successfully!")
            self.username_var.set("")
            self.password_var.set("")
            self.captcha_answer_var.set("")
            self.reload_captcha()
        else:
            messagebox.showerror("Error", "User already exists.")

    def switch_to_login(self):
        self.root.destroy()
        root = tk.Tk()
        LoginApp(root)
        root.mainloop()


class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Infosis - Login")
        self.root.geometry("400x400")
        self.root.configure(bg="#0f0f1a")

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.create_widgets()

    def styled_label(self, text, size=11, bold=False, color="#cfd3ec"):
        return tk.Label(self.root, text=text,
                        fg=color, bg="#0f0f1a",
                        font=("Segoe UI", size, "bold" if bold else "normal"))

    def styled_entry(self, variable, show=None):
        return tk.Entry(self.root, textvariable=variable,
                        show=show, bg="#1a1a2e", fg="white",
                        insertbackground="white", relief="flat",
                        font=("Consolas", 11), width=30)

    def styled_button(self, text, command):
        return tk.Button(self.root, text=text, command=command,
                         bg="#1e90ff", fg="white",
                         activebackground="#2c2c54", activeforeground="white",
                         relief="flat", width=20,
                         font=("Segoe UI", 10, "bold"))

    def create_widgets(self):
        self.styled_label("Login to Infosis", size=14, bold=True, color="#00ffe5").pack(pady=10)

        self.styled_label("Username").pack(pady=5)
        self.styled_entry(self.username_var).pack()

        self.styled_label("Password").pack(pady=5)
        self.styled_entry(self.password_var, show="*").pack()

        self.styled_button("Login", self.login).pack(pady=20)
        self.styled_button("Go to Register", self.switch_to_register).pack()

    def login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both fields.")
            return

        users = load_users()
        for user in users:
            if user["username"].lower() == username.lower():
                hashed_pw = user["password_hash"]
                if bcrypt.checkpw(password.encode(), hashed_pw.encode()):
                    if is_password_expired(user):
                        messagebox.showwarning("Password Expired", "Your password has expired. Please reset it.")
                    else:
                        messagebox.showinfo("Login Successful", f"Welcome back, {username}!")
                    return
        messagebox.showerror("Login Failed", "Invalid username or password.")

    def switch_to_register(self):
        self.root.destroy()
        root = tk.Tk()
        RegistrationApp(root)
        root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    RegistrationApp(root)
    root.mainloop()
