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
        container = tk.Frame(self.root, bg="#0f0f1a")
        container.pack(expand=True)

        def spacer(height=10):
            tk.Label(container, text="", bg="#0f0f1a").pack(pady=height)

        tk.Label(container, text="🛡️ Register Secure Account",
                 fg="#00ffe5", bg="#0f0f1a",
                 font=("Segoe UI", 16, "bold")).pack(pady=(0, 10))

        tk.Label(container, text="👤 Username", fg="#cfd3ec", bg="#0f0f1a", font=("Segoe UI", 11)).pack()
        tk.Entry(container, textvariable=self.username_var,
                 bg="#1a1a2e", fg="white", insertbackground="white",
                 font=("Consolas", 11), relief="flat", width=30).pack(pady=5)

        tk.Label(container, text="🔒 Password", fg="#cfd3ec", bg="#0f0f1a", font=("Segoe UI", 11)).pack()
        self.password_entry = tk.Entry(container, textvariable=self.password_var,
                                       show="*", bg="#1a1a2e", fg="white", insertbackground="white",
                                       font=("Consolas", 11), relief="flat", width=30)
        self.password_entry.pack(pady=5)

        self.strength_label = tk.Label(container, text="Password strength:",
                                       fg="#d3d3d3", bg="#0f0f1a", font=("Segoe UI", 10))
        self.strength_label.pack(pady=2)

        self.password_entry.bind("<KeyRelease>", self.update_strength)

        spacer(10)
        tk.Label(container, text="🤖 CAPTCHA", fg="#cfd3ec", bg="#0f0f1a", font=("Segoe UI", 11)).pack()
        self.captcha_label = tk.Label(container, font=("Courier New", 18, "bold"),
                                      fg="#00ffae", bg="#0f0f1a")
        self.captcha_label.pack()
        self.reload_captcha()

        tk.Entry(container, textvariable=self.captcha_answer_var,
                 bg="#1a1a2e", fg="white", insertbackground="white",
                 font=("Consolas", 11), relief="flat", width=30).pack(pady=(5, 15))

        btn_style = {
            "bg": "#1f8ef1", "fg": "white",
            "activebackground": "#2962ff", "activeforeground": "white",
            "relief": "flat", "font": ("Segoe UI", 10, "bold"),
            "bd": 0, "highlightthickness": 1,
            "highlightcolor": "#00ffae", "highlightbackground": "#00ffae",
            "width": 25, "padx": 10, "pady": 5
        }

        tk.Button(container, text="🔁 Reload CAPTCHA", command=self.reload_captcha, **btn_style).pack(pady=5)
        tk.Button(container, text="✅ Register", command=self.register, **btn_style).pack(pady=8)
        tk.Button(container, text="🔐 Go to Login", command=self.switch_to_login, **btn_style).pack(pady=5)

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
                         bg="#1f8ef1", fg="white",
                         activebackground="#2962ff", activeforeground="white",
                         relief="flat", width=25,
                         font=("Segoe UI", 10, "bold"),
                         bd=0, highlightthickness=1, highlightcolor="#00ffae", highlightbackground="#00ffae")

    def create_widgets(self):
        # Title
        tk.Label(self.root, text="🛡️Infosis",
                 fg="#00ffe5", bg="#0f0f1a",
                 font=("Segoe UI", 16, "bold")).pack(pady=(20, 10))

        #Username Field
        tk.Label(self.root, text="👤 Username", fg="#cfd3ec", bg="#0f0f1a", font=("Segoe UI", 11)).pack(pady=(5, 0))
        tk.Entry(self.root, textvariable=self.username_var,
                 bg="#1a1a2e", fg="white", insertbackground="white",
                 font=("Consolas", 11), relief="flat", width=30).pack(pady=5)

        #Password Field
        tk.Label(self.root, text="🔒 Password", fg="#cfd3ec", bg="#0f0f1a", font=("Segoe UI", 11)).pack(pady=(10, 0))
        self.password_entry = tk.Entry(self.root, textvariable=self.password_var,
                                       show="*", bg="#1a1a2e", fg="white", insertbackground="white",
                                       font=("Consolas", 11), relief="flat", width=30)
        self.password_entry.pack(pady=5)

        self.strength_label = tk.Label(self.root, text="Password strength:",
                                       fg="#d3d3d3", bg="#0f0f1a", font=("Segoe UI", 10))
        self.strength_label.pack(pady=2)

        self.password_entry.bind("<KeyRelease>", self.update_strength)

        # CAPTCHA
        tk.Label(self.root, text="🤖 CAPTCHA", fg="#cfd3ec", bg="#0f0f1a", font=("Segoe UI", 11)).pack(pady=(20, 0))
        self.captcha_label = tk.Label(self.root, font=("Courier New", 18, "bold"),
                                      fg="#00ffae", bg="#0f0f1a")
        self.captcha_label.pack()
        self.reload_captcha()

        tk.Entry(self.root, textvariable=self.captcha_answer_var,
                 bg="#1a1a2e", fg="white", insertbackground="white",
                 font=("Consolas", 11), relief="flat", width=30).pack(pady=(5, 15))

        # Buttons
        button_style = {
            "bg": "#1f8ef1", "fg": "white",
            "activebackground": "#2962ff", "activeforeground": "white",
            "relief": "flat", "font": ("Segoe UI", 10, "bold"),
            "bd": 0, "highlightthickness": 1,
            "highlightcolor": "#00ffae", "highlightbackground": "#00ffae",
            "width": 25, "padx": 10, "pady": 5
        }

        tk.Button(self.root, text="🔁 Reload CAPTCHA", command=self.reload_captcha, **button_style).pack(pady=5)
        tk.Button(self.root, text="✅ Register", command=self.register, **button_style).pack(pady=8)
        tk.Button(self.root, text="🔐 Go to Login", command=self.switch_to_login, **button_style).pack(pady=5)

    def switch_to_register(self):
        self.root.destroy()
        root = tk.Tk()
        RegistrationApp(root)
        root.mainloop()



if __name__ == "__main__":
    root = tk.Tk()
    RegistrationApp(root)
    root.mainloop()
