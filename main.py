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

BG_COLOR = "#121212"
FG_COLOR = "#e0e0e0"
ENTRY_BG = "#1f1f1f"
HIGHLIGHT = "#03dac6"
BUTTON_BG = "#1e88e5"
BUTTON_ACTIVE = "#1565c0"
FONT = ("Segoe UI", 14)
LABEL_FONT = ("Segoe UI", 11)
TITLE_FONT = ("Segoe UI", 16, "bold")
ENTRY_WIDTH = 36
ENTRY_PADY = 10
BTN_BG = "#1f8ef1"
BTN_FG = "white"
BTN_ACTIVE = "#1565c0"
BTN_FONT = ("Segoe UI", 11, "bold")


def authenticate(username, password):
    for user in load_users():
        if user["username"].lower() == username.lower():
            return bcrypt.checkpw(password.encode(), user["password_hash"].encode())
    return False

class RegistrationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Infosis - Secure Registration")
        self.root.geometry("420x600")
        self.root.configure(bg=BG_COLOR)

        self.fullname_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.email_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.confirm_password_var = tk.StringVar()
        self.captcha_answer_var = tk.StringVar()
        self.captcha_text = ""

        self.create_widgets()

    def create_widgets(self):
        container = tk.Frame(self.root, bg=BG_COLOR)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container, bg=BG_COLOR, highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=BG_COLOR)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        #Adding the widgets in scrollable
        tk.Label(scrollable_frame, text="🛡️ Register Secure Account", fg=HIGHLIGHT, bg=BG_COLOR, font=TITLE_FONT).pack(
            pady=(20, 20))

        self.labeled_entry(scrollable_frame, "🧑 Full Name", self.fullname_var)
        self.labeled_entry(scrollable_frame, "👤 Username", self.username_var)
        self.labeled_entry(scrollable_frame, "📧 Email", self.email_var)
        self.password_entry = self.labeled_entry(scrollable_frame, "🔒 Password", self.password_var, show="*")
        self.labeled_entry(scrollable_frame, "🔒 Confirm Password", self.confirm_password_var, show="*")

        self.strength_label = tk.Label(scrollable_frame, text="Password strength:", fg=FG_COLOR, bg=BG_COLOR, font=FONT)
        self.strength_label.pack(pady=(5, 10))

        self.password_entry.bind("<KeyRelease>", self.update_strength)

        tk.Label(scrollable_frame, text="🤖 CAPTCHA", fg=FG_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack()
        self.captcha_label = tk.Label(scrollable_frame, text="", fg=HIGHLIGHT, bg=BG_COLOR,
                                      font=("Courier", 20, "bold"))
        self.captcha_label.pack(pady=5)

        self.reload_captcha()

        tk.Entry(scrollable_frame, textvariable=self.captcha_answer_var, bg=ENTRY_BG, fg=FG_COLOR,
                 insertbackground=FG_COLOR, font=FONT, relief="flat", width=ENTRY_WIDTH).pack(pady=(5, 15))

        self.styled_button(scrollable_frame, "🔁 Reload CAPTCHA", self.reload_captcha)
        self.styled_button(scrollable_frame, "✅ Register", self.register)
        self.styled_button(scrollable_frame, "🔐 Go to Login", self.switch_to_login)

    def bind_mousewheel(widget, target):
        widget.bind_all("<MouseWheel>", lambda e: target.yview_scroll(int(-1 * (e.delta / 120)), "units"))  # Windows
        widget.bind_all("<Button-4>", lambda e: target.yview_scroll(-1, "units"))  # Linux
        widget.bind_all("<Button-5>", lambda e: target.yview_scroll(1, "units"))  # Linux

    def labeled_entry(self, parent, label_text, variable, show=None):
        frame = tk.Frame(parent, bg=BG_COLOR)
        frame.pack(fill="x", padx=20, pady=(5, 10))

        tk.Label(frame, text=label_text, fg=FG_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(anchor="w")

        entry_frame = tk.Frame(frame, bg=BG_COLOR)
        entry_frame.pack(fill="x")

        entry = tk.Entry(entry_frame, textvariable=variable, bg=ENTRY_BG, fg=FG_COLOR,
                         insertbackground=FG_COLOR, font=FONT, relief="flat", show=show)
        entry.grid(row=0, column=0, sticky="ew")

        if show == "*":
            toggle_btn = tk.Button(entry_frame, text="👁", bg=BG_COLOR, fg=HIGHLIGHT,
                                   font=("Segoe UI", 10, "bold"), bd=0, relief="flat",
                                   command=lambda: self.toggle_visibility(entry, toggle_btn))
            toggle_btn.grid(row=0, column=1, padx=(5, 0))

        entry_frame.columnconfigure(0, weight=1)

        return entry

    def toggle_visibility(self, entry, button):
        if entry.cget('show') == '':
            entry.config(show='*')
            button.config(text='👁')
        else:
            entry.config(show='')
            button.config(text='🙈')

    def styled_button(self, parent, text, command):
        btn = tk.Button(parent, text=text, command=command, bg=BTN_BG, fg=BTN_FG,
                        activebackground=BTN_ACTIVE, activeforeground=BTN_FG,
                        font=BTN_FONT, relief="flat", cursor="hand2")
        btn.pack(fill="x", pady=(0, 10))
        return btn

    def update_strength(self, event=None):
        password = self.password_var.get()
        strength, _ = check_password_strength(password)
        self.strength_label.config(text=f"Password strength: {strength}")

    def reload_captcha(self):
        self.captcha_text = generate_captcha()
        self.captcha_label.config(text=self.captcha_text)

    def register(self):
        fullname = self.fullname_var.get().strip()
        username = self.username_var.get().strip()
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()
        confirm_password = self.confirm_password_var.get().strip()
        captcha_input = self.captcha_answer_var.get().strip()

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

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
        self.root.geometry("420x500")
        self.root.configure(bg=BG_COLOR)

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.captcha_answer_var = tk.StringVar()
        self.captcha_text = ""

        self.create_widgets()

    def create_widgets(self):
        container = tk.Frame(self.root, bg=BG_COLOR)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container, bg=BG_COLOR, highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=BG_COLOR)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Header
        tk.Label(scrollable_frame, text="🛡️ Register Secure Account", fg=HIGHLIGHT, bg=BG_COLOR, font=TITLE_FONT).pack(
            pady=(20, 20))

        # Input Fields
        self.labeled_entry(scrollable_frame, "🧑 Full Name", self.fullname_var)
        self.labeled_entry(scrollable_frame, "👤 Username", self.username_var)
        self.labeled_entry(scrollable_frame, "📧 Email", self.email_var)
        self.password_entry = self.labeled_entry(scrollable_frame, "🔒 Password", self.password_var, show="*")
        self.confirm_password_entry = self.labeled_entry(scrollable_frame, "🔒 Confirm Password",
                                                         self.confirm_password_var, show="*")

        # Password Strength Info here
        self.strength_label = tk.Label(scrollable_frame, text="Password strength:", fg=FG_COLOR, bg=BG_COLOR, font=FONT)
        self.strength_label.pack(pady=(5, 15), anchor="center")
        self.password_entry.bind("<KeyRelease>", self.update_strength)

        # CAPTCHA Section here
        captcha_section = tk.Frame(scrollable_frame, bg=BG_COLOR)
        captcha_section.pack(pady=(10, 10))

        tk.Label(captcha_section, text="🤖 CAPTCHA", fg=FG_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(anchor="center")

        self.labeled_entry(scrollable_frame, "🤖 CAPTCHA", self.captcha_answer_var)

        self.captcha_label = tk.Label(scrollable_frame, text="", fg=HIGHLIGHT, bg=BG_COLOR,
                                      font=("Courier", 22, "bold"))
        self.captcha_label.pack(pady=(0, 10))
        self.reload_captcha()
        tk.Entry(captcha_section, textvariable=self.captcha_answer_var, bg=ENTRY_BG, fg=FG_COLOR,
                 insertbackground=FG_COLOR, font=FONT, relief="flat", width=ENTRY_WIDTH).pack(pady=(0, 15))

        #Buttons Section here
        button_frame = tk.Frame(scrollable_frame, bg=BG_COLOR)
        button_frame.pack(pady=(5, 20))

        self.styled_button(button_frame, "🔁 Reload CAPTCHA", self.reload_captcha)
        self.styled_button(button_frame, "✅ Register", self.register)
        self.styled_button(button_frame, "🔐 Go to Login", self.switch_to_login)

    def labeled_entry(self, parent, label_text, variable, show=None):
        frame = tk.Frame(parent, bg=BG_COLOR)
        frame.pack(fill="x", padx=20, pady=(5, 10))

        tk.Label(frame, text=label_text, fg=FG_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(anchor="w")

        entry_frame = tk.Frame(frame, bg=BG_COLOR)
        entry_frame.pack(fill="x")

        entry = tk.Entry(entry_frame, textvariable=variable, bg=ENTRY_BG, fg=FG_COLOR,
                         insertbackground=FG_COLOR, font=FONT, relief="flat", width=ENTRY_WIDTH, show=show)
        entry.pack(side="left", fill="x", expand=True)

        if show == "*":
            toggle_btn = tk.Button(entry_frame, text="👁", command=lambda: self.toggle_visibility(entry, toggle_btn),
                                   bg=BG_COLOR, fg=HIGHLIGHT, bd=0, font=("Segoe UI", 10, "bold"), relief="flat")
            toggle_btn.pack(side="right")

        return entry

    def toggle_visibility(self, entry, button):
        if entry.cget('show') == '':
            entry.config(show='*')
            button.config(text='👁')
        else:
            entry.config(show='')
            button.config(text='🙈')

    def styled_button(self, text, command):
        tk.Button(self.root, text=text, command=command, bg=BUTTON_BG, fg="white", activebackground=BUTTON_ACTIVE, activeforeground="white", font=FONT, relief="flat", width=25, pady=6).pack(pady=6)

    def update_strength(self, event=None):
        password = self.password_var.get()
        strength, _ = check_password_strength(password)
        self.strength_label.config(text=f"Password strength: {strength}")

    def reload_captcha(self):
        self.captcha_text = generate_captcha()
        self.captcha_label.config(text=self.captcha_text)

    def switch_to_register(self):
        self.root.destroy()
        root = tk.Tk()
        RegistrationApp(root)
        root.mainloop()

    def login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        captcha_input = self.captcha_answer_var.get().strip()

        if not validate_captcha(self.captcha_text, captcha_input):
            messagebox.showerror("CAPTCHA", "Incorrect CAPTCHA.")
            self.reload_captcha()
            return

        if authenticate(username, password):
            messagebox.showinfo("Success", "Login successful!")
        else:
            messagebox.showerror("Failed", "Incorrect username or password.")

if __name__ == "__main__":
    root = tk.Tk()
    RegistrationApp(root)
    root.mainloop()
