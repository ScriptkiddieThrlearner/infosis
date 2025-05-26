import tkinter as tk
from tkinter import messagebox
import bcrypt
from utils.password_utils import check_password_strength
from utils.captcha_utils import generate_captcha, validate_captcha
from utils.db_utils import save_user, load_users
from utils.extras import is_password_reused, update_password_history
from security import hash_password

BG_COLOR = "#121212"
FG_COLOR = "#e0e0e0"
ENTRY_BG = "#1f1f1f"
HIGHLIGHT = "#03dac6"
BUTTON_BG = "#1e88e5"
BUTTON_ACTIVE = "#1565c0"
FONT = ("Segoe UI", 12)
LABEL_FONT = ("Segoe UI", 11)
TITLE_FONT = ("Segoe UI", 16, "bold")
ENTRY_WIDTH = 34

class RegistrationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Infosis - Secure Registration")
        self.root.geometry("420x620")
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

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        tk.Label(scrollable_frame, text="🛡️ Register Secure Account", fg=HIGHLIGHT, bg=BG_COLOR, font=TITLE_FONT).pack(pady=(20, 20))

        self.labeled_entry(scrollable_frame, "🧑 Full Name", self.fullname_var)
        self.labeled_entry(scrollable_frame, "👤 Username", self.username_var)
        self.labeled_entry(scrollable_frame, "📬 Email", self.email_var)
        self.password_entry = self.labeled_entry(scrollable_frame, "🔐 Password", self.password_var, toggle=True)
        self.confirm_password_entry = self.labeled_entry(scrollable_frame, "🔐 Confirm Password", self.confirm_password_var, toggle=True)

        self.strength_label = tk.Label(scrollable_frame, text="Password strength:", fg=FG_COLOR, bg=BG_COLOR, font=FONT)
        self.strength_label.pack(pady=(5, 15), anchor="center")
        self.password_entry.bind("<KeyRelease>", self.update_strength)

        self.labeled_entry(scrollable_frame, "🤖 CAPTCHA", self.captcha_answer_var)

        self.captcha_label = tk.Label(scrollable_frame, text="", fg=HIGHLIGHT, bg=BG_COLOR, font=("Courier", 22, "bold"))
        self.captcha_label.pack(pady=(0, 10))
        self.reload_captcha()

        button_frame = tk.Frame(scrollable_frame, bg=BG_COLOR)
        button_frame.pack(pady=(20, 40))

        self.styled_button(button_frame, "🔁 Reload CAPTCHA", self.reload_captcha)
        self.styled_button(button_frame, "✅ Register", self.register)
        self.styled_button(button_frame, "🔐 Go to Login", self.switch_to_login)

    def labeled_entry(self, parent, label_text, variable, show=None, toggle=False):
        frame = tk.Frame(parent, bg=BG_COLOR)
        frame.pack(fill="x", pady=(5, 10))
        tk.Label(frame, text=label_text, fg=FG_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(anchor="w")
        entry = tk.Entry(frame, textvariable=variable, bg=ENTRY_BG, fg=FG_COLOR,
                         insertbackground=FG_COLOR, font=FONT, relief="flat", width=ENTRY_WIDTH, show=show)
        entry.pack(side="left", fill="x", expand=True)
        if toggle:
            btn = tk.Button(frame, text="👁", bg=BG_COLOR, fg=HIGHLIGHT, relief="flat", command=lambda: self.toggle_visibility(entry, btn))
            btn.pack(side="right")
        return entry

    def styled_button(self, parent, text, command):
        tk.Button(parent, text=text, command=command,
                  bg=BUTTON_BG, fg="white",
                  activebackground=BUTTON_ACTIVE, activeforeground="white",
                  font=FONT, relief="flat", width=25, pady=6).pack(pady=6)

    def toggle_visibility(self, entry, button):
        if entry.cget("show") == "*":
            entry.config(show="")
            button.config(text="👁")
        else:
            entry.config(show="*")
            button.config(text="👁")

    def update_strength(self, event=None):
        password = self.password_var.get()
        strength, _ = check_password_strength(password)
        self.strength_label.config(text=f"Password strength: {strength}")

    def reload_captcha(self):
        self.captcha_text = generate_captcha()
        self.captcha_label.config(text=self.captcha_text)

    def register(self):
        username = self.username_var.get().strip()
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()
        confirm_password = self.confirm_password_var.get().strip()
        captcha_input = self.captcha_answer_var.get().strip()

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        if not validate_captcha(self.captcha_text, captcha_input):
            messagebox.showerror("CAPTCHA", "Incorrect CAPTCHA.")
            self.reload_captcha()
            return

        if is_password_reused(username, password):
            messagebox.showerror("Error", "Password recently used. Try another.")
            return

        strength, feedback = check_password_strength(password)
        if strength == "Weak":
            messagebox.showwarning("Weak Password", "Your password is weak. Please strengthen it.")
            return

        hashed_pw = hash_password(password)
        if save_user(username, hashed_pw):
            update_password_history(username, hashed_pw)
            messagebox.showinfo("Success", "User registered successfully!")
            self.switch_to_login()
        else:
            messagebox.showerror("Error", "Username already exists.")

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

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        tk.Label(scrollable_frame, text="🔐 Login to Infosis", fg=HIGHLIGHT, bg=BG_COLOR, font=TITLE_FONT).pack(pady=(20, 20))

        self.labeled_entry(scrollable_frame, "👤 Username", self.username_var)
        self.password_entry = self.labeled_entry(scrollable_frame, "🔐 Password", self.password_var, show="*", toggle=True)

        tk.Label(scrollable_frame, text="🤖 CAPTCHA", fg=FG_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(pady=(15, 2))
        self.captcha_label = tk.Label(scrollable_frame, text="", fg=HIGHLIGHT, bg=BG_COLOR, font=("Courier", 22, "bold"))
        self.captcha_label.pack()
        self.reload_captcha()

        self.labeled_entry(scrollable_frame, "", self.captcha_answer_var)

        button_frame = tk.Frame(scrollable_frame, bg=BG_COLOR)
        button_frame.pack(pady=(20, 40))

        self.styled_button(button_frame, "🔁 Reload CAPTCHA", self.reload_captcha)
        self.styled_button(button_frame, "✅ Login", self.login)
        self.styled_button(button_frame, "🔄 Back to Register", self.switch_to_register)

    def labeled_entry(self, parent, label_text, variable, show=None, toggle=False):
        frame = tk.Frame(parent, bg=BG_COLOR)
        frame.pack(fill="x", pady=(5, 10))
        if label_text:
            tk.Label(frame, text=label_text, fg=FG_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(anchor="w")
        entry = tk.Entry(frame, textvariable=variable, bg=ENTRY_BG, fg=FG_COLOR,
                         insertbackground=FG_COLOR, font=FONT, relief="flat", width=ENTRY_WIDTH, show=show)
        entry.pack(side="left", fill="x", expand=True)
        if toggle:
            btn = tk.Button(frame, text="👁", bg=BG_COLOR, fg=HIGHLIGHT, relief="flat", command=lambda: self.toggle_visibility(entry, btn))
            btn.pack(side="right")
        return entry

    def styled_button(self, parent, text, command):
        tk.Button(parent, text=text, command=command,
                  bg=BUTTON_BG, fg="white",
                  activebackground=BUTTON_ACTIVE, activeforeground="white",
                  font=FONT, relief="flat", width=25, pady=6).pack(pady=6)

    def toggle_visibility(self, entry, button):
        if entry.cget("show") == "*":
            entry.config(show="")
            button.config(text="👁")
        else:
            entry.config(show="*")
            button.config(text="👁")

    def reload_captcha(self):
        self.captcha_text = generate_captcha()
        self.captcha_label.config(text=self.captcha_text)

    def login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        captcha_input = self.captcha_answer_var.get().strip()

        if not validate_captcha(self.captcha_text, captcha_input):
            messagebox.showerror("CAPTCHA", "Incorrect CAPTCHA.")
            self.reload_captcha()
            return

        for user in load_users():
            if user["username"].lower() == username.lower():
                if bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
                    messagebox.showinfo("Success", "Login successful!")
                    return

        messagebox.showerror("Login Failed", "Incorrect username or password.")

    def switch_to_register(self):
        self.root.destroy()
        root = tk.Tk()
        RegistrationApp(root)
        root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    RegistrationApp(root)
    root.mainloop()
