import tkinter as tk
from tkinter import messagebox
import bcrypt
from utils.password_utils import check_password_strength
from utils.captcha_utils import generate_captcha, validate_captcha
from utils.db_utils import insert_user, validate_user
from utils.extras import is_password_reused, update_password_history
from utils.validation import is_valid_email, is_valid_username
from utils.activity_log import log_attempt
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
ENTRY_WIDTH = 30


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Infosis - Secure Authentication")
        self.geometry("420x640")
        self.configure(bg=BG_COLOR)
        self.resizable(False, False)
        self.show_login_screen()

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self.clear_window()
        LoginScreen(self)

    def show_register_screen(self):
        self.clear_window()
        RegisterScreen(self)


class ScrollableFrame(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, bg=BG_COLOR, highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=BG_COLOR)
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


class RegisterScreen:
    def __init__(self, parent):
        self.parent = parent
        self.fullname_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.email_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.confirm_password_var = tk.StringVar()
        self.captcha_answer_var = tk.StringVar()
        self.captcha_text = generate_captcha()
        self.create_widgets()

    def create_widgets(self):
        container = ScrollableFrame(self.parent)
        container.pack(fill="both", expand=True, padx=40)
        frame = container.scrollable_frame

        tk.Label(frame, text="🛡️ Register Secure Account", fg=HIGHLIGHT, bg=BG_COLOR, font=TITLE_FONT).pack(
            pady=(20, 20))

        self.labeled_entry(frame, "🧑 Full Name", self.fullname_var)
        self.labeled_entry(frame, "👤 Username", self.username_var)
        self.labeled_entry(frame, "📬 Email", self.email_var)
        self.password_entry = self.labeled_entry(frame, "🔐 Password", self.password_var, toggle=True)
        self.confirm_password_entry = self.labeled_entry(frame, "🔐 Confirm Password", self.confirm_password_var,
                                                         toggle=True)

        self.strength_label = tk.Label(frame, text="Password strength: ", fg=FG_COLOR, bg=BG_COLOR, font=FONT)
        self.strength_label.pack(pady=(5, 15), anchor="w")

        self.password_entry.bind("<KeyRelease>", self.update_strength)

        self.labeled_entry(frame, "🤖 CAPTCHA", self.captcha_answer_var)
        self.captcha_label = tk.Label(frame, text=self.captcha_text, fg=HIGHLIGHT, bg=BG_COLOR,
                                      font=("Courier", 22, "bold"))
        self.captcha_label.pack(pady=(0, 10))

        button_frame = tk.Frame(frame, bg=BG_COLOR)
        button_frame.pack(pady=(20, 20))
        self.styled_button(button_frame, "🔁 Reload CAPTCHA", self.reload_captcha).pack(pady=6)
        action_frame = tk.Frame(button_frame, bg=BG_COLOR)
        action_frame.pack(pady=10)

        register_btn = self.styled_button(action_frame, "✅ Register", self.register)
        back_btn = self.styled_button(action_frame, "⬅ Back", self.parent.show_login_screen)

        register_btn.grid(row=0, column=0, padx=5)
        back_btn.grid(row=0, column=1, padx=5)

    def labeled_entry(self, parent, label_text, variable, show=None, toggle=False):
        frame = tk.Frame(parent, bg=BG_COLOR)
        frame.pack(fill="x", pady=(5, 10))
        tk.Label(frame, text=label_text, fg=FG_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(anchor="w")
        entry = tk.Entry(frame, textvariable=variable, bg=ENTRY_BG, fg=FG_COLOR, insertbackground=FG_COLOR, font=FONT,
                         relief="flat", width=ENTRY_WIDTH, show=show)
        entry.pack(side="left", fill="x", expand=True)
        if toggle:
            btn = tk.Button(frame, text="👁", bg=BG_COLOR, fg=HIGHLIGHT, relief="flat",
                            command=lambda: self.toggle_visibility(entry, btn))
            btn.pack(side="right")
        return entry

    def styled_button(self, parent, text, command, width=14):
        btn = tk.Label(
            parent,
            text=text,
            bg="#1e88e5",
            fg="white",
            font=("Segoe UI", 11, "bold"),
            padx=16,
            pady=10,
            cursor="hand2",
            width=width,
            anchor="center"
        )
        btn.configure(relief="flat", bd=0)
        btn.bind("<Enter>", lambda e: btn.config(bg="#2196f3"))
        btn.bind("<Leave>", lambda e: btn.config(bg="#1e88e5"))
        btn.bind("<Button-1>", lambda e: command())
        btn.pack_propagate(False)
        return btn

    def toggle_visibility(self, entry, button):
        entry.config(show="" if entry.cget("show") == "*" else "*")

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

        if not all([fullname, username, email, password, confirm_password, captcha_input]):
            messagebox.showerror("Error", "All fields are required.")
            return
        if not is_valid_username(username):
            messagebox.showerror("Error", "Username must be at least 4 characters and alphanumeric.")
            return
        if not is_valid_email(email):
            messagebox.showerror("Error", "Invalid email address.")
            return
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
        strength, _ = check_password_strength(password)
        if strength == "Weak":
            messagebox.showwarning("Weak Password", "Your password is weak. Please strengthen it.")
            return
        if insert_user(fullname, username, email, password):
            update_password_history(username, password)
            messagebox.showinfo("Success", "User registered successfully!")
            self.parent.show_login_screen()
        else:
            messagebox.showerror("Error", "Username or email already exists.")


class LoginScreen:
    def __init__(self, parent):
        self.parent = parent
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.captcha_answer_var = tk.StringVar()
        self.captcha_text = generate_captcha()
        self.create_widgets()

    def create_widgets(self):
        container = ScrollableFrame(self.parent)
        container.pack(fill="both", expand=True, padx=40)
        frame = container.scrollable_frame

        tk.Label(frame, text="🔒 Secure Login", fg=HIGHLIGHT, bg=BG_COLOR, font=TITLE_FONT).pack(pady=(20, 20))

        self.labeled_entry(frame, "👤 Username", self.username_var)
        self.password_entry = self.labeled_entry(frame, "🔐 Password", self.password_var, toggle=True)
        self.labeled_entry(frame, "🤖 CAPTCHA", self.captcha_answer_var)

        self.captcha_label = tk.Label(frame, text=self.captcha_text, fg=HIGHLIGHT, bg=BG_COLOR,
                                      font=("Courier", 22, "bold"))
        self.captcha_label.pack(pady=(0, 10))

        button_frame = tk.Frame(frame, bg=BG_COLOR)
        button_frame.pack(pady=(20, 20))

        self.styled_button(button_frame, "🔁 Reload CAPTCHA", self.reload_captcha).pack(pady=6)

        action_frame = tk.Frame(button_frame, bg=BG_COLOR)
        action_frame.pack(pady=10)

        self.styled_button(action_frame, "✅ Login", self.login).pack(side="left", padx=5)
        self.styled_button(action_frame, "➡ Register", self.parent.show_register_screen).pack(side="right", padx=5)

    def labeled_entry(self, parent, label_text, variable, show=None, toggle=False):
        frame = tk.Frame(parent, bg=BG_COLOR)
        frame.pack(fill="x", pady=(5, 10))
        tk.Label(frame, text=label_text, fg=FG_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(anchor="w")
        entry = tk.Entry(frame, textvariable=variable, bg=ENTRY_BG, fg=FG_COLOR, insertbackground=FG_COLOR, font=FONT,
                         relief="flat", width=ENTRY_WIDTH, show=show)
        entry.pack(side="left", fill="x", expand=True)
        if toggle:
            btn = tk.Button(frame, text="👁", bg=BG_COLOR, fg=HIGHLIGHT, relief="flat",
                            command=lambda: self.toggle_visibility(entry, btn))
            btn.pack(side="right")
        return entry

    def styled_button(self, parent, text, command):
        btn = tk.Button(parent, text=text, command=command, bg=BUTTON_BG, fg="white", activebackground=BUTTON_ACTIVE,
                        activeforeground="white", font=FONT, relief="flat", padx=10, pady=6)
        return btn

    def toggle_visibility(self, entry, button):
        entry.config(show="" if entry.cget("show") == "*" else "*")

    def reload_captcha(self):
        self.captcha_text = generate_captcha()
        self.captcha_label.config(text=self.captcha_text)

    def login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        captcha_input = self.captcha_answer_var.get().strip()

        if not all([username, password, captcha_input]):
            messagebox.showerror("Error", "All fields are required.")
            return
        if not validate_captcha(self.captcha_text, captcha_input):
            messagebox.showerror("CAPTCHA", "Incorrect CAPTCHA.")
            self.reload_captcha()
            return
        if validate_user(username, password):
            log_attempt(username, True)
            messagebox.showinfo("Success", "Login successful!")
        else:
            log_attempt(username, False)
            messagebox.showerror("Login Failed", "Incorrect username or password.")


if __name__ == "__main__":
    app = App()
    app.mainloop()
