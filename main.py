import tkinter as tk
from tkinter import messagebox
from utils.password_utils import check_password_strength
from utils.captcha_utils import generate_captcha, validate_captcha
from utils.db_utils import insert_user, validate_user
from utils.extras import is_password_reused, update_password_history
from utils.validation import is_valid_email, is_valid_username
from utils.activity_log import log_attempt


BG_COLOR = "#121212"
FG_COLOR = "#e0e0e0"
ENTRY_BG = "#1f1f1f"
HIGHLIGHT = "#03dac6"
BUTTON_BG = "#1e88e5"
BUTTON_HOVER = "#2196f3"
FONT = ("Segoe UI", 11)
LABEL_FONT = ("Segoe UI", 10)
TITLE_FONT = ("Segoe UI", 16, "bold")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Infosis - Secure Authentication")
        self.geometry("440x640")
        self.configure(bg=BG_COLOR)
        self.resizable(False, False)
        self.show_login()

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_window()
        LoginScreen(self)

    def show_register(self):
        self.clear_window()
        RegisterScreen(self)


class ScrollableFrame(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, bg=BG_COLOR, highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=BG_COLOR)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")


        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel_linux)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel_linux)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_mousewheel_linux(self, event):
        if event.num == 4:
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            self.canvas.yview_scroll(1, "units")



class BaseScreen:
    def styled_button(self, parent, text, command, width=16):
        btn = tk.Label(
            parent,
            text=text,
            bg=BUTTON_BG,
            fg="white",
            font=("Segoe UI", 11, "bold"),
            padx=10,
            pady=8,
            cursor="hand2",
            width=width,
        )
        btn.bind("<Enter>", lambda e: btn.config(bg=BUTTON_HOVER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BUTTON_BG))
        btn.bind("<Button-1>", lambda e: command())
        btn.pack_propagate(False)
        return btn

    def entry_with_label(self, parent, text, variable, show=None, toggle=False):
        frame = tk.Frame(parent, bg=BG_COLOR)
        frame.pack(fill="x", pady=8)
        tk.Label(frame, text=text, fg=FG_COLOR, bg=BG_COLOR, font=LABEL_FONT).pack(anchor="w")
        entry = tk.Entry(frame, textvariable=variable, bg=ENTRY_BG, fg=FG_COLOR,
                         insertbackground=FG_COLOR, font=FONT, relief="flat", show=show)
        entry.pack(fill="x", ipady=6)
        return entry

class LoginScreen(BaseScreen):
    def __init__(self, parent):
        self.parent = parent
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.captcha_answer = tk.StringVar()
        self.captcha_text = generate_captcha()
        self.build_ui()

    def build_ui(self):
        frame = ScrollableFrame(self.parent)
        frame.pack(fill="both", expand=True, padx=40)
        f = frame.scrollable_frame

        tk.Label(f, text="🔒 Secure Login", font=TITLE_FONT, bg=BG_COLOR, fg=HIGHLIGHT).pack(pady=20)

        self.entry_with_label(f, "👤 Username", self.username)
        self.entry_with_label(f, "🔐 Password", self.password, show="*")
        self.entry_with_label(f, "🤖 CAPTCHA", self.captcha_answer)

        tk.Label(f, text=self.captcha_text, font=("Courier", 22, "bold"), bg=BG_COLOR, fg=HIGHLIGHT).pack(pady=(0, 10))

        self.styled_button(f, "🔁 Reload CAPTCHA", self.reload_captcha).pack(pady=10)

        btn_frame = tk.Frame(f, bg=BG_COLOR)
        btn_frame.pack(pady=10)
        self.styled_button(btn_frame, "✅ Login", self.login).grid(row=0, column=0, padx=8)
        self.styled_button(btn_frame, "➡ Register", self.parent.show_register).grid(row=0, column=1, padx=8)

    def reload_captcha(self):
        self.captcha_text = generate_captcha()
        self.parent.show_login()

    def login(self):
        u = self.username.get().strip()
        p = self.password.get().strip()
        c = self.captcha_answer.get().strip()

        if not all([u, p, c]):
            messagebox.showerror("Error", "All fields are required.")
            return
        if not validate_captcha(self.captcha_text, c):
            messagebox.showerror("Error", "CAPTCHA does not match.")
            self.reload_captcha()
            return
        if validate_user(u, p):
            log_attempt(u, True)
            messagebox.showinfo("Success", "Login successful.")
        else:
            log_attempt(u, False)
            messagebox.showerror("Failed", "Invalid username or password.")



class RegisterScreen(BaseScreen):
    def __init__(self, parent):
        self.parent = parent
        self.fullname = tk.StringVar()
        self.username = tk.StringVar()
        self.email = tk.StringVar()
        self.password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        self.captcha_answer = tk.StringVar()
        self.captcha_text = generate_captcha()
        self.build_ui()

    def build_ui(self):
        frame = ScrollableFrame(self.parent)
        frame.pack(fill="both", expand=True, padx=40)
        f = frame.scrollable_frame

        tk.Label(f, text="🛡️ Register to Infosis", font=TITLE_FONT, bg=BG_COLOR, fg=HIGHLIGHT).pack(pady=20)

        self.entry_with_label(f, "👤 Full Name", self.fullname)
        self.entry_with_label(f, "🧑 Username", self.username)
        self.entry_with_label(f, "📧 Email", self.email)
        self.password_entry = self.entry_with_label(f, "🔒 Password", self.password, show="*")
        self.entry_with_label(f, "🔁 Confirm Password", self.confirm_password, show="*")

        self.password_entry.bind("<KeyRelease>", self.check_strength)
        self.strength_label = tk.Label(f, text="Password strength: ", bg=BG_COLOR, fg=FG_COLOR, font=FONT)
        self.strength_label.pack(anchor="w", pady=(5, 10))

        self.entry_with_label(f, "🤖 CAPTCHA", self.captcha_answer)
        tk.Label(f, text=self.captcha_text, font=("Courier", 22, "bold"), bg=BG_COLOR, fg=HIGHLIGHT).pack(pady=(0, 10))

        self.styled_button(f, "🔁 Reload CAPTCHA", self.reload_captcha).pack(pady=10)

        btn_frame = tk.Frame(f, bg=BG_COLOR)
        btn_frame.pack(pady=10)
        self.styled_button(btn_frame, "✅ Register", self.register).grid(row=0, column=0, padx=8)
        self.styled_button(btn_frame, "⬅ Login", self.parent.show_login).grid(row=0, column=1, padx=8)

    def check_strength(self, event=None):
        strength, _ = check_password_strength(self.password.get())
        self.strength_label.config(text=f"Password strength: {strength}")

    def reload_captcha(self):
        self.captcha_text = generate_captcha()
        self.parent.show_register()

    def register(self):
        fn = self.fullname.get().strip()
        un = self.username.get().strip()
        em = self.email.get().strip()
        pw = self.password.get().strip()
        cp = self.confirm_password.get().strip()
        ca = self.captcha_answer.get().strip()

        if not all([fn, un, em, pw, cp, ca]):
            messagebox.showerror("Error", "All fields are required.")
            return
        if not is_valid_username(un):
            messagebox.showerror("Error", "Invalid username format.")
            return
        if not is_valid_email(em):
            messagebox.showerror("Error", "Invalid email address.")
            return
        if pw != cp:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        if not validate_captcha(self.captcha_text, ca):
            messagebox.showerror("CAPTCHA", "Incorrect CAPTCHA.")
            self.reload_captcha()
            return
        if is_password_reused(un, pw):
            messagebox.showerror("Error", "Password recently used. Choose another.")
            return
        if check_password_strength(pw)[0] == "Weak":
            messagebox.showwarning("Weak Password", "Please use a stronger password.")
            return
        if insert_user(fn, un, em, pw):
            update_password_history(un, pw)
            messagebox.showinfo("Success", "Registration successful!")
            self.parent.show_login()
        else:
            messagebox.showerror("Error", "Username or email already exists.")

if __name__ == "__main__":
    app = App()
    app.mainloop()
