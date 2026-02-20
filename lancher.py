import tkinter as tk
from tkinter import messagebox, ttk
import webbrowser, json, os, base64, time, pyautogui, subprocess, ctypes, sys

# --- Ρυθμίσεις Χρωμάτων (Dark UI) ---
BG_MAIN = "#121212"
BG_CARD = "#1e1e1e"
BG_ENTRY = "#2c2c2c"
FG_TEXT = "#e0e0e0"
ACCENT_GREEN = "#4caf50"
ACCENT_BLUE = "#2196f3"
ACCENT_RED = "#f44336"

# --- Διόρθωση Μονοπατιού για το .exe ---
if getattr(sys, 'frozen', False):
    SCRIPT_DIR = os.path.dirname(sys.executable)
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

VAULT_PATH = os.path.join(SCRIPT_DIR, "vault.bin")
STATUS_PATH = os.path.join(SCRIPT_DIR, "status.sys")
ICON_PATH = os.path.join(SCRIPT_DIR, "manager-removebg-preview.ico")

# --- Συναρτήσεις Ασφαλείας ---
def get_usb_id():
    try:
        drive = os.path.splitdrive(SCRIPT_DIR)[0]
        output = subprocess.check_output(f"vol {drive}", shell=True).decode()
        return output.split()[-1].replace("-", "").encode()
    except: return b"hardware_error_99"

def derive_key(password, usb_id):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=usb_id, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def get_status_fernet(usb_id):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"status_salt", iterations=1000)
    key = base64.urlsafe_b64encode(kdf.derive(usb_id))
    from cryptography.fernet import Fernet
    return Fernet(key)

# --- Κύρια Εφαρμογή Launcher ---
class FinalLauncher:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Vault Launcher")
        self.root.geometry("400x550")
        self.root.configure(bg=BG_MAIN)
        self.usb_id = get_usb_id()
        
        # Προσθήκη Icon πάνω αριστερά
        try:
            if os.path.exists(ICON_PATH):
                self.root.iconbitmap(ICON_PATH)
        except: pass

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TProgressbar", thickness=10, troughcolor=BG_ENTRY, background=ACCENT_RED)
        
        self.check_security()

    def check_security(self):
        if not os.path.exists(VAULT_PATH):
            for widget in self.root.winfo_children(): widget.destroy()
            tk.Label(self.root, text="ΤΟ VAULT ΔΕΝ ΒΡΕΘΗΚΕ", fg=ACCENT_RED, bg=BG_MAIN, font=("Consolas", 14, "bold")).pack(pady=50)
            return

        if os.path.exists(STATUS_PATH):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(STATUS_PATH, 128)
                f_status = get_status_fernet(self.usb_id)
                with open(STATUS_PATH, "rb") as f: enc_status = f.read()
                tries = int(f_status.decrypt(enc_status).decode())
                if tries >= 3:
                    self.secure_wipe()
                    return
            except: pass 
        self.login_screen()

    def secure_wipe(self):
        for widget in self.root.winfo_children(): widget.destroy()
        tk.Label(self.root, text="⚠️ SECURITY BREACH ⚠️", fg=ACCENT_RED, bg=BG_MAIN, font=("Consolas", 16, "bold")).pack(pady=30)
        pb = ttk.Progressbar(self.root, length=300, mode='determinate', style="TProgressbar")
        pb.pack(pady=20)
        
        for f_name in [VAULT_PATH, STATUS_PATH]:
            if os.path.exists(f_name):
                ctypes.windll.kernel32.SetFileAttributesW(f_name, 128)
                size = os.path.getsize(f_name)
                with open(f_name, "wb") as f: f.write(os.urandom(size))
                os.remove(f_name)
                pb['value'] += 50
                self.root.update()
                time.sleep(1)
        self.root.destroy()

    def login_screen(self):
        tk.Label(self.root, text="SECURE ACCESS", font=("Consolas", 18, "bold"), bg=BG_MAIN, fg=ACCENT_GREEN).pack(pady=40)
        tk.Label(self.root, text="Master Password:", bg=BG_MAIN, fg=FG_TEXT).pack()
        self.entry = tk.Entry(self.root, show="*", width=30, bg=BG_ENTRY, fg="white", insertbackground="white", borderwidth=0, font=("Arial", 12))
        self.entry.pack(pady=10)
        self.entry.focus()
        tk.Button(self.root, text="UNLOCK VAULT", command=self.unlock, bg=ACCENT_GREEN, fg="white", font=("Arial", 10, "bold"), width=20, height=2, bd=0).pack(pady=30)
        self.root.bind('<Return>', lambda e: self.unlock())

    def unlock(self):
        from cryptography.fernet import Fernet
        m_pass = self.entry.get()
        try:
            with open(VAULT_PATH, "rb") as f: enc_data = f.read()
            key = derive_key(m_pass, self.usb_id)
            f_obj = Fernet(key)
            self.data = json.loads(f_obj.decrypt(enc_data).decode())
            
            f_status = get_status_fernet(self.usb_id)
            ctypes.windll.kernel32.SetFileAttributesW(STATUS_PATH, 128)
            with open(STATUS_PATH, "wb") as f: f.write(f_status.encrypt(b"0"))
            ctypes.windll.kernel32.SetFileAttributesW(STATUS_PATH, 0x02 | 0x04)
            self.show_dashboard()
        except:
            self.handle_failure()

    def handle_failure(self):
        tries = 1
        f_status = get_status_fernet(self.usb_id)
        if os.path.exists(STATUS_PATH):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(STATUS_PATH, 128)
                with open(STATUS_PATH, "rb") as f: enc_val = f.read()
                tries = int(f_status.decrypt(enc_val).decode()) + 1
            except: tries = 1
        
        with open(STATUS_PATH, "wb") as f: f.write(f_status.encrypt(str(tries).encode()))
        ctypes.windll.kernel32.SetFileAttributesW(STATUS_PATH, 0x02 | 0x04)
        
        if tries >= 3: self.secure_wipe()
        else:
            self.entry.delete(0, tk.END)
            messagebox.showerror("Σφάλμα", f"Λάθος κωδικός! ({tries}/3)")

    def show_dashboard(self):
        for widget in self.root.winfo_children(): widget.destroy()
        self.root.geometry("450x600")
        tk.Label(self.root, text="VAULT DASHBOARD", font=("Consolas", 16, "bold"), bg=BG_MAIN, fg=ACCENT_BLUE).pack(pady=20)
        container = tk.Frame(self.root, bg=BG_MAIN)
        container.pack(fill="both", expand=True, padx=20)
        
        for s in self.data:
            btn = tk.Button(container, text=f"🌐 {s['name']}", command=lambda x=s: self.auto_login(x),
                            bg=BG_CARD, fg=FG_TEXT, font=("Arial", 11), height=2, bd=0, anchor="w", padx=20)
            btn.pack(fill="x", pady=5)
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#333"))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=BG_CARD))

    def auto_login(self, s):
        webbrowser.open(s['url'])
        time.sleep(5) 
        pyautogui.write(s['email'])
        pyautogui.press('tab')
        time.sleep(0.5)
        pyautogui.write(s['password'])
        pyautogui.press('enter')

if __name__ == "__main__":
    root = tk.Tk()
    app = FinalLauncher(root)
    root.mainloop()
