import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import json, os, ctypes, base64, subprocess, string, random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Ρυθμίσεις Χρωμάτων (Dark UI) ---
BG_MAIN = "#121212"
BG_CARD = "#1e1e1e"
BG_ENTRY = "#2c2c2c"
FG_TEXT = "#e0e0e0"
ACCENT_GREEN = "#4caf50"
ACCENT_BLUE = "#2196f3"
ACCENT_RED = "#f44336"

def get_usb_drives():
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if bitmask & 1:
            drive_path = f"{letter}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(drive_path) == 2:
                drives.append(f"{letter}:")
        bitmask >>= 1
    return drives

def get_usb_id(drive_letter):
    try:
        output = subprocess.check_output(f"vol {drive_letter}", shell=True).decode()
        serial = output.split()[-1].replace("-", "")
        return serial.encode()
    except: return None

def derive_key(password, usb_id):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=usb_id, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def get_status_fernet(usb_id):
    """Δημιουργεί ένα κλειδί βασισμένο μόνο στο USB ID για το status file."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"status_salt", iterations=1000)
    key = base64.urlsafe_b64encode(kdf.derive(usb_id))
    return Fernet(key)

class SiteDialog(tk.Toplevel):
    def __init__(self, parent, title="Στοιχεία Site", initial_data=None):
        super().__init__(parent)
        self.title(title)
        self.geometry("350x280")
        self.configure(bg=BG_CARD)
        self.result = None
        self.transient(parent)
        self.grab_set()

        fields = [("Όνομα:", "name"), ("URL:", "url"), ("Email:", "email"), ("Password:", "password")]
        self.entries = {}

        for i, (label_text, key) in enumerate(fields):
            tk.Label(self, text=label_text, bg=BG_CARD, fg=FG_TEXT).grid(row=i, column=0, padx=15, pady=10, sticky="e")
            ent = tk.Entry(self, width=25, bg=BG_ENTRY, fg="white", insertbackground="white", borderwidth=0)
            if key == "password": ent.config(show="*")
            if initial_data: ent.insert(0, initial_data.get(key, ""))
            ent.grid(row=i, column=1, padx=5, pady=10)
            self.entries[key] = ent

        tk.Button(self, text="ΑΠΟΘΗΚΕΥΣΗ", command=self.save, bg=ACCENT_BLUE, fg="white", 
                  font=("Arial", 10, "bold"), width=20, height=2, bd=0).grid(row=4, column=0, columnspan=2, pady=20)

    def save(self):
        self.result = {key: ent.get() for key, ent in self.entries.items()}
        if self.result["name"] and self.result["password"]:
            self.destroy()
        else:
            messagebox.showwarning("Προσοχή", "Το Όνομα και το Password είναι υποχρεωτικά!")

class AdminManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Vault Admin - Encrypted Status")
        self.root.geometry("500x850")
        self.root.configure(bg=BG_MAIN)
        self.sites = []
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TCombobox", fieldbackground=BG_ENTRY, background=BG_ENTRY, foreground="white")

        tk.Label(root, text="USB VAULT MANAGER", font=("Consolas", 18, "bold"), bg=BG_MAIN, fg=ACCENT_GREEN).pack(pady=20)

        tk.Label(root, text="Master Password:", bg=BG_MAIN, fg=FG_TEXT).pack()
        self.pass_ent = tk.Entry(root, show="*", width=35, bg=BG_ENTRY, fg="white", insertbackground="white", borderwidth=0, font=("Arial", 12))
        self.pass_ent.pack(pady=5)

        tk.Label(root, text="Επιλογή USB:", bg=BG_MAIN, fg=FG_TEXT).pack(pady=(10,0))
        self.usb_combo = ttk.Combobox(root, width=32, state="readonly", font=("Arial", 10))
        self.usb_combo.pack(pady=5)
        self.refresh_usbs()

        act_frame = tk.Frame(root, bg=BG_MAIN)
        act_frame.pack(pady=10)
        tk.Button(act_frame, text="🔓 ΦΟΡΤΩΣΗ", command=self.load_from_usb, bg="#333", fg=ACCENT_GREEN, width=15, bd=0).pack(side=tk.LEFT, padx=5)
        tk.Button(act_frame, text="🔑 ΑΛΛΑΓΗ ΚΩΔΙΚΟΥ", command=self.change_master_password, bg="#333", fg="orange", width=18, bd=0).pack(side=tk.LEFT, padx=5)

        tk.Label(root, text="Λίστα Sites (Ιδιωτική Προβολή):", bg=BG_MAIN, fg="#888", font=("Arial", 8, "italic")).pack(pady=(15,0))
        self.listbox = tk.Listbox(root, height=12, width=50, bg=BG_ENTRY, fg=FG_TEXT, borderwidth=0, highlightthickness=0, font=("Consolas", 11))
        self.listbox.pack(pady=5, padx=20)
        self.listbox.bind("<Double-1>", lambda e: self.edit_site())

        btn_frame = tk.Frame(root, bg=BG_MAIN)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="+ ΠΡΟΣΘΗΚΗ", command=self.add_site, bg=ACCENT_GREEN, fg="white", width=12, bd=0, height=2).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="- ΔΙΑΓΡΑΦΗ", command=self.delete_site, bg=ACCENT_RED, fg="white", width=12, bd=0, height=2).pack(side=tk.LEFT, padx=5)

        tk.Button(root, text="🔒 ΑΠΟΘΗΚΕΥΣΗ / BUILD VAULT", command=self.build_vault, 
                  bg=ACCENT_BLUE, fg="white", font=("Arial", 11, "bold"), height=3).pack(pady=20, fill="x", padx=60)
        
        tk.Button(root, text="ΚΑΘΑΡΙΣΜΟΣ USB (RESET)", command=self.reset_usb, bg=BG_MAIN, fg="#555", bd=0, font=("Arial", 8, "underline")).pack(side=tk.BOTTOM, pady=10)

    def refresh_usbs(self):
        drives = get_usb_drives()
        self.usb_combo['values'] = drives
        if drives: self.usb_combo.set(drives[0])
        else: self.usb_combo.set("Δεν βρέθηκε USB")

    def update_listbox(self):
        self.listbox.delete(0, tk.END)
        for s in self.sites:
            self.listbox.insert(tk.END, f" > {s['name']}")

    def load_from_usb(self):
        m_pass = self.pass_ent.get()
        drive = self.usb_combo.get()
        if not m_pass or ":" not in drive:
            messagebox.showwarning("Προσοχή", "Βάλτε τον κωδικό και επιλέξτε USB!")
            return

        drive_path = drive if drive.endswith("\\") else drive + "\\"
        vault_file = os.path.join(drive_path, "vault.bin")

        if not os.path.exists(vault_file):
            messagebox.showerror("Error", "Δεν βρέθηκε Vault.")
            return

        try:
            usb_id = get_usb_id(drive)
            key = derive_key(m_pass, usb_id)
            f_obj = Fernet(key)
            ctypes.windll.kernel32.SetFileAttributesW(vault_file, 128)
            with open(vault_file, "rb") as f: enc_data = f.read()
            self.sites = json.loads(f_obj.decrypt(enc_data).decode())
            ctypes.windll.kernel32.SetFileAttributesW(vault_file, 0x02 | 0x04)
            self.update_listbox()
            messagebox.showinfo("Success", "Τα δεδομένα φορτώθηκαν!")
        except Exception:
            messagebox.showerror("Error", "Λάθος Master Password!")

    def change_master_password(self):
        drive = self.usb_combo.get()
        if ":" not in drive: return
        drive_path = drive if drive.endswith("\\") else drive + "\\"
        vault_file = os.path.join(drive_path, "vault.bin")
        
        old_pass = simpledialog.askstring("Ασφάλεια", "Εισάγετε τον Τρέχοντα Master Password:", show="*")
        if not old_pass: return
        
        try:
            usb_id = get_usb_id(drive)
            old_key = derive_key(old_pass, usb_id)
            f_old = Fernet(old_key)
            ctypes.windll.kernel32.SetFileAttributesW(vault_file, 128)
            with open(vault_file, "rb") as f: enc_data = f.read()
            dec_data = f_old.decrypt(enc_data).decode()
            
            new_pass = simpledialog.askstring("Νέος Κωδικός", "Εισάγετε τον Νέο Master Password:", show="*")
            if not new_pass: return
            
            new_key = derive_key(new_pass, usb_id)
            f_new = Fernet(new_key)
            new_enc = f_new.encrypt(dec_data.encode())
            with open(vault_file, "wb") as f: f.write(new_enc)
            ctypes.windll.kernel32.SetFileAttributesW(vault_file, 0x02 | 0x04)
            messagebox.showinfo("Success", "Ο κωδικός άλλαξε!")
        except: messagebox.showerror("Error", "Λάθος τρέχων κωδικός!")

    def add_site(self):
        dialog = SiteDialog(self.root, title="Νέα Εγγραφή")
        self.root.wait_window(dialog)
        if dialog.result:
            self.sites.append(dialog.result)
            self.update_listbox()

    def edit_site(self):
        try:
            index = self.listbox.curselection()[0]
            dialog = SiteDialog(self.root, title="Επεξεργασία", initial_data=self.sites[index])
            self.root.wait_window(dialog)
            if dialog.result:
                self.sites[index] = dialog.result
                self.update_listbox()
        except IndexError: pass

    def delete_site(self):
        try:
            index = self.listbox.curselection()[0]
            if messagebox.askyesno("Διαγραφή", "Σίγουρα;"):
                self.sites.pop(index)
                self.update_listbox()
        except IndexError: pass

    def build_vault(self):
        m_pass = self.pass_ent.get()
        drive = self.usb_combo.get()
        if not m_pass or ":" not in drive: return

        drive_path = drive if drive.endswith("\\") else drive + "\\"
        usb_id = get_usb_id(drive)
        if not usb_id: return

        try:
            key = derive_key(m_pass, usb_id)
            f_obj = Fernet(key)
            data = f_obj.encrypt(json.dumps(self.sites).encode())
            
            # Κρυπτογράφηση του status "0"
            f_status = get_status_fernet(usb_id)
            status_data = f_status.encrypt(b"0")
            
            path = os.path.join(drive_path, "vault.bin")
            status_path = os.path.join(drive_path, "status.sys")
            
            for p in [path, status_path]:
                if os.path.exists(p): ctypes.windll.kernel32.SetFileAttributesW(p, 128)
            with open(path, "wb") as f: f.write(data)
            with open(status_path, "wb") as f: f.write(status_data)
            ctypes.windll.kernel32.SetFileAttributesW(path, 0x02 | 0x04)
            ctypes.windll.kernel32.SetFileAttributesW(status_path, 0x02 | 0x04)
            messagebox.showinfo("Επιτυχία", "Το Vault ενημερώθηκε (και το status κρυπτογραφήθηκε)!")
        except Exception as e: messagebox.showerror("Σφάλμα", str(e))

    def reset_usb(self):
        drive = self.usb_combo.get()
        if ":" in drive and messagebox.askyesno("Reset", "Καθαρισμός USB;"):
            try:
                for f in ["vault.bin", "status.sys"]:
                    p = os.path.join(drive if drive.endswith("\\") else drive + "\\", f)
                    if os.path.exists(p):
                        ctypes.windll.kernel32.SetFileAttributesW(p, 128)
                        os.remove(p)
                self.sites = []
                self.update_listbox()
                messagebox.showinfo("Reset", "Το USB καθαρίστηκε.")
            except: pass

if __name__ == "__main__":
    root = tk.Tk()
    AdminManager(root)
    root.mainloop()
