import customtkinter as ctk
from tkinter import filedialog, messagebox
import base64, os, pyperclip, hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
from datetime import datetime

# ---------------- Enhanced Encryption Helpers ---------------- #
def generate_key(password: str, salt: bytes = None):
    """Generate a secure Fernet key from password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_text(message, password):
    salt = os.urandom(16)
    key, salt = generate_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())
    # Combine salt and encrypted data
    return base64.urlsafe_b64encode(salt + encrypted).decode()

def decrypt_text(encrypted_message, password):
    try:
        # Decode the base64 message
        data = base64.urlsafe_b64decode(encrypted_message.encode())
        # Extract salt (first 16 bytes) and encrypted data
        salt, encrypted = data[:16], data[16:]
        key, _ = generate_key(password, salt)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted).decode()
    except Exception:
        raise ValueError("Decryption failed - wrong password or corrupted data")

# ---------------- Password Strength Checker ---------------- #
def check_password_strength(password):
    """Check password strength and return score and feedback"""
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long")
    
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Password should contain lowercase letters")
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Password should contain uppercase letters")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Password should contain numbers")
    
    if any(not c.isalnum() for c in password):
        score += 1
    else:
        feedback.append("Password should contain special characters")
    
    # Strength levels
    if score <= 2:
        strength = "Weak"
        color = "red"
    elif score <= 3:
        strength = "Moderate"
        color = "orange"
    elif score <= 4:
        strength = "Strong"
        color = "green"
    else:
        strength = "Very Strong"
        color = "blue"
    
    return strength, color, feedback

# ---------------- App Class ---------------- #
class PyCryptApp:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.geometry("700x600")
        self.app.title("🔐 PyCrypt - Secure Text Encryption")
        self.app.minsize(600, 500)
        
        # Set appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize history file
        self.history_file = "pycrypt_history.json"
        self.history = self.load_history()
        
        self.setup_ui()
        
    def setup_ui(self):
        # Create main frame
        main_frame = ctk.CTkFrame(self.app)
        main_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Title
        title_label = ctk.CTkLabel(
            main_frame, 
            text="🔐 PyCrypt - Secure Text Encryption", 
            font=("Arial", 20, "bold")
        )
        title_label.pack(pady=10)
        
        # Text input area
        text_frame = ctk.CTkFrame(main_frame)
        text_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        text_label = ctk.CTkLabel(text_frame, text="Text to Encrypt/Decrypt")
        text_label.pack(pady=5)
        
        self.text_box = ctk.CTkTextbox(text_frame, height=120, font=("Consolas", 13))
        self.text_box.pack(padx=10, pady=5, fill="both", expand=True)
        
        # File operations frame
        file_frame = ctk.CTkFrame(text_frame)
        file_frame.pack(pady=5)
        
        ctk.CTkButton(
            file_frame, 
            text="📁 Load from File", 
            command=self.load_from_file
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            file_frame, 
            text="🗑️ Clear Text", 
            command=self.clear_text
        ).pack(side="left", padx=5)
        
        # Password area
        password_frame = ctk.CTkFrame(main_frame)
        password_frame.pack(padx=10, pady=5, fill="x")
        
        password_label = ctk.CTkLabel(password_frame, text="Enter Secret Key")
        password_label.pack(pady=5)
        
        self.password_entry = ctk.CTkEntry(
            password_frame, 
            show="•", 
            placeholder_text="Enter your encryption key"
        )
        self.password_entry.pack(pady=5, fill="x", padx=10)
        self.password_entry.bind("<KeyRelease>", self.on_password_change)
        
        # Password strength indicator
        self.strength_label = ctk.CTkLabel(password_frame, text="Password Strength: ")
        self.strength_label.pack(pady=2)
        
        # Action buttons
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(pady=10)
        
        ctk.CTkButton(
            button_frame, 
            text="🔒 Encrypt", 
            command=self.encrypt,
            fg_color="#D32F2F",
            hover_color="#B71C1C"
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            button_frame, 
            text="🔓 Decrypt", 
            command=self.decrypt,
            fg_color="#388E3C",
            hover_color="#1B5E20"
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            button_frame, 
            text="🎲 Generate Key", 
            command=self.generate_random_key
        ).pack(side="left", padx=5)
        
        # History panel
        history_frame = ctk.CTkFrame(main_frame)
        history_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        history_header = ctk.CTkFrame(history_frame)
        history_header.pack(fill="x")
        
        history_label = ctk.CTkLabel(history_header, text="History", font=("Arial", 14, "bold"))
        history_label.pack(side="left", padx=5, pady=5)
        
        ctk.CTkButton(
            history_header, 
            text="Clear History", 
            command=self.clear_history,
            width=100
        ).pack(side="right", padx=5, pady=5)
        
        self.history_box = ctk.CTkTextbox(history_frame, font=("Consolas", 11))
        self.history_box.pack(padx=5, pady=5, fill="both", expand=True)
        
        # Footer with theme toggle
        footer_frame = ctk.CTkFrame(main_frame)
        footer_frame.pack(pady=10, fill="x")
        
        ctk.CTkButton(
            footer_frame, 
            text="Toggle Dark/Light Mode", 
            command=self.toggle_theme
        ).pack(side="left", padx=5)
        
        # Status bar
        self.status_var = ctk.StringVar(value="Ready")
        status_bar = ctk.CTkLabel(footer_frame, textvariable=self.status_var)
        status_bar.pack(side="right", padx=5)
        
        # Load history
        self.refresh_history()
    
    def on_password_change(self, event=None):
        password = self.password_entry.get()
        if password:
            strength, color, feedback = check_password_strength(password)
            self.strength_label.configure(text=f"Password Strength: {strength}", text_color=color)
        else:
            self.strength_label.configure(text="Password Strength: ", text_color="white")
    
    def generate_random_key(self):
        """Generate a random secure key"""
        import secrets
        import string
        
        # Generate a random password with letters, digits, and punctuation
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
        self.on_password_change()
        
        self.status_var.set("Random key generated")
    
    def encrypt(self):
        message = self.text_box.get("1.0", "end-1c").strip()
        password = self.password_entry.get()
        
        if not message:
            messagebox.showerror("Error", "Please enter text to encrypt")
            return
            
        if not password:
            messagebox.showerror("Error", "Please enter an encryption key")
            return
        
        try:
            encrypted = encrypt_text(message, password)
            self.add_to_history("ENCRYPT", message, encrypted)
            self.show_result("Encryption Result", encrypted)
            self.status_var.set("Text encrypted successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.status_var.set("Encryption failed")
    
    def decrypt(self):
        message = self.text_box.get("1.0", "end-1c").strip()
        password = self.password_entry.get()
        
        if not message:
            messagebox.showerror("Error", "Please enter text to decrypt")
            return
            
        if not password:
            messagebox.showerror("Error", "Please enter the decryption key")
            return
        
        try:
            decrypted = decrypt_text(message, password)
            self.add_to_history("DECRYPT", message, decrypted)
            self.show_result("Decryption Result", decrypted)
            self.status_var.set("Text decrypted successfully")
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed. Wrong key or invalid data.")
            self.status_var.set("Decryption failed")
    
    def show_result(self, title, content):
        result_win = ctk.CTkToplevel(self.app)
        result_win.title(title)
        result_win.geometry("500x400")
        result_win.transient(self.app)
        result_win.grab_set()
        
        # Center the window
        result_win.update_idletasks()
        x = self.app.winfo_x() + (self.app.winfo_width() // 2) - (result_win.winfo_width() // 2)
        y = self.app.winfo_y() + (self.app.winfo_height() // 2) - (result_win.winfo_height() // 2)
        result_win.geometry(f"+{x}+{y}")
        
        result_text = ctk.CTkTextbox(result_win, font=("Consolas", 13), wrap="word")
        result_text.pack(padx=10, pady=10, fill="both", expand=True)
        result_text.insert("end", content)
        
        button_frame = ctk.CTkFrame(result_win)
        button_frame.pack(pady=10)
        
        ctk.CTkButton(
            button_frame, 
            text="Copy", 
            command=lambda: self.copy_to_clipboard(content)
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            button_frame, 
            text="Save to File", 
            command=lambda: self.save_to_file(content)
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            button_frame, 
            text="Close", 
            command=result_win.destroy
        ).pack(side="left", padx=5)
    
    def copy_to_clipboard(self, content):
        pyperclip.copy(content)
        self.status_var.set("Copied to clipboard")
    
    def save_to_file(self, content):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Saved", f"Content saved to {file_path}")
                self.status_var.set(f"Saved to {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def load_from_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.text_box.delete("1.0", "end")
                self.text_box.insert("end", content)
                self.status_var.set(f"Loaded from {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def clear_text(self):
        self.text_box.delete("1.0", "end")
        self.status_var.set("Text cleared")
    
    def load_history(self):
        """Load history from JSON file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return []
    
    def save_history(self):
        """Save history to JSON file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception:
            pass
    
    def add_to_history(self, action, original, result):
        """Add an entry to history"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": timestamp,
            "action": action,
            "original": original[:100] + "..." if len(original) > 100 else original,
            "result": result[:100] + "..." if len(result) > 100 else result,
            "full_original": original,
            "full_result": result
        }
        
        self.history.insert(0, entry)
        # Keep only the last 50 entries
        if len(self.history) > 50:
            self.history = self.history[:50]
        
        self.save_history()
        self.refresh_history()
    
    def refresh_history(self):
        """Refresh the history display"""
        self.history_box.delete("1.0", "end")
        
        if not self.history:
            self.history_box.insert("end", "No history yet. Your operations will appear here.")
            return
        
        for i, entry in enumerate(self.history):
            timestamp = entry["timestamp"]
            action = entry["action"]
            original = entry["original"]
            result = entry["result"]
            
            self.history_box.insert("end", f"{i+1}. {timestamp} - {action}\n")
            self.history_box.insert("end", f"   Original: {original}\n")
            self.history_box.insert("end", f"   Result: {result}\n\n")
    
    def clear_history(self):
        """Clear the history"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all history?"):
            self.history = []
            self.save_history()
            self.refresh_history()
            self.status_var.set("History cleared")
    
    def toggle_theme(self):
        theme = ctk.get_appearance_mode()
        new_theme = "light" if theme == "Dark" else "dark"
        ctk.set_appearance_mode(new_theme)
        self.status_var.set(f"Switched to {new_theme} mode")
    
    def run(self):
        self.app.mainloop()

# ---------------- Run Application ---------------- #
if __name__ == "__main__":
    app = PyCryptApp()
    app.run()