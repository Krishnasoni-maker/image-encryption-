from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import io

class ImageEncryptorPro:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Image Encryption")
        self.root.geometry("700x500")
        
        # Encryption settings
        self.key = None
        self.key_file = "encryption_key.key"
        self.formats = {
            "Standard Encryption": ".enc",
            "PNG Encryption": ".png.enc",
            "JPEG Encryption": ".jpg.enc",
            "Custom Format": ".custom"
        }
        
        # UI Setup
        self.setup_ui()
        
        # Auto-load or generate key
        self.initialize_key()

    def setup_ui(self):
        # Top Frame - Key Management
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10)
        
        tk.Label(top_frame, text="Encryption Key:").grid(row=0, column=0)
        self.key_status = tk.Label(top_frame, text="Not Loaded", fg="red")
        self.key_status.grid(row=0, column=1)
        
        tk.Button(top_frame, text="Manage Keys", command=self.key_manager).grid(row=0, column=2, padx=10)

        # Middle Frame - Image Preview
        mid_frame = tk.Frame(self.root)
        mid_frame.pack(pady=10)
        
        self.preview_label = tk.Label(mid_frame, text="Image Preview Will Appear Here", 
                                    width=50, height=15, relief="solid")
        self.preview_label.pack()

        # Bottom Frame - Controls
        bottom_frame = tk.Frame(self.root)
        bottom_frame.pack(pady=10)
        
        # Format selection
        tk.Label(bottom_frame, text="Encryption Format:").grid(row=0, column=0)
        self.format_var = tk.StringVar()
        self.format_dropdown = ttk.Combobox(bottom_frame, textvariable=self.format_var, 
                                          values=list(self.formats.keys()))
        self.format_dropdown.grid(row=0, column=1)
        self.format_dropdown.current(0)
        
        # Action buttons
        tk.Button(bottom_frame, text="Select & Encrypt Image", 
                 command=self.encrypt_image).grid(row=1, column=0, pady=5)
        tk.Button(bottom_frame, text="Select & Decrypt Image", 
                 command=self.decrypt_image).grid(row=1, column=1, pady=5)

    def initialize_key(self):
        """Handles key loading/generation automatically"""
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, "rb") as f:
                    self.key = f.read()
                self.key_status.config(text="Loaded", fg="green")
            except:
                self.generate_key()
        else:
            self.generate_key()

    def generate_key(self):
        """Creates a new encryption key"""
        self.key = get_random_bytes(32)
        with open(self.key_file, "wb") as f:
            f.write(self.key)
        self.key_status.config(text="New Key Generated", fg="blue")
        messagebox.showinfo("Key Generated", "A new encryption key has been created.")

    def key_manager(self):
        """Key management dialog"""
        key_win = tk.Toplevel(self.root)
        key_win.title("Key Management")
        
        tk.Label(key_win, text="Current Key:").pack()
        key_text = tk.Text(key_win, height=2, width=50)
        key_text.pack()
        key_text.insert("1.0", self.key.hex() if self.key else "No key loaded")
        key_text.config(state="disabled")
        
        tk.Button(key_win, text="Generate New Key", 
                command=lambda: [self.generate_key(), key_win.destroy()]).pack(pady=5)

    def show_image_preview(self, image_data):
        """Displays image preview"""
        try:
            img = Image.open(io.BytesIO(image_data))
            img.thumbnail((300, 300))
            photo = ImageTk.PhotoImage(img)
            
            self.preview_label.config(image=photo, text="")
            self.preview_label.image = photo  # Keep reference
        except:
            self.preview_label.config(image=None, text="Preview Not Available")

    def encrypt_image(self):
        """Handles image encryption with format selection"""
        if not self.key:
            messagebox.showerror("Error", "No encryption key available")
            return
            
        file_path = filedialog.askopenfilename(
            title="Select Image to Encrypt",
            filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp")]
        )
        if not file_path:
            return
            
        try:
            with open(file_path, "rb") as f:
                image_data = f.read()
            
            # Show preview
            self.show_image_preview(image_data)
            
            # Get selected format
            format_name = self.format_var.get()
            ext = self.formats.get(format_name, ".enc")
            
            # Encrypt
            cipher = AES.new(self.key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(image_data, AES.block_size))
            encrypted_data = cipher.iv + ct_bytes
            
            # Save with appropriate extension
            save_path = os.path.splitext(file_path)[0] + ext
            with open(save_path, "wb") as f:
                f.write(encrypted_data)
            
            messagebox.showinfo("Success", 
                f"Image encrypted as {format_name}!\nSaved to:\n{save_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")

    def decrypt_image(self):
        """Handles image decryption"""
        if not self.key:
            messagebox.showerror("Error", "No decryption key available")
            return
            
        file_path = filedialog.askopenfilename(
            title="Select Encrypted Image",
            filetypes=[("Encrypted Files", "*.enc *.png.enc *.jpg.enc")]
        )
        if not file_path:
            return
            
        try:
            with open(file_path, "rb") as f:
                encrypted_data = f.read()
            
            iv = encrypted_data[:16]
            ct = encrypted_data[16:]
            
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            
            # Show preview
            self.show_image_preview(pt)
            
            # Save decrypted image
            save_path = os.path.splitext(os.path.splitext(file_path)[0])[0]  # Remove double extensions
            with open(save_path, "wb") as f:
                f.write(pt)
            
            messagebox.showinfo("Success", 
                f"Image decrypted successfully!\nSaved to:\n{save_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    
    # Required additional packages
    try:
        from PIL import Image, ImageTk
    except ImportError:
        messagebox.showerror("Dependency Missing", 
                           "Please install Pillow:\npip install pillow")
        root.destroy()
        exit()
    
    app = ImageEncryptorPro(root)
    root.mainloop()