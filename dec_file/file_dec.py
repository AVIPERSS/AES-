import os
import random
import string
import customtkinter as ctk
from tkinter import filedialog, messagebox, Toplevel
import pyperclip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

saved_password = None
file_name_mapping = {}
attempt_count = 0

#  تولید کلید رمزگذاری
def generate_key(password, salt):
    """تولید کلید رمزگذاری با استفاده از PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

#  پسوندهای مجاز
ALLOWED_EXTENSIONS = {
    '.txt', '.csv', '.log', '.pdf', '.doc', '.docx', '.odt',
    '.xls', '.xlsx', '.ppt', '.pptx',
    '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.svg', '.tiff', '.webp',
    '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm',
    '.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a',
    '.py', '.java', '.c', '.cpp', '.html', '.css', '.js', '.php', '.rb', '.go', '.sh',
    '.iso', '.exe', '.msi', '.apk', '.app', '.dll'
}

# تابع برای تولید رمز عبور تصادفی
def generate_random_password(length=16):
    """تولید رمز عبور تصادفی."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    password_entry.delete(0, 'end')
    password_entry.insert(0, password)

def generate_random_filename(length):
    """تولید نام فایل تصادفی."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# تابع برای ذخیره‌سازی ت
def save_data():
    """ذخیره‌شازی اطلاعات در فایل data.txt."""
    try:
        with open("data.txt", "w") as f:
            f.write(f"{saved_password.decode()}\n")
            f.write(f"{attempt_count}\n")
            for random_name, original_name in file_name_mapping.items():
                f.write(f"{random_name},{original_name}\n")
    except Exception as e:
        print(f"Error saving data: {str(e)}")

# تابع برای بارگذاری اطلاعات
def load_data():
    """بارگذاری اطلاعات از فایل data.txt."""
    global saved_password, attempt_count
    try:
        if os.path.exists("data.txt"):
            with open("data.txt", "r") as f:
                lines = f.readlines()
                if len(lines) >= 2:
                    saved_password = lines[0].strip().encode()
                    attempt_count = int(lines[1].strip())
                    for line in lines[2:]:
                        random_name, original_name = line.strip().split(",")
                        file_name_mapping[random_name] = original_name
    except Exception as e:
        print(f"Error loading data: {str(e)}")

def encrypt_file(file_path, key):
    """رمزگذاری فایل با استفاده از کلید مشخص شده."""
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        iv = os.urandom(16)  # تولید IV تصادفی
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = iv + encryptor.update(file_data) + encryptor.finalize()

        random_length = random.randint(10, 25)
        random_filename = generate_random_filename(random_length) + ".enc"
        enc_file_path = os.path.join(os.path.dirname(file_path), random_filename)

        file_name_mapping[random_filename] = os.path.basename(file_path)

        with open(enc_file_path, 'wb') as file:
            file.write(encrypted_data)

        os.remove(file_path)  # حذف فایل اصلی
    except Exception as e:
        print(f"Error encrypting file {file_path}: {str(e)}")

# تابع برای رمزگشایی فایل
def decrypt_file(file_path, key):
    """رمزگشایی فایل با استفاده از کلید مشخص شده."""
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

        original_filename = file_name_mapping.get(os.path.basename(file_path))
        if original_filename:
            original_file_path = os.path.join(os.path.dirname(file_path), original_filename)
            with open(original_file_path, 'wb') as file:
                file.write(decrypted_data)

        os.remove(file_path)  # حذف فایل رمزگذاری شده
    except Exception as e:
        print(f"Error decrypting file {file_path}: {str(e)}")

def lock_specific_files():
    """قفل کردن فایل‌های خاص انتخاب شده توسط کاربر."""
    global saved_password
    file_paths = filedialog.askopenfilenames(title="Select files to lock", filetypes=[("All Files", "*.*")])
    if not file_paths:
        return

    confirm_window = Toplevel(root)
    confirm_window.title("Confirm Lock")
    confirm_window.geometry("400x300")
    confirm_window.resizable(False, False)

    file_list = ctk.CTkTextbox(confirm_window, width=350, height=150)
    file_list.pack(pady=10)

    for file_path in file_paths:
        file_list.insert("end", f"{os.path.basename(file_path)}\n")

    def confirm_lock():
        """تأیید قفل کردن فایل‌ها."""
        global saved_password
        password = password_entry.get().encode()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        saved_password = password
        salt = os.urandom(16)
        key = generate_key(password, salt)

        progress_bar.start()

        try:
            for file_path in file_paths:
                if os.path.splitext(file_path)[1].lower() in ALLOWED_EXTENSIONS:
                    encrypt_file(file_path, key)

            with open(os.path.join(os.path.dirname(file_paths[0]), "salt.bin"), 'wb') as salt_file:
                salt_file.write(salt)

            save_data()  
            messagebox.showinfo("Success", "Selected files locked successfully!\nRemember to keep the password safe!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to lock files: {str(e)}")
        finally:
            progress_bar.stop()
            confirm_window.destroy()

    def cancel_lock():
        """لغو قفل کردن فایل‌ها."""
        confirm_window.destroy()

    confirm_label = ctk.CTkLabel(confirm_window, text="Are you sure you want to lock the selected files?", text_color="black", font=("Arial", 12))
    confirm_label.pack(pady=10)

    confirm_button = ctk.CTkButton(confirm_window, text="Confirm", command=confirm_lock, width=120)
    confirm_button.pack(pady=10)

    cancel_button = ctk.CTkButton(confirm_window, text="Cancel", command=cancel_lock, width=120)
    cancel_button.pack(pady=10)

def lock_all_files_in_folder(folder_path):
    """قفل کردن تمام فایل‌ها در پوشه انتخاب شده."""
    global saved_password  
    confirm_window = Toplevel(root)
    confirm_window.title("Confirm Lock All")
    confirm_window.geometry("400x300")
    confirm_window.resizable(False, False)

    file_list = ctk.CTkTextbox(confirm_window, width=350, height=150)
    file_list.pack(pady=10)

    for filename in os.listdir(folder_path):
        if os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS:
            file_list.insert("end", f"{filename}\n")  

    def confirm_lock_all():
        """تأیید قفل کردن تمام فایل‌ها."""
        global saved_password  
        password = password_entry.get().encode()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        saved_password = password  
        salt = os.urandom(16)  
        key = generate_key(password, salt)

        progress_bar.start()

        try:
            for root, dirs, files in os.walk(folder_path):
                for filename in files:
                    if os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS:
                        file_path = os.path.join(root, filename)
                        encrypt_file(file_path, key)

            with open(os.path.join(folder_path, "salt.bin"), 'wb') as salt_file:
                salt_file.write(salt)

            save_data()  
            messagebox.showinfo("Success", "All files in the folder locked successfully!\nRemember to keep the password safe!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to lock files: {str(e)}")
        finally:
            progress_bar.stop()
            confirm_window.destroy()

    def cancel_lock_all():
        """لغو قفل کردن تمام فایل‌ها."""
        confirm_window.destroy()

    confirm_label = ctk.CTkLabel(confirm_window, text="Are you sure you want to lock all files in this folder?", text_color="black", font=("Arial", 12))
    confirm_label.pack(pady=10)

    confirm_button = ctk.CTkButton(confirm_window, text="Confirm", command=confirm_lock_all, width=120)
    confirm_button.pack(pady=10)

    cancel_button = ctk.CTkButton(confirm_window, text="Cancel", command=cancel_lock_all, width=120)
    cancel_button.pack(pady=10)

def unlock_specific_files():
    """باز کردن فایل‌های خاص انتخاب شده توسط کاربر."""
    file_paths = filedialog.askopenfilenames(title="Select files to unlock", filetypes=[("Encrypted Files", "*.enc")])
    if not file_paths:
        return

    confirm_window = Toplevel(root)
    confirm_window.title("Confirm Unlock")
    confirm_window.geometry("400x200")
    confirm_window.resizable(False, False)

    global attempt_count  

    def confirm_unlock():
        """تأیید باز کردن فایل‌ها."""
        global attempt_count  
        password = password_entry.get().encode()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        try:
            if password != saved_password: 
                attempt_count += 1  
                messagebox.showerror("Error", f"Incorrect password.\nAttempts left: {3 - attempt_count}")

                if attempt_count >= 3:
                    messagebox.showwarning("Warning", "Too many failed attempts. Deleting encrypted files.")
                    for file_path in file_paths:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    messagebox.showinfo("Deleted", "Encrypted files have been deleted.")
                    confirm_window.destroy()  
                    return
                return

            key_file_path = os.path.join(os.path.dirname(file_paths[0]), "salt.bin")
            with open(key_file_path, 'rb') as salt_file:
                salt = salt_file.read()

            key = generate_key(password, salt)

            progress_bar.start()
            
            for file_path in file_paths:
                decrypt_file(file_path, key)

            messagebox.showinfo("Success", "Selected files unlocked successfully!")
            confirm_window.destroy()  
            attempt_count = 0  

        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock files: {str(e)}")
        finally:
            progress_bar.stop()

    def cancel_unlock():
        """لغو باز کردن فایل‌ها."""
        confirm_window.destroy()

    confirm_label = ctk.CTkLabel(confirm_window, text="Are you sure you want to unlock the selected files?", text_color="black", font=("Arial", 12))
    confirm_label.pack(pady=20)

    confirm_button = ctk.CTkButton(confirm_window, text="Confirm", command=confirm_unlock, width=120)
    confirm_button.pack(pady=10)

    cancel_button = ctk.CTkButton(confirm_window, text="Cancel", command=cancel_unlock, width=120)
    cancel_button.pack(pady=10)

# تابع برای باز کردن فایل‌ها در یک پوشه
def unlock_files_in_folder():
    """باز کردن تمام فایل‌ها در پوشه انتخاب شده."""
    folder_path = filedialog.askdirectory(title="Select a folder to unlock files")
    if not folder_path:
        return

    confirm_window = Toplevel(root)
    confirm_window.title("Confirm Unlock All")
    confirm_window.geometry("400x200")
    confirm_window.resizable(False, False)

    global attempt_count  

    def confirm_unlock_all():
        """تأیید باز کردن تمام فایل‌ها."""
        global attempt_count  
        password = password_entry.get().encode()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        try:
            if password != saved_password:
                attempt_count += 1  
                messagebox.showerror("Error", f"Incorrect password.\nAttempts left: {3 - attempt_count}")

                if attempt_count >= 3:
                    messagebox.showwarning("Warning", "Too many failed attempts. Deleting encrypted files.")
                    for root, dirs, files in os.walk(folder_path):
                        for filename in files:
                            if filename.endswith('.enc'):
                                os.remove(os.path.join(root, filename))
                    messagebox.showinfo("Deleted", "Encrypted files have been deleted.")
                    confirm_window.destroy()  
                    return
                return

            key_file_path = os.path.join(folder_path, "salt.bin")
            with open(key_file_path, 'rb') as salt_file:
                salt = salt_file.read()

            key = generate_key(password, salt)

            progress_bar.start()
            
            for root, dirs, files in os.walk(folder_path):
                for filename in files:
                    if filename.endswith('.enc'):
                        file_path = os.path.join(root, filename)
                        decrypt_file(file_path, key)

            messagebox.showinfo("Success", "All files unlocked successfully!")
            confirm_window.destroy()  
            attempt_count = 0  

        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock files: {str(e)}")
        finally:
            progress_bar.stop()

    def cancel_unlock_all():
        """لغو باز کردن تمام فایل‌ها."""
        confirm_window.destroy()

    confirm_label = ctk.CTkLabel(confirm_window, text="Are you sure you want to unlock all files in this folder?", text_color="black", font=("Arial", 12))
    confirm_label.pack(pady=20)

    confirm_button = ctk.CTkButton(confirm_window, text="Confirm", command=confirm_unlock_all, width=120)
    confirm_button.pack(pady=10)

    cancel_button = ctk.CTkButton(confirm_window, text="Cancel", command=cancel_unlock_all, width=120)
    cancel_button.pack(pady=10)


root = ctk.CTk()
root.title("File Lock App")
root.geometry("300x500") 
root.resizable(False, True) 
load_data()  

# ورودی رمز عبور
password_entry = ctk.CTkEntry(root, placeholder_text="Enter Password", show='*', width=250)
password_entry.pack(pady=20)

# ایجاد دکمه‌ها
button_frame = ctk.CTkFrame(root)
button_frame.pack(pady=10)

# تابع برای تغییر نمایش رمز عبور
def toggle_password_visibility():
    """تغییر نمایش رمز عبور."""
    if password_entry.cget('show') == '*':
        password_entry.configure(show='')
        toggle_password_button.configure(text='👁️')
    else:
        password_entry.configure(show='*')
        toggle_password_button.configure(text='👁️')

toggle_password_button = ctk.CTkButton(button_frame, text='👁️', command=toggle_password_visibility, width=40)
toggle_password_button.pack(side='left', padx=(10, 0))

random_password_button = ctk.CTkButton(button_frame, text="🔑", command=generate_random_password, width=40)
random_password_button.pack(side='left', padx=(10, 0))

# تابع برای کپی کردن رمز عبور
def copy_password():
    """کپی کردن رمز عبور به کلیپ بورد."""
    pyperclip.copy(password_entry.get())
    messagebox.showinfo("Copied", "Password copied to clipboard!") 

copy_password_button = ctk.CTkButton(button_frame, text="📝", command=copy_password, width=40)
copy_password_button.pack(side='left', padx=(10, 0))

# دکمه‌های قفل کردن و باز کردن فایل‌ها
lock_specific_button = ctk.CTkButton(root, text="Lock Specific Files", command=lock_specific_files)
lock_specific_button.pack(pady=10)

lock_all_button = ctk.CTkButton(root, text="Lock All Files in Folder", command=lambda: lock_all_files_in_folder(filedialog.askdirectory(title="Select a folder to lock files")))
lock_all_button.pack(pady=10)

unlock_specific_button = ctk.CTkButton(root, text="Unlock Specific Files", command=unlock_specific_files)
unlock_specific_button.pack(pady=10)

unlock_button = ctk.CTkButton(root, text="Unlock Files in Folder", command=unlock_files_in_folder)
unlock_button.pack(pady=10)
#نوار گرافیکی
progress_bar = ctk.CTkProgressBar(root)
progress_bar.pack(pady=20, fill='x', padx=20)

# برچسب 
footer_label = ctk.CTkLabel(root, text="Created by : Github.com/AVIPERSS", text_color="gray")
footer_label.pack(side="bottom", pady=20)

# اجرا
root.mainloop()