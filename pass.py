import string
import random
import tkinter as tk
from tkinter import messagebox
from tkinter import Menu
from tkinter import filedialog
from art import tprint
import os
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from tkinter import Tk, Canvas, Entry, Text, Button, PhotoImage
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--r')
args = parser.parse_args()

OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r"assets\frame0")

def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)

def caesar_cipher(text, shift):
    alphabet = string.ascii_letters + string.digits + string.punctuation + " "
    shifted_alphabet = alphabet[shift:] + alphabet[:shift]
    table = str.maketrans(alphabet, shifted_alphabet)
    return text.translate(table)

def encrypt_data(data, key):
    encrypted_data = key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data.hex()

def decrypt_data(encrypted_data, key):
    decrypted_data = key.decrypt(
        bytes.fromhex(encrypted_data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode()

def generate_password(length, include_numbers, include_special_chars, include_uppercase):
    characters = string.ascii_letters
    if include_numbers:
        characters += string.digits
    if include_special_chars:
        characters += string.punctuation
    if include_uppercase:
        characters += string.ascii_uppercase

    password = ''.join(random.choices(characters, k=length))
    return password

def is_duplicate(password, password_list):
    for existing_password in password_list:
        if password == existing_password:
            return True
    return False

def generate_unique_password(length, include_numbers, include_special_chars, include_uppercase, password_list):
    while True:
        password = generate_password(length, include_numbers, include_special_chars, include_uppercase)
        if not is_duplicate(password, password_list):
            return password

def save_password_to_file(password, site, username, public_key):
    file_path = os.path.join(save_folder_path, "passwords.txt")
    encrypted_site = encrypt_data(site, public_key)
    encrypted_username = encrypt_data(username, public_key)
    encrypted_password = encrypt_data(password, public_key)
    with open(file_path, 'a') as file:
        file.write(f"Сайт: {encrypted_site}\n")
        file.write(f"Логин: {encrypted_username}\n")
        file.write(f"Пароль: {encrypted_password}\n\n")

def generate_and_show_password():
    try:
        password_length = int(length_entry.get())
        if password_length < 1 and args.r == 'developer':
            raise ValueError("ты конченный? Зачем тебе такой короткий пароль?")
        elif password_length < 1:
            raise ValueError("Пароль слишком короткий")
        if password_length >= 191 and args.r == 'developer':
            raise ValueError("ты конченный? Зачем тебе такой длинный пароль?")
        elif password_length < 1:
            raise ValueError("Пароль слишком длинный")

        include_numbers = numbers_var.get()
        include_special_chars = special_chars_var.get()
        include_uppercase = uppercase_var.get()
        site = site_entry.get()
        username = username_entry.get()

        password = generate_unique_password(password_length, include_numbers, include_special_chars, include_uppercase, password_list)
        password_list.append(password)

        messagebox.showinfo("Сгенерированный пароль", f"Ваш пароль:\n\n{password}")

        save_password_to_file(password, site, username, public_key)

        messagebox.showinfo("Пароль сохранен", "Пароль сгенерирован и сохранен.")
    except ValueError as e:
        messagebox.showerror("Недопустимый ввод", str(e))

def open_settings():

    def select_save_folder():
        global save_folder_path
        save_folder_path = filedialog.askdirectory()
        save_settings()

    def save_settings():
        settings = {
            "save_folder_path": save_folder_path
        }
        with open("settings.json", "w") as file:
            json.dump(settings, file)
    settings_window = tk.Toplevel(window)
    settings_window.title("Настройки")
    settings_window.geometry("300x200")
    settings_window.configure(bg = "#84BAB7")
    settings_window.iconbitmap(r'assets\frame0\fuck.ico')
    settings_window.attributes("-topmost",True)

    button_images = PhotoImage(
        file=relative_to_assets("button_3.png"))
    save_folder_button = Button(
        settings_window,
        image=button_images,
        borderwidth=0,
        highlightthickness=0,
        command=select_save_folder,
        relief="flat"
    )
    save_folder_button.place(
        x=25.0,
        y=40.0,
        width=250.0,
        height=25.0
    )
    window.resizable(False, False)
    window.mainloop()


# Создание главного окна
window = tk.Tk()
window.title("Генератор паролей")
window.configure(bg = "#84BAB7")
x = (window.winfo_screenwidth() - window.winfo_reqwidth()) / 2
y = (window.winfo_screenheight() - window.winfo_reqheight()) / 2 - 100
window.wm_geometry("+%d+%d" % (x, y))
window.geometry("250x300")
window.iconbitmap(r'assets\frame0\fuck.ico')
window.resizable(width=False, height=False)


canvas = Canvas(
    window,
    bg = "#84BAB7",
    height = 285,
    width = 250,
    bd = 0,
    highlightthickness = 0,
    relief = "ridge"
)

canvas.place(x = 0, y = 0)
entry_image_1 = PhotoImage(
    file=relative_to_assets("entry_1.png"))
entry_bg_1 = canvas.create_image(
    195.0,
    38.00000000000001,
    image=entry_image_1
)
length_entry = Entry(
    bd=0,
    bg="#D9D9D9",
    fg="#000716",
    highlightthickness=0
)
length_entry.place(
    x=168.0,
    y=28.000000000000007,
    width=54.0,
    height=18.0
)

canvas.create_text(
    25.0,
    32.00000000000001,
    anchor="nw",
    text="Длина пароля",
    fill="#000000",
    font=("Inder Regular", 12 * -1)
)
canvas.create_rectangle(
    8.0,
    51.00000000000001,
    240.0,
    53.00000000000001,
    fill="#365B5F",
    outline="")

entry_image_2 = PhotoImage(
    file=relative_to_assets("entry_2.png"))
entry_bg_2 = canvas.create_image(
    125.0,
    200.0,
    image=entry_image_2
)
canvas.create_text(
    181.0,
    63.00000000000001,
    anchor="nw",
    text="Регистр",
    fill="#000000",
    font=("Inder Regular", 12 * -1)
)
uppercase_var = tk.BooleanVar()
uppercase_check = tk.Checkbutton(window, variable=uppercase_var)
uppercase_check.place(
    x=140.0,
    y=63.00000000000001,
    width=15.0,
    height=10.0
)
canvas.create_text(
    45.0,
    63.00000000000001,
    anchor="nw",
    text="Числа",
    fill="#000000",
    font=("Inder Regular", 12 * -1)
)
numbers_var = tk.BooleanVar()
button_4 = tk.Checkbutton(window, variable=numbers_var)
button_4.place(
    x=18.0,
    y=63.00000000000001,
    width=15.0,
    height=10.0
)
special_chars_var = tk.BooleanVar()
special_chars_check = tk.Checkbutton(window, variable=special_chars_var)
special_chars_check.place(
    x=42.0,
    y=87.0,
    width=15.0,
    height=10.0
)

canvas.create_text(
    77.0,
    87.0,
    anchor="nw",
    text="Специальные символы",
    fill="#000000",
    font=("Inder Regular", 12 * -1)
)

canvas.create_rectangle(
    8.0,
    51.00000000000001,
    240.0,
    53.00000000000001,
    fill="#365B5F",
    outline="")

entry_image_2 = PhotoImage(
    file=relative_to_assets("entry_2.png"))
entry_bg_2 = canvas.create_image(
    125.0,
    200.0,
    image=entry_image_2
)
site_entry = Entry(
    bd=0,
    bg="#D9D9D9",
    fg="#000716",
    highlightthickness=0
)
site_entry.place(
    x=45.0,
    y=190.0,
    width=160.0,
    height=18.0
)
entry_image_3 = PhotoImage(
    file=relative_to_assets("entry_3.png"))
entry_bg_3 = canvas.create_image(
    125.0,
    146.5,
    image=entry_image_3
)
username_entry = Entry(
    bd=0,
    bg="#D9D9D9",
    fg="#000716",
    highlightthickness=0
)
username_entry.place(
    x=45.0,
    y=137.0,
    width=160.0,
    height=17.0
)

button_image_1 = PhotoImage(
    file=relative_to_assets("button_1.png"))
button_1 = Button(
    image=button_image_1,
    borderwidth=0,
    highlightthickness=0,
    command=generate_and_show_password,
    relief="flat"
)
button_1.place(
    x=10.0,
    y=216.0,
    width=230.0,
    height=25.0
)

canvas.create_text(
    64.0,
    7.000000000000007,
    anchor="nw",
    text="Генератор паролей",
    fill="#000000",
    font=("Inder Regular", 12 * -1)
)

# Список сгенерированных паролей
password_list = []

# Место сохранения файла по умолчанию
save_folder_path = os.getcwd()

# Создание и сохранение ключей RSA
key_path = os.path.join(save_folder_path, "private_key.pem")
if not os.path.exists(key_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'defolter'),
    )
    with open(key_path, 'wb') as key_file:
        key_file.write(private_key_pem)

# Загрузка и расшифровка ключей
with open(key_path, 'rb') as key_file:
    private_key_pem = key_file.read()
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=b'defolter',
        backend=default_backend()
    )

# Получение публичного ключа
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Шифрование и сохранение публичного ключа
encrypted_public_key = caesar_cipher(public_key_pem.decode(), 13)
public_key_path = os.path.join(save_folder_path, "public_key.txt")
with open(public_key_path, 'w') as key_file:
    key_file.write(encrypted_public_key)

# Загрузка и расшифровка публичного ключа
with open(public_key_path, 'r') as key_file:
    encrypted_public_key = key_file.read()
    public_key_pem = caesar_cipher(encrypted_public_key, -13)
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )

def show_my_passwords():
    file_path = os.path.join(save_folder_path, "passwords.txt")
    decrypted_passwords = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for i in range(0, len(lines), 4):
            encrypted_site = lines[i].replace("Сайт: ", "").strip()
            encrypted_username = lines[i+1].replace("Логин: ", "").strip()
            encrypted_password = lines[i+2].replace("Пароль: ", "").strip()
            site = decrypt_data(encrypted_site, private_key)
            username = decrypt_data(encrypted_username, private_key)
            password = decrypt_data(encrypted_password, private_key)
            decrypted_passwords.append((site, username, password))

    passwords_text = "\n".join([f"Сайт: {site}\nЛогин: {username}\nПароль: {password}\n" for site, username, password in decrypted_passwords])
    
    # Создание нового окна для отображения паролей
    passwords_window = tk.Toplevel(window)
    passwords_window.title("Мои пароли")
    passwords_window.geometry("400x300")
    passwords_window.iconbitmap(r'assets\frame0\fuck.ico')
    passwords_window.configure(bg = "#84BAB7")
    # Создание текстового поля для отображения паролей
    canvas = Canvas(
        passwords_window,
        bg = "#84BAB7",
        height = 300,
        width = 400,
        bd = 0,
        highlightthickness = 0,
        relief = "ridge"
    )
    canvas.place(x = 0, y = 0)
    entry_image_1 = PhotoImage(
        file=relative_to_assets("entry_4.png"))
    entry_bg_1 = canvas.create_image(
        200.0,
        164.0,
        image=entry_image_1
    )
    passwords_textbox = Text(
        passwords_window,
        bd=0,
        bg="#D9D9D9",
        fg="#000716",
        highlightthickness=0
    )
    passwords_textbox.insert(tk.END, passwords_text)
    passwords_textbox.place(
        x=28.0,
        y=49.0,
        width=344.0,
        height=228.0
    )

    canvas.create_text(
        152.0,
        19.0,
        anchor="nw",
        text="Мои пароли",
        fill="#000000",
        font=("Inder Regular", 12 * -1)
    )
    
    passwords_window.resizable(width=False, height=False)

    # Функция для копирования текста из текстового поля в буфер обмена
    def copy_text():
        selected_text = passwords_textbox.get(tk.SEL_FIRST, tk.SEL_LAST)
        window.clipboard_clear()
        window.clipboard_append(selected_text)

    # Создание контекстного меню для копирования текста
    def copy_text():
        selected_text = passwords_textbox.get(tk.SEL_FIRST, tk.SEL_LAST)
        window.clipboard_clear()
        window.clipboard_append(selected_text)

    context_menu = Menu(passwords_textbox, tearoff=0)
    context_menu.add_command(label="copy", command=copy_text)

    # Привязка контекстного меню к текстовому полю
    passwords_textbox.bind("<Button-3>", lambda e: context_menu.post(e.x_root, e.y_root))

    # Привязка функции копирования текста к комбинации клавиш Ctrl+C
    passwords_textbox.bind("<Control-c>", lambda e: copy_text())

button_image_2 = PhotoImage(
    file=relative_to_assets("button_2.png"))
button_2 = Button(
    image=button_image_2,
    borderwidth=0,
    highlightthickness=0,
    command=show_my_passwords,
    relief="flat"
)
button_2.place(
    x=18.0,
    y=251.0,
    width=219.0,
    height=27.0
)
# Создание меню настроек
settings_menu = Menu(window)
settings_menu.add_command(label="Настройки", command=open_settings)
window.config(menu=settings_menu)

canvas.create_rectangle(
    25.0,
    164.0,
    225.0,
    184.0,
    fill="#7EDBD6",
    outline="")

canvas.create_rectangle(
    25.0,
    111.0,
    225.0,
    131.0,
    fill="#7DDAD5",
    outline="")

canvas.create_text(
    101.0,
    114.0,
    anchor="nw",
    text="Логин",
    fill="#000000",
    font=("Inder Regular", 12 * -1)
)

canvas.create_text(
    97.0,
    167.0,
    anchor="nw",
    text="Сайт",
    fill="#000000",
    font=("Inder Regular", 12 * -1)
)

# Загрузка настроек из файла JSON
if os.path.exists("settings.json"):
    with open("settings.json", "r") as file:
        settings = json.load(file)
        if "save_folder_path" in settings:
            save_folder_path = settings["save_folder_path"]

# Запуск главного цикла обработки событий
tprint('Genpass', font='bulbhead')
window.mainloop()
