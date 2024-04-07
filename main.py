import string
import random
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.checkbox import CheckBox
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.contextmenu import ContextMenu
from kivy.uix.contextmenu import ContextMenuItem
from kivy.uix.boxlayout import BoxLayout
from kivy.core.clipboard import Clipboard

class PasswordGeneratorApp(App):
    def build(self):
        self.password_list = []
        self.save_folder_path = os.getcwd()
        self.private_key = None
        self.public_key = None

        # Создание и сохранение ключей RSA
        key_path = os.path.join(self.save_folder_path, "private_key.pem")
        if not os.path.exists(key_path):
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            private_key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b'openai'),
            )
            with open(key_path, 'wb') as key_file:
                key_file.write(private_key_pem)

        # Загрузка и расшифровка ключей
        with open(key_path, 'rb') as key_file:
            private_key_pem = key_file.read()
            self.private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=b'openai',
                backend=default_backend()
            )

        # Получение публичного ключа
        self.public_key = self.private_key.public_key()
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Шифрование и сохранение публичного ключа
        encrypted_public_key = self.caesar_cipher(public_key_pem.decode(), 13)
        public_key_path = os.path.join(self.save_folder_path, "public_key.txt")
        with open(public_key_path, 'w') as key_file:
            key_file.write(encrypted_public_key)

        # Загрузка и расшифровка публичного ключа
        with open(public_key_path, 'r') as key_file:
            encrypted_public_key = key_file.read()
            public_key_pem = self.caesar_cipher(encrypted_public_key, -13)
            self.public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )

        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        # Метка и поле ввода для длины пароля
        length_label = Label(text="Password Length:")
        self.length_entry = TextInput(multiline=False)
        layout.add_widget(length_label)
        layout.add_widget(self.length_entry)

        # Флажки для выбора опций пароля
        self.numbers_var = CheckBox(active=False)
        self.special_chars_var = CheckBox(active=False)
        self.uppercase_var = CheckBox(active=False)
        numbers_label = Label(text="Include Numbers")
        special_chars_label = Label(text="Include Special Characters")
        uppercase_label = Label(text="Include Uppercase Letters")
        layout.add_widget(numbers_label)
        layout.add_widget(self.numbers_var)
        layout.add_widget(special_chars_label)
        layout.add_widget(self.special_chars_var)
        layout.add_widget(uppercase_label)
        layout.add_widget(self.uppercase_var)

        # Метка и поле ввода для сайта
        site_label = Label(text="Site:")
        self.site_entry = TextInput(multiline=False)
        layout.add_widget(site_label)
        layout.add_widget(self.site_entry)

        # Метка и поле ввода для имени пользователя
        username_label = Label(text="Username:")
        self.username_entry = TextInput(multiline=False)
        layout.add_widget(username_label)
        layout.add_widget(self.username_entry)

        # Кнопка для генерации и отображения пароля
        generate_button = Button(text="Generate Password")
        generate_button.bind(on_press=self.generate_and_show_password)
        layout.add_widget(generate_button)

        # Кнопка для отображения паролей
        show_passwords_button = Button(text="Show My Passwords")
        show_passwords_button.bind(on_press=self.show_my_passwords)
        layout.add_widget(show_passwords_button)

        return layout

    def caesar_cipher(self, text, shift):
        alphabet = string.ascii_letters + string.digits + string.punctuation + " "
        shifted_alphabet = alphabet[shift:] + alphabet[:shift]
        table = str.maketrans(alphabet, shifted_alphabet)
        return text.translate(table)

    def encrypt_data(self, data, key):
        encrypted_data = key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data.hex()

    def decrypt_data(self, encrypted_data, key):
        decrypted_data = key.decrypt(
            bytes.fromhex(encrypted_data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data.decode()

    def generate_password(self, length, include_numbers, include_special_chars, include_uppercase):
        characters = string.ascii_letters
        if include_numbers:
            characters += string.digits
        if include_special_chars:
            characters += string.punctuation
        if include_uppercase:
            characters += string.ascii_uppercase

        password = ''.join(random.choices(characters, k=length))
        return password

    def is_duplicate(self, password, password_list):
        for existing_password in password_list:
            if password == existing_password:
                return True
        return False

    def generate_unique_password(self, length, include_numbers, include_special_chars, include_uppercase):
        while True:
            password = self.generate_password(length, include_numbers, include_special_chars, include_uppercase)
            if not self.is_duplicate(password, self.password_list):
                return password
    def generate_and_show_password(self, instance):
        try:
            password_length = int(self.length_entry.text)
            if password_length < 0 or password_length > 10000:
                raise ValueError("Invalid password length. Please enter a value between 0 and 10000.")

            include_numbers = self.numbers_var.active
            include_special_chars = self.special_chars_var.active
            include_uppercase = self.uppercase_var.active
            site = self.site_entry.text
            username = self.username_entry.text

            password = self.generate_unique_password(password_length, include_numbers, include_special_chars, include_uppercase)
            self.password_list.append(password)

            popup_content = BoxLayout(orientation='vertical', padding=10, spacing=10)
            password_label = Label(text="Your password is:\n\n" + password, halign='center')
            popup_content.add_widget(password_label)

            save_button = Button(text="Save Password")
            save_button.bind(on_press=lambda instance: self.save_password_to_file(password, site, username, self.public_key))
            popup_content.add_widget(save_button)

            popup = Popup(title="Generated Password", content=popup_content, size_hint=(None, None), size=(400, 200))
            popup.open()

        except ValueError as e:
            popup_content = BoxLayout(orientation='vertical', padding=10, spacing=10)
            error_label = Label(text=str(e), halign='center')
            popup_content.add_widget(error_label)

            ok_button = Button(text="OK")
            ok_button.bind(on_press=lambda instance: popup.dismiss())
            popup_content.add_widget(ok_button)

            popup = Popup(title="Invalid Input", content=popup_content, size_hint=(None, None), size=(300, 150))
            popup.open()

    def save_password_to_file(self, password, site, username, public_key):
        file_path = os.path.join(self.save_folder_path, "passwords.txt")
        encrypted_site = self.encrypt_data(site, public_key)
        encrypted_username = self.encrypt_data(username, public_key)
        encrypted_password = self.encrypt_data(password, public_key)
        with open(file_path, 'a') as file:
            file.write(f"Site: {encrypted_site}\n")
            file.write(f"Username: {encrypted_username}\n")
            file.write(f"Password: {encrypted_password}\n\n")

    def show_my_passwords(self, instance):
        file_path = os.path.join(self.save_folder_path, "passwords.txt")
        decrypted_passwords = []
        with open(file_path, 'r') as file:
            lines = file.readlines()
            for i in range(0, len(lines), 4):
                encrypted_site = lines[i].replace("Site: ", "").strip()
                encrypted_username = lines[i+1].replace("Username: ", "").strip()
                encrypted_password = lines[i+2].replace("Password: ", "").strip()
                site = self.decrypt_data(encrypted_site, self.private_key)
                username = self.decrypt_data(encrypted_username, self.private_key)
                password = self.decrypt_data(encrypted_password, self.private_key)
                decrypted_passwords.append((site, username, password))

        popup_content = BoxLayout(orientation='vertical', padding=10, spacing=10)
        scroll_view = ScrollView()
        grid_layout = GridLayout(cols=1, spacing=10, size_hint_y=None)

        for site, username, password in decrypted_passwords:
            password_text = f"Site: {site}\nUsername: {username}\nPassword: {password}\n"
            password_label = Label(text=password_text, halign='left')
            grid_layout.add_widget(password_label)

        scroll_view.add_widget(grid_layout)
        popup_content.add_widget(scroll_view)

        popup = Popup(title="My Passwords", content=popup_content, size_hint=(None, None), size=(500, 400))
        popup.open()

    def copy_text(self, instance):
        selected_text = instance.text
        Clipboard.copy(selected_text)

    def build_context_menu(self, instance):
        menu = ContextMenu()
        copy_item = ContextMenuItem(text="Copy", on_release=self.copy_text)
        menu.add_widget(copy_item)
        instance.add_widget(menu)

    def on_start(self):
        self.root.ids.password_text.register_event_type('on_context_menu')
        self.root.ids.password_text.bind(on_context_menu=self.build_context_menu)

if __name__ == '__main__':
    PasswordGeneratorApp().run()
