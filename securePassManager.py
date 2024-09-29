import sys
import json
import os
import random
import string
import hashlib
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox, QListWidget, QListWidgetItem, QFormLayout
)
from PyQt5.QtGui import QClipboard

class SecurePassManager(QWidget):
    def __init__(self):
        super().__init__()
        self.passwords_file = 'passwords.json'
        self.master_password_hash = None
        self.passwords = {}
        self.load_passwords()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Secure Password Manager')
        self.setGeometry(100, 100, 400, 400)

        layout = QVBoxLayout()
        self.setLayout(layout)

        self.master_password_input = QLineEdit(self)
        self.master_password_input.setEchoMode(QLineEdit.Password)
        self.master_password_input.setPlaceholderText("Enter Master Password")
        layout.addWidget(self.master_password_input)

        self.unlock_button = QPushButton('Unlock', self)
        self.unlock_button.clicked.connect(self.unlock)
        layout.addWidget(self.unlock_button)

        self.password_list = QListWidget(self)
        layout.addWidget(self.password_list)

        self.generate_button = QPushButton('Generate Password', self)
        self.generate_button.clicked.connect(self.generate_password)
        layout.addWidget(self.generate_button)

        self.copy_button = QPushButton('Copy to Clipboard', self)
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        layout.addWidget(self.copy_button)

        self.add_button = QPushButton('Add Password', self)
        self.add_button.clicked.connect(self.add_password)
        layout.addWidget(self.add_button)

        self.delete_button = QPushButton('Delete Password', self)
        self.delete_button.clicked.connect(self.delete_password)
        layout.addWidget(self.delete_button)

    def unlock(self):
        master_password = self.master_password_input.text()
        hashed_password = hashlib.sha256(master_password.encode()).hexdigest()

        if self.master_password_hash is None:
            self.master_password_hash = hashed_password
            QMessageBox.information(self, 'Unlocked', 'Master Password set. You can now add passwords.')
        elif hashed_password == self.master_password_hash:
            QMessageBox.information(self, 'Unlocked', 'Welcome back!')
            self.load_passwords()
        else:
            QMessageBox.warning(self, 'Error', 'Incorrect Master Password!')

        self.master_password_input.clear()
        self.update_password_list()

    def generate_password(self):
        length = 12
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_list.addItem(QListWidgetItem(password))

    def copy_to_clipboard(self):
        clipboard = QClipboard()
        selected_item = self.password_list.currentItem()
        if selected_item:
            clipboard.setText(selected_item.text())
            QMessageBox.information(self, 'Copied', 'Password copied to clipboard!')
        else:
            QMessageBox.warning(self, 'Error', 'No password selected!')

    def add_password(self):
        item, ok = QInputDialog.getText(self, 'Add Password', 'Enter service name:')
        if ok and item:
            password = self.password_list.currentItem().text() if self.password_list.currentItem() else ''
            self.passwords[item] = password
            self.save_passwords()
            self.update_password_list()

    def delete_password(self):
        selected_item = self.password_list.currentItem()
        if selected_item:
            del self.passwords[selected_item.text()]
            self.save_passwords()
            self.update_password_list()
        else:
            QMessageBox.warning(self, 'Error', 'No password selected!')

    def load_passwords(self):
        if os.path.exists(self.passwords_file):
            with open(self.passwords_file, 'r') as f:
                self.passwords = json.load(f)

    def save_passwords(self):
        with open(self.passwords_file, 'w') as f:
            json.dump(self.passwords, f)

    def update_password_list(self):
        self.password_list.clear()
        for service, password in self.passwords.items():
            self.password_list.addItem(QListWidgetItem(f"{service}: {password}"))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = SecurePassManager()
    window.show()
    sys.exit(app.exec_())
