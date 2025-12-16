# Password Manager Final Project

# Import Modules Needed

import re
import json
import sqlite3
import hashlib
from datetime import datetime
import requests
from bs4 import BeautifulSoup


#Use of Regex


def validate_password(password: str) -> bool:
    """
    Password must:
    - Be at least 8 characters
    - Contain uppercase letter
    - Contain number
    - Contain special character
    """
    pattern = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$"
    return bool(re.match(pattern, password))



#Ethics + Security: Hashing
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


#Input Validation 
def get_non_empty(prompt):
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Input cannot be empty.")


#OOP- base class

class PasswordManager:
    def __init__(self, owner):
        self.owner = owner

    def add_password(self, service, username, password):
        raise NotImplementedError("Subclasses must implement add_password")

    def get_password(self, service):
        raise NotImplementedError("Subclasses must implement get_password")



#Containers + File I/O
class FilePasswordManager(PasswordManager):
    def __init__(self, owner, filename="passwords.json"):
        super().__init__(owner)
        self.filename = filename
        self.passwords = self._load()

    def _load(self):
        try:
            with open(self.filename, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save(self):
        with open(self.filename, "w") as f:
            json.dump(self.passwords, f, indent=4)

    def add_password(self, service, username, password):
        if service in self.passwords:
            raise ValueError("Service already exists.")
        if not validate_password(password):
            raise ValueError("Password does not meet strength requirements.")

        self.passwords[service] = (
            username,
            hash_password(password),
            datetime.now().isoformat()
        )
        self._save()

    def get_password(self, service):
        return self.passwords.get(service)


#Database + SQL
class DatabasePasswordManager(PasswordManager):
    def __init__(self, owner, db_name="passwords.db"):
        super().__init__(owner)
        self.conn = sqlite3.connect(db_name)
        self._create_table()

    def _create_table(self):
        cur = self.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                service TEXT,
                username TEXT,
                password TEXT,
                created_at TEXT
            )
        """)
        self.conn.commit()

    def add_password(self, service, username, password):
        if not validate_password(password):
            raise ValueError("Password does not meet strength requirements.")
        try:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO credentials VALUES (?, ?, ?, ?)",
                (service, username, hash_password(password), datetime.now().isoformat())
            )
            self.conn.commit()
        except sqlite3.Error as e:
            print("Database error:", e)

    def get_password(self, service):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM credentials WHERE service = ?", (service,))
        return cur.fetchone()


#Data on the Web
def check_password_breach(password):
    """
    Checks if a password prefix exists in a public breach database.
    Demonstrates using external web data.
    """
    try:
        response = requests.get(
            "https://api.pwnedpasswords.com/range/" + password[:5],
            timeout=5
        )
        return response.status_code == 200
    except requests.RequestException:
        return False

#Web scraping

def scrape_password_guidelines():
    """
    Scrapes publicly available password guidelines from a government site.
    Demonstrates ethical web scraping.
    """
    url = "https://www.cisa.gov/password-guidance"
    response = requests.get(url, timeout=5)
    soup = BeautifulSoup(response.text, "html.parser")

    guidelines = []
    for p in soup.find_all("p"):
        text = p.get_text(strip=True)
        if text:
            guidelines.append(text)

    return guidelines[:3]

#Data Analysis

def analyze_passwords(file="passwords.json"):
    import pandas as pd

    with open(file) as f:
        data = json.load(f)

    rows = []
    for service, (user, pw, date) in data.items():
        rows.append({
            "service": service,
            "username": user,
            "hash_length": len(pw),
            "created": date
        })

    df = pd.DataFrame(rows)
    return df.describe()

def main():
    print("=== Password Manager ===")
    manager = FilePasswordManager("User")

    while True:
        print("\n1) Add Password\n2) Get Password\n3) Exit")
        choice = input("Choose: ")

        if choice == "1":
            service = get_non_empty("Service: ")
            username = get_non_empty("Username: ")
            password = get_non_empty("Password: ")
            try:
                manager.add_password(service, username, password)
                print("Password saved successfully.")
            except ValueError as e:
                print("Error:", e)

        elif choice == "2":
            service = get_non_empty("Service: ")
            result = manager.get_password(service)
            if result:
                print(result)
            else:
                print("No password found for that service.")

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Please choose a valid option.")


if __name__ == "__main__":
    main()
