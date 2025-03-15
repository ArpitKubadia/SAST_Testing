# vuln_app.py - Example highly vulnerable Python code
import subprocess
import sqlite3
import os
import pickle

# **CWE-78: OS Command Injection** - Directly executing user input
def run_command(cmd):
    subprocess.run(cmd, shell=True)  # 🔥 User-controlled input leads to arbitrary command execution

# **CWE-89: SQL Injection** - No input sanitization
def find_user(username):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()

    # 🔥 SQL Injection via unsanitized input
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)

    return cursor.fetchall()

# **CWE-94: Code Injection** - Unsafe eval() usage
def execute_python_code(user_input):
    return eval(user_input)  # 🔥 Arbitrary code execution vulnerability

# **CWE-502: Deserialization of Untrusted Data** - Dangerous pickle loading
def load_user_data(filepath):
    with open(filepath, "rb") as file:
        return pickle.load(file)  # 🔥 Untrusted file can lead to RCE

# **CWE-798: Hardcoded Credentials** - Exposing sensitive information
HARDCODED_PASSWORD = "admin123"  # 🔥 Attackers can easily retrieve this

# **CWE-22: Path Traversal** - Allowing users to read arbitrary files
def read_file(filename):
    with open(filename, "r") as file:
        return file.read()  # 🔥 Attacker can use `../../etc/passwd`

if __name__ == "__main__":
    user_input = input("Enter a command: ")
    run_command(user_input)  # Allows direct command execution

    username = input("Enter a username: ")
    find_user(username)  # Exploitable via SQL Injection

    python_code = input("Enter Python code to execute: ")
    execute_python_code(python_code)  # Allows arbitrary Python execution

    filepath = input("Enter path to user data file: ")
    load_user_data(filepath)  # Allows malicious object deserialization

    file_to_read = input("Enter filename to read: ")
    print(read_file(file_to_read))  # Allows reading of any file on the system
