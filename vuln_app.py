# vuln_app.py - Example vulnerable Python code
import subprocess, sqlite3

def run_command(cmd):
    print("Running Cmd")
    #subprocess.run(cmd, shell=True)  # CWE-78: OS Command Injection

def find_user(username):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    # **Unsafe** string formatting of SQL command:
    #query = f"SELECT * FROM users WHERE name = '{username}'"
    query = "SELECT * FROM users WHERE name = 'Arpit'"
    cursor.execute(query)            # CWE-89: SQL Injection

if __name__ == "__main__":
    user_input = input("Enter a value:  ")
    run_command("echo " + user_input)
    find_user(user_input)
