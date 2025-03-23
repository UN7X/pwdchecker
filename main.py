from ncce.password_data import passwords
from stdiomask import getpass
import re
import string
import random
import replit
import hashlib
import requests

# Constants for colors
GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"
CYAN = "\033[36m"

# Common Passwords List (placeholder)
# Assuming 'passwords' is imported from ncce.password_data

# Regex for checking password complexity
regex = r"""^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*:;.?&~`\[\]()|\"\''])[A-Za-z\d@$!%*:;.?&~`\[\]()|\"\'']{8,}$"""

def check_common_password(nsPassword):
    if nsPassword in passwords:
        rank = passwords.index(nsPassword) + 1
        print(f"{nsPassword} {RED}IS{RESET} a common password.")
        print(f"Popularity Rank: {rank}")
        return False
    return True

def check_pwned_api(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    url = f'https://api.pwnedpasswords.com/range/{first5_char}'
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the API and try again')
    hashes = (line.split(':') for line in response.text.splitlines())
    return any(h == tail for h, count in hashes)

def print_password_strength(nsPassword, pws):
    print(f"{nsPassword} is {GREEN if pws >= 80 else RED}{pws}% / 100%{RESET} secure, on the UniLabs Security Scale.")

def check_password_strength(nsPassword):
    pws = 0
    if check_common_password(nsPassword):
        print(f"{nsPassword} {GREEN}IS NOT{RESET} a common password.")
        pws += 20
        if len(nsPassword) >= 8:
            print(f"{nsPassword} {GREEN}Contains{RESET} at least 8 characters.")
            pws += 20
            if re.search(r'[a-z]', nsPassword) and re.search(r'[A-Z]', nsPassword):
                uppercase_count = sum(1 for c in nsPassword if c.isupper())
                lowercase_count = sum(1 for c in nsPassword if c.islower())
                print(f"{nsPassword} {GREEN}Contains{RESET} ({uppercase_count}) uppercase letters and ({lowercase_count}) lowercase letters.")
                pws += 20
                if re.search(r'[\W_]', nsPassword):
                    symbol_count = sum(1 for c in nsPassword if not c.isalnum())
                    print(f"{nsPassword} {GREEN}Contains{RESET} ({symbol_count}) special symbols.")
                    pws += 20
                    if re.search(r'\d', nsPassword):
                        digit_count = sum(1 for c in nsPassword if c.isdigit())
                        print(f"{nsPassword} {GREEN}Contains{RESET} ({digit_count}) numbers.")
                        pws += 20
                        print(f"{nsPassword} {GREEN}IS secure.{RESET}")
                    else:
                        print(f"{nsPassword} {RED}DOES NOT contain{RESET} numbers.")
                else:
                    print(f"{nsPassword} {RED}DOES NOT contain{RESET} special symbols.")
            else:
                print(f"{nsPassword} {RED}DOES NOT contain{RESET} capital and/or lowercase letters.")
        else:
            print(f"{nsPassword} {RED}DOES NOT contain{RESET} at least 8 characters.")
    print_password_strength(nsPassword, pws)
    return pws

def suggest_password_improvements(nsPassword):
    suggestions = []
    if len(nsPassword) < 12:
        suggestions.append("Make it at least 12 characters long.")
    if not re.search(r'[A-Z]', nsPassword):
        suggestions.append("Include at least one uppercase letter.")
    if not re.search(r'[a-z]', nsPassword):
        suggestions.append("Include at least one lowercase letter.")
    if not re.search(r'\d', nsPassword):
        suggestions.append("Include at least one number.")
    if not re.search(r'[\W_]', nsPassword):
        suggestions.append("Include at least one special character.")
    print("Suggestions to improve your password:")
    for suggestion in suggestions:
        print(f"- {suggestion}")
    return suggestions

def generate_password(length, include_lowercase, include_uppercase, include_digits, include_symbols):
    character_set = ''
    if include_lowercase:
        character_set += string.ascii_lowercase
    if include_uppercase:
        character_set += string.ascii_uppercase
    if include_digits:
        character_set += string.digits
    if include_symbols:
        character_set += string.punctuation
    password = ''.join(random.choice(character_set) for i in range(length))
    return password

def check_e3(password):
    issues = []
    if len(password) < 8:
        issues.append("Password is too short. It must be at least 8 characters.")
    if not re.search(r'[A-Z]', password):
        issues.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        issues.append("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        issues.append("Password must contain at least one digit.")
    if not re.search(r'[\W_]', password):
        issues.append("Password must contain at least one special character.")
    if issues:
        print(f"{password} {RED}does not meet the E3 criteria for the following reasons:{RESET}")
        for issue in issues:
            print(f"- {issue}")
    else:
        print(f"{password} {GREEN}meets the E3 criteria.{RESET}")

def main():
    while True:
        uppercase_count = 0
        lowercase_count = 0
        digit_count = 0
        symbol_count = 0
        replit.clear()
        pws = 0

        def get_bool(prompt):
            while True:
                try:
                    return {"true": True, "false": False}[input(prompt).lower()]
                except KeyError:
                    print("Please enter 'true' or 'false'.")

        print(CYAN, "Uni" + RED, "Labs", RESET, " P@ssW0rd Checker")
        print()
        print("Mode Directory:")
        print()
        print("""Quick Password Check (1) 
Common Password Detector & Ranker (2) 
Standard Password Check (3)
E3 Password Check (4)
Strong Password Generator (5)
Exit (6)""")
        print()
        ans = input("> ")
        print()
        if ans == "1":
            mode = "Quick Password Check"
            print("You've selected ", mode, "(", ans, ")")
            print()
            print("Enter Password to Check")
            password = getpass("> ")
            nsPassword = re.sub(r'\s', '', password)
            print()
            if re.match(regex, nsPassword):
                print(nsPassword, GREEN, "IS secure", RESET)
            else:
                print(nsPassword, RED, "IS NOT secure.", RESET)
            print()
            print("Type anything to continue.")
            input("> ")
        elif ans == "2":
            mode = "Common Password Detector & Ranker"
            print("You've selected ", mode, "(", ans, ")")
            print()
            print("Enter Password to Check")
            password = getpass("> ")
            nsPassword = re.sub(r'\s', '', password)
            print()
            if password in passwords:
                print(nsPassword, RED, "IS", RESET, "a common password")
                rank = passwords.index(password) + 1  # Adjust rank to start from 1
                print("Popularity Rank:", rank)
            else:
                print(nsPassword, GREEN, "IS NOT", RESET, "a common password")
            print()
            print("Type anything to continue.")
            input("> ")
        elif ans == "3":
            mode = "Standard Password Check"
            print("You've selected ", mode, "(", ans, ")")
            print()
            print("Enter Password to Check")
            password = getpass("> ")
            nsPassword = re.sub(r'\s', '', password)
            print()
            if check_pwned_api(nsPassword):
                print(f"{nsPassword} {RED}has been compromised in a data breach.{RESET}")
                print("Consider changing it immediately.")
            else:
                print(f"{nsPassword} {GREEN}is not found in data breaches.{RESET}")
            print()
            pws = check_password_strength(nsPassword)
            suggest_password_improvements(nsPassword)
            print()
            print("Type anything to continue.")
            input("> ")
        elif ans == "4":
            mode = "E3 Password Check"
            print("You've selected ", mode, "(", ans, ")")
            print()
            print("Enter Password to Check")
            password = getpass("> ")
            nsPassword = re.sub(r'\s', '', password)
            print()
            check_e3(nsPassword)
            print()
            print("Type anything to continue.")
            input("> ")
        elif ans == "5":
            print("Enter Password Length")
            print()
            l = int(input("> "))
            print()
            print("Include", GREEN, "lowercase", RESET, "letters in the password? (true/false): ")
            print()
            include_lowercase = get_bool("> ")
            print()
            print("Include", GREEN, "UPPERCASE", RESET, "letters in the password? (true/false): ")
            print()
            include_uppercase = get_bool("> ")
            print()
            print("Include", GREEN, "dig1ts", RESET, "in the password? (true/false): ")
            print()
            include_digits = get_bool("> ")
            print()
            print("Include", GREEN, "$ymbols", RESET,"in the password? (true/false):")
            print()
            include_symbols = get_bool("> ")
            print()

            password = generate_password(l, include_lowercase, include_uppercase, include_digits, include_symbols)
            print("Your Generated Password is: ", password)
            if re.search(regex, password):
                pws2 = sum([include_lowercase, include_uppercase, include_digits, include_symbols]) * 25 - 1
                print(password, GREEN, "IS Secure", RESET)
                print(password, "Is", GREEN, f"{pws2}% / 100%", RESET, "secure, on the UniLabs Security Scale.")
            else:
                print(password, RED, "IS NOT Secure.", RESET)

            print()
            print("Type anything to continue.")
            input("> ")
        elif ans == "6":
            break
        else:
            print("Invalid Option, please try again.")
            print()
            print("Type anything to continue.")
            input("> ")

if __name__ == '__main__':
    main()
