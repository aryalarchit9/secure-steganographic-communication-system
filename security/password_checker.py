import re

def check_password_strength(password):
    score = 0

    # Length check
    if len(password) >= 8:
        score += 2
    elif len(password) >= 5:
        score += 1

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 1

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 1

    # Digits
    if re.search(r"\d", password):
        score += 1

    # Special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 2

    return score