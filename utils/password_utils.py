import re

def check_password_strength(password):
    feedback = []
    score = 0

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Password must be at least 12 characters long.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Include at least one number.")

    if re.search(r"[!@#$%^&*()_+={}\[\]:;\"'|<>,.?/~`\\-]", password):
        score += 1
    else:
        feedback.append("Use at least one special character.")

    if re.fullmatch(r"[A-Za-z0-9]*", password):
        feedback.append("Avoid simple alphanumeric-only patterns.")
        score = min(score, 3)

    if score >= 5:
        return "Strong", feedback
    elif 3 <= score < 5:
        return "Moderate", feedback
    else:
        return "Weak", feedback
