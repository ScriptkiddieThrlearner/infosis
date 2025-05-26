import re

def is_valid_email(email):
    """Validate email using regex pattern."""
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w{2,}$"
    return re.match(pattern, email)

def is_valid_username(username):
    """Check if username is at least 4 characters and alphanumeric."""
    return len(username) >= 4 and username.isalnum()
