import random
import string

def generate_captcha(length=5):
    captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    return captcha

def validate_captcha(actual, user_input):
    return actual.strip().lower() == user_input.strip().lower()
