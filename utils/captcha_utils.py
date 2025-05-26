import random
import string

def generate_captcha(length=6):
    characters = string.ascii_uppercase + string.digits
    captcha = ''.join(random.choices(characters, k=length))
    return captcha

def validate_captcha(correct, entered):
    return correct.strip().lower() == entered.strip().lower()
