import random

def generate_captcha():
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    return f"{a} + {b}", str(a + b)

def validate_captcha(expected, user_input):
    return expected.strip() == user_input.strip()
