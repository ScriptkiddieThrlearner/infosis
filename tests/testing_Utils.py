import unittest
import bcrypt
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.password_utils import check_password_strength
from utils.captcha_utils import generate_captcha, validate_captcha
from utils.db_utils import save_user, load_users
from main import authenticate

class TestPasswordStrength(unittest.TestCase):
    def test_weak_password(self):
        strength, _ = check_password_strength("abc")
        self.assertEqual(strength, "Weak")

    def test_moderate_password(self):
        strength, _ = check_password_strength("Abcdef@123")
        self.assertEqual(strength, "Moderate")

    def test_strong_password(self):
        strength, _ = check_password_strength("Kis!ybendhs@_9273.")
        self.assertEqual(strength, "Strong")


class TestCaptcha(unittest.TestCase):
    def test_validate_captcha_correct(self):
        self.assertTrue(validate_captcha("12", "12"))

    def test_validate_captcha_wrong(self):
        self.assertFalse(validate_captcha("12", "15"))

    def test_generate_captcha_format(self):
        question, answer = generate_captcha()
        self.assertIn('+', question)
        self.assertTrue(answer.isdigit())


class TestAuthentication(unittest.TestCase):
    def test_authenticate_success(self):
        username = "testuser"
        password = "Test@123"
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        users = load_users()
        save_user(username, hashed)

        self.assertTrue(authenticate(username, password))

    def test_authenticate_fail(self):
        self.assertFalse(authenticate("fakeuser", "WrongPass"))

if __name__ == '__main__':
    unittest.main()
