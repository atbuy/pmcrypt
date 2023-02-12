import os
from unittest import TestCase

from pmcrypt import PasswordManager


class TestHash(TestCase):
    def setUp(self):
        self.manager = PasswordManager()

    def test_hashed(self):
        """Test password hashing."""

        password = "password"
        hashed, salt = self.manager.hash(password)

        self.assertEqual(len(hashed), 64)
        self.assertEqual(len(salt), 32)

    def test_salt(self):
        """Test salt generation."""

        salt = self.manager.generate_salt()

        self.assertEqual(len(salt), 32)

    def test_pepper(self):
        """Test pepper generation."""

        os.environ["PEPPER"] = "pepper"

        pepper = self.manager.get_pepper()

        self.assertEqual(len(pepper), 6)

    def test_check(self):
        """Test password checking."""

        password = "password"
        hashed, salt = self.manager.hash(password)
        checked = self.manager.check(password, hashed, salt)

        self.assertTrue(checked)

    def test_password_salting(self):
        """Two hashed identical passwords should be different if salted differently."""

        password = "password"
        hashed1, salt1 = self.manager.hash(password)
        hashed2, salt2 = self.manager.hash(password)

        self.assertNotEqual(hashed1, hashed2)
        self.assertNotEqual(salt1, salt2)

    def test_password_pepper(self):
        """Test password hashing with pepper. Use same salt."""

        # Set pepper
        os.environ["PEPPER"] = "pepper"

        password = "password"
        salt = "test"

        hashed1, salt1 = self.manager.hash(password, salt)
        hashed2, salt2 = self.manager.hash(password, salt)

        self.assertEqual(salt1, salt2)
        self.assertEqual(hashed1, hashed2)

    def test_no_iterations(self):
        """Test hashing with 0 iterations"""

        password = "password"
        hashed, salt = self.manager.hash(password, iterations=0)

        self.assertEqual(len(hashed), len(password))
        self.assertEqual(len(salt), 32)
