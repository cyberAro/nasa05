import unittest

from api.main import hash_password, normalize_phone, verify_password


class AuthHelperTests(unittest.TestCase):
    def test_normalizes_sri_lankan_phone_formats(self):
        self.assertEqual(normalize_phone("077 123 4567"), "+94771234567")
        self.assertEqual(normalize_phone("94771234567"), "+94771234567")
        self.assertEqual(normalize_phone("+94 (77) 123-4567"), "+94771234567")

    def test_rejects_phone_without_valid_country_code(self):
        with self.assertRaises(ValueError):
            normalize_phone("not a phone")

    def test_password_hash_verifies_without_storing_plaintext(self):
        password = "correct horse battery staple"
        stored_hash = hash_password(password)
        self.assertNotIn(password, stored_hash)
        self.assertTrue(verify_password(password, stored_hash))
        self.assertFalse(verify_password("incorrect password", stored_hash))


if __name__ == "__main__":
    unittest.main()
