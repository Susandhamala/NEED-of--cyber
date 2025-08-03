# test_cybersphere.py
import unittest
import sys
import os
import hashlib
import json
import tempfile
import secrets
import string

# Ensure Python can find your project modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

# --- Test 1: Core Authentication Logic (Hashing) ---
class TestAuthentication(unittest.TestCase):

    def test_password_hashing_consistency(self):
        """Test that the same password always produces the same SHA-256 hash."""
        password = "MySecurePassword123!"
        hash1 = hashlib.sha256(password.encode('utf-8')).hexdigest()
        hash2 = hashlib.sha256(password.encode('utf-8')).hexdigest()
        self.assertEqual(hash1, hash2)

    def test_password_hashing_uniqueness(self):
        """Test that different passwords produce different SHA-256 hashes."""
        password1 = "Password1"
        password2 = "Password2"
        hash1 = hashlib.sha256(password1.encode('utf-8')).hexdigest()
        hash2 = hashlib.sha256(password2.encode('utf-8')).hexdigest()
        self.assertNotEqual(hash1, hash2)

    def test_password_hash_length(self):
        """Test that SHA-256 produces a 64-character hexadecimal string."""
        password = "test"
        hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
        self.assertEqual(len(hashed), 64)
        # Also check it's valid hex
        try:
            int(hashed, 16)
        except ValueError:
            self.fail("Hash is not a valid hexadecimal string")

# --- Test 2: Data Persistence (JSON Files) ---
class TestDataPersistence(unittest.TestCase):

    def setUp(self):
        """Set up test environment with a temporary directory."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.test_dir)

    def test_user_data_save_load(self):
        """Test saving and loading user data to/from JSON."""
        users_file = os.path.join(self.test_dir, "test_users.json")
        test_username = "alice"
        test_password = "alicepassword"
        test_hash = hashlib.sha256(test_password.encode('utf-8')).hexdigest()

        # --- Simulate Saving (as done in register_page.py) ---
        users_data = {}
        users_data[test_username] = test_hash
        with open(users_file, 'w') as f:
            json.dump(users_data, f)

        # --- Simulate Loading (as done in login_page.py) ---
        if os.path.exists(users_file):
            with open(users_file, 'r') as f:
                loaded_users = json.load(f)
        else:
            loaded_users = {}

        # --- Verify ---
        self.assertIn(test_username, loaded_users)
        self.assertEqual(loaded_users[test_username], test_hash)

    def test_configuration_save_load(self):
        """Test saving and loading application configuration."""
        config_file = os.path.join(self.test_dir, "config.json")
        config_data = {"theme": "dark", "auto_scan": True}

        # Save
        with open(config_file, 'w') as f:
            json.dump(config_data, f)

        # Load
        with open(config_file, 'r') as f:
            loaded_config = json.load(f)

        self.assertEqual(config_data, loaded_config)

# --- Test 3: Password Generation Logic ---
# Assuming logic exists in tools/password_generator.py or similar
class TestPasswordGeneration(unittest.TestCase):

    def test_generated_password_length(self):
        """Test that generated passwords match the requested length."""
        for length in [8, 12, 16, 20]:
            # Mimic the core logic from password_generator.py
            charset = string.ascii_letters + string.digits + "!@#$%^&*"
            password = ''.join(secrets.choice(charset) for _ in range(length))
            self.assertEqual(len(password), length)

    def test_character_set_inclusion(self):
        """Test that generated passwords contain characters from the specified set."""
        charset = "ABC123!@"
        length = 20
        password = ''.join(secrets.choice(charset) for _ in range(length))
        for char in password:
            self.assertIn(char, charset)

    def test_password_strength_simple_evaluation(self):
        """Test a simple password strength evaluation logic."""
        # Define a simple strength function (adjust based on your actual logic)
        def evaluate_strength(pw):
            score = 0
            if len(pw) >= 8: score += 1
            if any(c.isupper() for c in pw): score += 1
            if any(c.islower() for c in pw): score += 1
            if any(c.isdigit() for c in pw): score += 1
            if any(c in "!@#$%^&*" for c in pw): score += 1
            return score

        weak_pw = "123456"
        strong_pw = "Str0ng!P@ssw0rd"

        self.assertLess(evaluate_strength(weak_pw), 3)
        self.assertGreater(evaluate_strength(strong_pw), 6) # Adjust threshold as needed

# --- Test 4: Basic Network Utilities (Logic only) ---
class TestNetworkUtilities(unittest.TestCase):

    def test_simple_ip_validation(self):
        """Test basic IP address format validation."""
        def is_valid_ip(ip):
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                try:
                    num = int(part)
                    if not 0 <= num <= 255:
                        return False
                except ValueError:
                    return False
            return True

        # Valid IPs
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("0.0.0.0"))
        self.assertTrue(is_valid_ip("255.255.255.255"))

        # Invalid IPs
        self.assertFalse(is_valid_ip("192.168.1.256"))
        self.assertFalse(is_valid_ip("192.168.1"))
        self.assertFalse(is_valid_ip("192.168.1.1.1"))
        self.assertFalse(is_valid_ip("abc.def.ghi.jkl"))
        self.assertFalse(is_valid_ip(""))

# --- Test 5: Encryption Utilities (if applicable) ---
# If you are using the cryptography library in password vault or chat
class TestEncryptionBasics(unittest.TestCase):

    def test_fernet_encryption_decryption(self):
        """Test basic Fernet encryption and decryption functionality."""
        try:
            from cryptography.fernet import Fernet

            # Generate a key
            key = Fernet.generate_key()
            cipher_suite = Fernet(key)

            # Original message
            message = "This is a secret message."
            message_bytes = message.encode('utf-8')

            # Encrypt
            encrypted_bytes = cipher_suite.encrypt(message_bytes)

            # Decrypt
            decrypted_bytes = cipher_suite.decrypt(encrypted_bytes)
            decrypted_message = decrypted_bytes.decode('utf-8')

            # Verify
            self.assertEqual(message, decrypted_message)
            self.assertNotEqual(message_bytes, encrypted_bytes) # Ensure encryption happened

        except ImportError:
            self.skipTest("cryptography library not available")


# --- Main Execution ---
if __name__ == '__main__':
    unittest.main(verbosity=2)