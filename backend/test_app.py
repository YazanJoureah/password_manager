import unittest
import json
from app import app, init_db, encrypt_password_aes,  derive_key

class PasswordManagerTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Set up the test client and initialize the database."""
        cls.app = app.test_client()
        cls.app.testing = True
        init_db()  # Initialize the database for testing

    def test_post_password_aes(self):
        """Test the POST method for saving an AES-encrypted password."""
        password_data = {
        "name": "TestService",
        "password": "testPass123",
        "encryption_type": "aes"    
        }

        response = self.app.post('/api/passwords',
        data=json.dumps(password_data),
        content_type='application/json')

        self.assertEqual(response.status_code, 201)
        self.assertIn(b'Password saved successfully!', response.data)

   
    def test_get_passwords(self):
        """Test the GET method to retrieve saved passwords."""
        response = self.app.get('/api/passwords')
        self.assertEqual(response.status_code, 200)

        # Check if we get a list back (JSON response)
        self.assertIsInstance(json.loads(response.data), list)

    def test_invalid_encryption_type(self):
        """Test handling of an invalid encryption type."""
        invalid_password_data = {
        "name": "InvalidService",
        "password": "somePassword",
        "encryption_type": "invalid"
        }

        response = self.app.post('/api/passwords',
        data=json.dumps(invalid_password_data),
        content_type='application/json')

        self.assertEqual(response.status_code, 400)
        self.assertIn(b'Invalid encryption type', response.data)

if __name__ == '__main__':
    unittest.main()