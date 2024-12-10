import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:
    def __init__(self, master_password):
        """
        Initialize the Password Manager with a master password.

        Args:
            master_password (str): The master password used to encrypt/decrypt passwords
        """
        # Generate a key from the master password
        self.key = self._generate_key(master_password)
        self.cipher_suite = Fernet(self.key)

        # File to store encrypted passwords
        self.storage_file = 'password_vault.txt'

        # Initialize the storage file if it doesn't exist
        if not os.path.exists(self.storage_file):
            open(self.storage_file, 'w').close()

    def _generate_key(self, master_password):
        """
        Generate a cryptographic key from the master password.

        Args:
            master_password (str): The master password

        Returns:
            bytes: A secure encryption key
        """
        # Use a salt to make key generation more secure
        salt = b'secure_password_salt'

        # Key Derivation Function to create a secure key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )

        # Convert master password to bytes and derive key
        key = base64.urlsafe_b64encode(
            kdf.derive(master_password.encode())
        )
        return key

    def add_password(self, service, username, password):
        """
        Add a new password entry to the vault.

        Args:
            service (str): Name of the service/website
            username (str): Username for the service
            password (str): Password to be stored
        """
        # Combine credentials into a single string
        entry = f"{service}:{username}:{password}"

        # Encrypt the entry
        encrypted_entry = self.cipher_suite.encrypt(entry.encode())

        # Append to the storage file
        with open(self.storage_file, 'ab') as file:
            file.write(encrypted_entry + b'\n')

        print(f"Password for {service} added successfully!")

    def get_password(self, service):
        """
        Retrieve passwords for a specific service.

        Args:
            service (str): Name of the service to retrieve passwords for

        Returns:
            list: List of matching username/password tuples
        """
        matches = []

        # Read and decrypt entries
        with open(self.storage_file, 'rb') as file:
            for line in file:
                try:
                    # Decrypt the line
                    decrypted_entry = self.cipher_suite.decrypt(line.strip()).decode()
                    stored_service, stored_username, stored_password = decrypted_entry.split(':')

                    # Check if service matches
                    if stored_service == service:
                        matches.append((stored_username, stored_password))
                except Exception:
                    # Skip any entries that can't be decrypted (e.g., wrong key)
                    pass

        return matches

    def list_services(self):
        """
        List all unique services in the password vault.

        Returns:
            list: Unique service names
        """
        services = set()

        # Read and decrypt entries
        with open(self.storage_file, 'rb') as file:
            for line in file:
                try:
                    # Decrypt the line
                    decrypted_entry = self.cipher_suite.decrypt(line.strip()).decode()
                    services.add(decrypted_entry.split(':')[0])
                except Exception:
                    # Skip any entries that can't be decrypted
                    pass

        return list(services)


def main():
    # Example usage
    print("Welcome to Password Manager")
    master_password = input("Enter your master password: ")

    # Create password manager instance
    pm = PasswordManager(master_password)

    while True:
        print("\n1. Add Password")
        print("2. Get Password")
        print("3. List Services")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            service = input("Enter service name: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            pm.add_password(service, username, password)

        elif choice == '2':
            service = input("Enter service name: ")
            passwords = pm.get_password(service)
            if passwords:
                for username, password in passwords:
                    print(f"Username: {username}, Password: {password}")
            else:
                print("No passwords found for this service.")

        elif choice == '3':
            services = pm.list_services()
            print("Stored Services:")
            for service in services:
                print(service)

        elif choice == '4':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()