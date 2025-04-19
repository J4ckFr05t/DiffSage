from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()

fernet = Fernet(os.environ["ENCRYPTION_KEY"].encode())

def encrypt_token(token: str) -> str:
    return fernet.encrypt(token.encode()).decode()

def decrypt_token(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()