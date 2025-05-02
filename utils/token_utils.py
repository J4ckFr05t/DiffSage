from itsdangerous import URLSafeTimedSerializer
import os

def generate_reset_token(email, secret_key, salt="password-reset"):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(email, salt=salt)

def verify_reset_token(token, secret_key, max_age=3600, salt="password-reset"):
    serializer = URLSafeTimedSerializer(secret_key)
    try:
        email = serializer.loads(token, salt=salt, max_age=max_age)
        return email
    except Exception:
        return None