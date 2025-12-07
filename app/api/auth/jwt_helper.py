import time
import traceback
from app.heplers.constants import ACCESS_TOKEN_EXPIRATION_SECONDS, REFRESH_TOKEN_EXPIRATION_SECONDS, JWT_SECRET, \
    JWT_ALGORITHM
from app.logs.logger import DeveloperLogger
import jwt

def generate_jwt_tokens(user_data: dict) -> dict:
    now = time.time()
    payload = {
        "user": user_data,
        "exp": now + ACCESS_TOKEN_EXPIRATION_SECONDS,
        "iat": now,
        "iss": "JKV",
        "refresh": False
    }
    access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    payload["exp"] = now + REFRESH_TOKEN_EXPIRATION_SECONDS
    payload["refresh"] = True
    refresh_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

def decode_jwt(token: str) -> dict | None:
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded_token
    except jwt.PyJWTError as e:
        DeveloperLogger().log_warning(f"Failed to decode JWT token: {e}")
    except Exception:
        DeveloperLogger().log_error(f"{traceback.format_exc()}")
    return None