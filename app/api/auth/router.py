from fastapi import APIRouter, HTTPException, Depends
from fastapi.concurrency import run_in_threadpool
from passlib.handlers.pbkdf2 import pbkdf2_sha256
from starlette import status
from app.api.auth.jwt_helper import generate_jwt_tokens
from app.api.auth.models import CredentialsAPI, RefreshToken, TokensAPIResponse
from app.controller.users import UsersDatabaseManager
from app.logs.logger import UserActionLogger

auth_router = APIRouter()
refresh_token_dependency = RefreshToken()

@auth_router.post("/", response_model=TokensAPIResponse)
async def login(user: CredentialsAPI):
    is_correct_user = False
    user_privilege_level = 1
    try:
        user_password_hash, user_privilege_level = await run_in_threadpool(UsersDatabaseManager().get_user, user.username)
        if user_password_hash is not None and user_privilege_level is not None and pbkdf2_sha256.verify(user.password, user_password_hash):
            is_correct_user = True
    except Exception:
        pass

    if not is_correct_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    user_data = {
        "username": user.username,
        "privilege_level": user_privilege_level
    }
    tokens = generate_jwt_tokens(user_data)
    UserActionLogger().log_info(f"User {user.username} logged in")
    return tokens


@auth_router.get("/tokens", response_model=TokensAPIResponse)
async def get_auth_tokens(refresh_token_payload: dict = Depends(refresh_token_dependency)):
    user_data = refresh_token_payload.get("user")
    tokens = await run_in_threadpool(generate_jwt_tokens, user_data)
    UserActionLogger().log_info(f"User {user_data.get('username')} use refresh token")
    return tokens




