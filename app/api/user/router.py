from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from starlette import status
from app.api.auth.models import AccessTokenPrivilegeLevel3
from app.api.user.models import UserAPI
from app.controller.users import UsersDatabaseManager
from app.logs.logger import UserActionLogger


user_router = APIRouter()
access_token_privilege_level_3_dependency = AccessTokenPrivilegeLevel3()

@user_router.get("/")
async def get_users(access_token_payload: dict = Depends(access_token_privilege_level_3_dependency)):
    return await run_in_threadpool(UsersDatabaseManager().get_users)

@user_router.post("/", status_code=status.HTTP_201_CREATED)
async def create(user: UserAPI, access_token_payload: dict = Depends(access_token_privilege_level_3_dependency)):
    _, _1 = UsersDatabaseManager().get_user, user.username
    if _ is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"User {user.username} already exist")

    success = UsersDatabaseManager().register_user(user.username, user.password, user.privilege_level)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_CONFLICT, detail=f"Could not create new user {user.username}")

    UserActionLogger().log_info(f"User {user.username} created with privileges {user.privilege_level} by {access_token_payload.get('user').get('username')}")


@user_router.put("/", status_code=status.HTTP_204_NO_CONTENT)
async def update(user: UserAPI, access_token_payload: dict = Depends(access_token_privilege_level_3_dependency)):
    _, _1 = UsersDatabaseManager().get_user(user.username)
    if _ is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User {user.username} not found")

    success = UsersDatabaseManager().update_user(user.username, user.password, user.privilege_level)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_CONFLICT, detail=f"Could not update user {user.username}")

    UserActionLogger().log_info(f"User {user.username} updated by {access_token_payload.get('user').get('username')}")


@user_router.delete("/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete(username, access_token_payload: dict = Depends(access_token_privilege_level_3_dependency)):
    _, _1 = UsersDatabaseManager().get_user(username)
    if _ is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User {username} not found")

    success = UsersDatabaseManager().delete_user(username)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_CONFLICT, detail=f"Could not delete user {username}")

    UserActionLogger().log_info(f"User {username} deleted by {access_token_payload.get('user').get('username')}")

