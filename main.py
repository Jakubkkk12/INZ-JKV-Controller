import uvicorn
from app.controller.users import UsersDatabaseManager
from app.heplers.constants import DEFAULT_USER_USERNAME, DEFAULT_USER_PASSWORD, DEFAULT_USER_PRIVILEGE_LEVEL

if __name__ == '__main__':
    print("START")
    UsersDatabaseManager().register_user(DEFAULT_USER_USERNAME, DEFAULT_USER_PASSWORD, DEFAULT_USER_PRIVILEGE_LEVEL)
    uvicorn.run("app.api.api:app", host="0.0.0.0", port=8081, reload=True)
    print("FINISH")

