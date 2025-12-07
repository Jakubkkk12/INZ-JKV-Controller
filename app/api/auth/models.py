from pydantic import BaseModel
from starlette import status
from app.api.auth.jwt_helper import decode_jwt
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


class CredentialsAPI(BaseModel):
    username: str
    password: str

    class Config:
        json_schema_extra = {
            "example": {
                "username": "user007",
                "password": "strongpassword"
            }
        }


class TokensAPIResponse(BaseModel):
    access_token: str
    refresh_token: str


class AuthBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(AuthBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(AuthBearer, self).__call__(request)
        if not credentials:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No credentials")
        if not credentials.scheme == "Bearer":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authorization header must be Bearer")

        self.verify_token(credentials.credentials)
        token_payload = decode_jwt(credentials.credentials)
        self.verify_token_payload(token_payload)
        self.verify_privilege_level(token_payload['user']['privilege_level'])

        return token_payload

    def verify_token(self, jwt_token: str) -> None:
        try:
            decode_jwt(jwt_token)
        except:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Unauthorized")

    def verify_token_payload(self, token_payload: dict) -> None:
        raise NotImplementedError

    def verify_privilege_level(self, privilege_level: int) -> None:
        raise NotImplementedError


class AccessToken(AuthBearer):
    def verify_token_payload(self, token_payload: dict) -> None:
        if token_payload is None or token_payload['refresh']:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Provide access token")

    def verify_privilege_level(self, privilege_level: int) -> None:
        raise NotImplementedError


class RefreshToken(AuthBearer):
    def verify_token_payload(self, token_payload: dict) -> None:
        if token_payload is None or not token_payload['refresh']:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Provide refresh token")

    def verify_privilege_level(self, privilege_level: int) -> None:
        pass


class AccessTokenPrivilegeLevel1(AccessToken):
    def verify_privilege_level(self, privilege_level: int) -> None:
        if privilege_level < 1:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges")


class AccessTokenPrivilegeLevel2(AccessToken):
    def verify_privilege_level(self, privilege_level: int) -> None:
        if privilege_level < 2:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges")


class AccessTokenPrivilegeLevel3(AccessToken):
    def verify_privilege_level(self, privilege_level: int) -> None:
        if privilege_level < 3:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges")
