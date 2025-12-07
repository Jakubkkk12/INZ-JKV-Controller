import re
from pydantic import BaseModel, field_validator

class UserAPI(BaseModel):
    username: str
    password: str
    privilege_level: int

    @field_validator("privilege_level")
    def check_setup(cls, v):
        if not (1 <= v <= 3):
            raise ValueError("privilege_level must be between 1 and 3")
        return v

    @field_validator("password")
    def check_password(cls, value: str) -> str:
        """
        Password must contain at least 16 characters, 1 lowercase letter, 1 uppercase letter, 1 number and 1 special character with: !@#$%^&*()-+
        """
        if len(value) < 16:
            raise ValueError("password must contain at least 16 characters")

        password_regex = re.compile(
            r'^(?=.*[a-z])'
            r'(?=.*[A-Z])'  
            r'(?=.*\d)'  
            r'(?=.*[!@#$%^&*()-+])' 
            r'.{16,}$'
        )

        if not password_regex.match(value):
            raise ValueError("password must contain 1 lowercase letter, 1 uppercase letter, 1 number and 1 special character with: !@#$%^&*()-+")
        return value

    class Config:
        json_schema_extra = {
            "example": {
                "username": "user007",
                "password": "Str0ngPa$$w0rd@007",
                "privilege_level": 1
            }
        }
