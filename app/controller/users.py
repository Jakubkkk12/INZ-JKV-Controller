import sqlite3
from time import sleep

from passlib.hash import pbkdf2_sha256
import atexit
from app.heplers.constants import USER_DB_FILE_PATH
from app.logs.logger import DeveloperLogger


class UsersDatabaseManager:
    __instance = None
    __user_db_file_path = USER_DB_FILE_PATH

    def __new__(cls, *args, **kwargs):
        if cls.__instance is None:
            cls.__instance = super(UsersDatabaseManager, cls).__new__(cls)
            cls.__instance._initialized = False
        return cls.__instance

    def __init__(self):
        try:
            self.conn = sqlite3.connect(self.__user_db_file_path, check_same_thread=False)
            self._init_db()
            atexit.register(self.close_connection)

        except sqlite3.Error as e:
            DeveloperLogger().log_error(f"Error while connecting to users database: {e}")
            self.conn = None

    def _init_db(self):
        if not self.conn:
            return

        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute(r"CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, privilege_level INTEGER NOT NULL DEFAULT 1)")
        except sqlite3.Error as e:
            DeveloperLogger().log_error(f"Error while creating users table: {e}")

    def get_users(self) -> list[dict] | None:
        if not self.conn:
            return None

        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT username, privilege_level FROM users")
            result = cursor.fetchall()

            if result:
                users = []
                for user in result:
                    _ = {
                        "username": user[0],
                        "privilege_level": user[1],
                    }
                    users.append(_)
                return users
            else:
                return None
        except sqlite3.Error as e:
            DeveloperLogger().log_error(f"Error while getting users: {e}")
            return None

    def get_user(self, username: str) -> tuple:
        if not self.conn:
            return None, None

        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT password_hash, privilege_level FROM users WHERE username = ?",(username,))
            result = cursor.fetchone()

            if result:
                return result[0], result[1]
            else:
                return None, None
        except sqlite3.Error as e:
            DeveloperLogger().log_error(f"Error while getting user data: {e}")
            return None, None

    def register_user(self, username: str, password: str, privilege_level: int) -> bool:
        if not self.conn:
            return False

        password_hash = pbkdf2_sha256.hash(password)

        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("INSERT INTO users (username, password_hash, privilege_level) VALUES (?, ?, ?)",(username, password_hash, privilege_level))
            return True
        except sqlite3.IntegrityError:
            pass
        except sqlite3.Error as e:
            DeveloperLogger().log_error(f"Error while inserting new user: {e}")
            return False

    def update_user(self, username, new_password=None, new_privilege_level=None):
        if not self.conn:
            return False

        if new_privilege_level is None and new_password is None:
            return False

        updates = []
        params = []

        if new_privilege_level:
            updates.append("privilege_level = ?")
            params.append(new_privilege_level)

        if new_password:
            password_hash = pbkdf2_sha256.hash(new_password)
            updates.append("password_hash = ?")
            params.append(password_hash)

        params.append(username)
        set_clause = ", ".join(updates)

        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute(f"UPDATE users SET {set_clause} WHERE username = ?", tuple(params))
                if cursor.rowcount == 0:
                    return False
            return True
        except (sqlite3.IntegrityError, sqlite3.Error) as e:
            DeveloperLogger().log_error(f"Error while updating user data: {e}")
            return False

    def delete_user(self, username):
        if not self.conn:
            return False

        try:
            with self.conn:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                if cursor.rowcount == 0:
                    return False
            return True
        except sqlite3.Error as e:
            DeveloperLogger().log_error(f"Error while deleting user: {e}")
            return False

    def close_connection(self):
        if self.conn:
            self.conn.close()
