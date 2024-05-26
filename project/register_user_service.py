import hashlib

import prisma
import prisma.models
from pydantic import BaseModel


class UserRegistrationResponse(BaseModel):
    """
    The response model for user registration, containing a message indicating success along with the new user's ID and username.
    """

    message: str
    id: int
    username: str


def hash_password(password: str) -> str:
    """
    Hashes a plain text password using SHA-256.

    Args:
        password (str): The plain text password to hash.

    Returns:
        str: The hashed password.

    Example:
        hash_password("mysecretpassword")
        > '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd46cccfed146a226dd'
    """
    return hashlib.sha256(password.encode()).hexdigest()


async def register_user(username: str, password: str) -> UserRegistrationResponse:
    """
    Registers a new user.

    Request Body: JSON object with 'username' and 'password' fields. This route will create a new user in the database.

    Expected Response: JSON object with 'message' indicating success, user 'id', and 'username'.

    Args:
        username (str): The desired username for the new user.
        password (str): The password for the new user account.

    Returns:
        UserRegistrationResponse: The response model for user registration, containing a message indicating success along with the new user's ID and username.

    Example:
        register_user("john_doe", "securepassword123")
        > { "message": "User registered successfully", "id": 1, "username": "john_doe" }
    """
    hashed_password = hash_password(password)
    user = await prisma.models.User.prisma().create(
        data={"email": username, "password": hashed_password, "role": "USER"}
    )
    response = UserRegistrationResponse(
        message="User registered successfully", id=user.id, username=user.email
    )
    return response
