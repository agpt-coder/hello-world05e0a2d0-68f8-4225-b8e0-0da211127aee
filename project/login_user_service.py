import bcrypt
import jwt
import prisma
import prisma.models
from pydantic import BaseModel


class UserLoginOutput(BaseModel):
    """
    The response model for a successful user login. It includes a message indicating success and a JWT token for accessing protected routes.
    """

    message: str
    token: str


JWT_SECRET = "your_jwt_secret"

JWT_ALGORITHM = "HS256"


async def login_user(username: str, password: str) -> UserLoginOutput:
    """
    Logs in an existing user.

    Request Body: JSON object with 'username' and 'password' fields. This route will verify the credentials and issue a JSON Web Token (JWT) for authenticated access.

    Expected Response: JSON object with 'message' indicating success and 'token' for accessing protected routes.

    Args:
    username (str): The username of the user attempting to log in.
    password (str): The password of the user attempting to log in.

    Returns:
    UserLoginOutput: The response model for a successful user login. It includes a message indicating success and a JWT token for accessing protected routes.

    Example:
    login_user('john_doe', 'password123')
    > UserLoginOutput(message='Login successful', token='<JWT_TOKEN>')
    """
    user = await prisma.models.User.prisma().find_unique(where={"email": username})
    if not user:
        raise ValueError("Invalid username or password")
    if not bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
        raise ValueError("Invalid username or password")
    token = jwt.encode({"user_id": user.id}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    response = UserLoginOutput(message="Login successful", token=token)
    return response
