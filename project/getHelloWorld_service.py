import jwt
import prisma
import prisma.models
from fastapi import HTTPException
from pydantic import BaseModel


class GetHelloWorldRequest(BaseModel):
    """
    This request model is used for the hello world endpoint. No parameters are needed.
    """

    pass


class GetHelloWorldResponse(BaseModel):
    """
    This response model returns 'Hello World' in a JSON object to authenticated users.
    """

    message: str


async def get_user_by_auth_token(token: str) -> bool:
    """
    Validates if a user exists for a given authentication token.

    Args:
        token (str): The authentication token of the user.

    Returns:
        bool: True if the user exists and is authenticated,
              otherwise False.

    Example:
        get_user_by_auth_token("valid_token")
        > True
    """
    try:
        decoded_token = jwt.decode(token, "secret_key", algorithms=["HS256"])
        user_email = decoded_token.get("email")
        if not user_email:
            return False
        user = await prisma.models.User.prisma().find_first(where={"email": user_email})
        if user:
            return True
        return False
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return False


async def get_hello_world_from_db() -> str:
    """
    Retrieves the 'Hello World' message from the database.

    Args:
        None

    Returns:
        str: The 'Hello World' message retrieved from the database.

    Example:
        get_hello_world_from_db()
        > "Hello World"
    """
    hello_world = await prisma.models.HelloWorld.prisma().find_first()
    return hello_world.text if hello_world else "Hello World"


async def getHelloWorld(request: GetHelloWorldRequest) -> GetHelloWorldResponse:
    """
    This endpoint returns 'Hello World' to authenticated users. It interacts with the UserManagement module
    to check if the user is authenticated before returning the response. If the user is authenticated, it responds
    with a 200 OK status and a JSON object containing the message 'Hello World'. If the user is not authenticated,
    it responds with a 401 Unauthorized status.

    Args:
        request (GetHelloWorldRequest): This request model is used for the hello world endpoint. No parameters are needed.

    Returns:
        GetHelloWorldResponse: This response model returns 'Hello World' in a JSON object to authenticated users.
    """
    token = "valid_token"
    if not await get_user_by_auth_token(token):
        raise HTTPException(status_code=401, detail="Unauthorized")
    message = await get_hello_world_from_db()
    return GetHelloWorldResponse(message=message)
