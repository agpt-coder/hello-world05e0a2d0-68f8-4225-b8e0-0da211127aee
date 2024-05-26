from typing import Optional

import jwt
import prisma
import prisma.models
from pydantic import BaseModel


class HelloWorldRequestModel(BaseModel):
    """
    Request model for the /api/hello endpoint which requires a JWT token for authentication. It validates the user's role to ensure they are either 'user' or 'admin'.
    """

    pass


class HelloWorldResponseModel(BaseModel):
    """
    Response model for the /api/hello endpoint, returning a simple message indicating 'Hello World'.
    """

    message: str


JWT_SECRET = "your_jwt_secret"

ALGORITHM = "HS256"


def verify_jwt_token(token: str) -> Optional[dict]:
    """
    Verifies the JWT token and returns the payload if valid.

    Args:
        token (str): JWT token to be verified.

    Returns:
        Optional[dict]: Payload of the JWT token if valid, None otherwise.

    Example:
        verify_jwt_token('valid_token')
        > {'user_id': 1, 'role': 'admin'}
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_hello_world(request: HelloWorldRequestModel) -> HelloWorldResponseModel:
    """
    This endpoint returns the string 'Hello World'. It serves as a basic greeting endpoint for the application. To ensure security, this endpoint requires the user to be authenticated. The authentication process should verify that the request originates from a valid session managed by the UserManagement module. If the user is authenticated and has the 'admin' or 'user' role, the endpoint will respond with a 200 HTTP status code and the body containing 'Hello World'. If the authentication fails, the endpoint will respond with a 401 Unauthorized error.

    Args:
        request (HelloWorldRequestModel): Request model for the /api/hello endpoint which requires a JWT token for authentication. It validates the user's role to ensure they are either 'user' or 'admin'.

    Returns:
        HelloWorldResponseModel: Response model for the /api/hello endpoint, returning a simple message indicating 'Hello World'.
    """
    payload = verify_jwt_token(
        request.jwt_token
    )  # TODO(autogpt): Cannot access attribute "jwt_token" for class "HelloWorldRequestModel"
    #     Attribute "jwt_token" is unknown. reportAttributeAccessIssue
    if not payload:
        return HelloWorldResponseModel(message="Unauthorized")
    user_id: int = payload.get("user_id", None)
    user_role: str = payload.get("role", None)
    if user_id is None or user_role is None:
        return HelloWorldResponseModel(message="Unauthorized")
    user = await prisma.models.User.prisma().find_unique(where={"id": user_id})
    if user and user.role in {"USER", "ADMIN"}:
        return HelloWorldResponseModel(message="Hello World")
    return HelloWorldResponseModel(message="Unauthorized")
