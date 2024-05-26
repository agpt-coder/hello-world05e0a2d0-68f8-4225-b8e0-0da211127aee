from typing import List

import jwt
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


def decode_jwt(token: str, secret_key: str, algorithms: List[str]) -> dict:
    """
    Decodes the JWT token to extract the payload.

    Args:
        token (str): The JWT token to decode.
        secret_key (str): The secret key used to decode the token.
        algorithms (list[str]): The algorithms used for decoding the token.

    Returns:
        dict: The decoded token payload.

    Example:
        decode_jwt("token_string", "secret", ["HS256"])
        => {"sub": "1234567890", "name": "John Doe", "role": "USER", "iat": 1516239022}
    """
    try:
        decoded = jwt.decode(token, secret_key, algorithms=algorithms)
        return decoded
    except jwt.PyJWTError:
        return {}


def say_hello_world(request: HelloWorldRequestModel) -> HelloWorldResponseModel:
    """
    Returns a 'Hello World' message.

    This route requires a valid JWT token and checks the user's role. Only authenticated users can access this route.
    It returns a simple 'Hello World' message.

    Expected Response: JSON object with 'message' field containing 'Hello World'.

    Args:
        request (HelloWorldRequestModel): Request model for the /api/hello endpoint which requires a JWT token
                                           for authentication. It validates the user's role to ensure they are
                                           either 'USER' or 'ADMIN'.

    Returns:
        HelloWorldResponseModel: Response model for the /api/hello endpoint, returning a simple message indicating 'Hello World'.

    Example:
        request = HelloWorldRequestModel(token="jwt_token_string")
        say_hello_world(request)
        => HelloWorldResponseModel(message="Hello World")
    """
    secret_key: str = "your_secret_key"
    algorithms: List[str] = ["HS256"]
    payload = decode_jwt(
        request.token, secret_key, algorithms
    )  # TODO(autogpt): Cannot access attribute "token" for class "HelloWorldRequestModel"
    #     Attribute "token" is unknown. reportAttributeAccessIssue
    if payload and "role" in payload and (payload["role"] in {"USER", "ADMIN"}):
        return HelloWorldResponseModel(message="Hello World")
    return HelloWorldResponseModel(message="Unauthorized")
