import logging
from contextlib import asynccontextmanager
from typing import Optional

import project.delete_user_account_service
import project.get_hello_world_service
import project.get_user_profile_service
import project.getHelloWorld_service
import project.login_user_service
import project.register_user_service
import project.say_hello_world_service
import project.update_user_profile_service
from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from prisma import Prisma

logger = logging.getLogger(__name__)

db_client = Prisma(auto_register=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db_client.connect()
    yield
    await db_client.disconnect()


app = FastAPI(
    title="hello world",
    lifespan=lifespan,
    description='create an app that has just one single api - which returns "Hello World"',
)


@app.get(
    "/api/users/profile",
    response_model=project.get_user_profile_service.UserProfileResponse,
)
async def api_get_get_user_profile(
    Authorization: str,
) -> project.get_user_profile_service.UserProfileResponse | Response:
    """
        Retrieves the profile of the logged-in user.

    This route requires a valid JWT token in the Authorization header. It fetches the user's profile information from the database.

    Expected Response: JSON object with user details, including 'id' and 'username'.
    """
    try:
        res = project.get_user_profile_service.get_user_profile(Authorization)
        return res
    except Exception as e:
        logger.exception("Error processing request")
        res = dict()
        res["error"] = str(e)
        return Response(
            content=jsonable_encoder(res),
            status_code=500,
            media_type="application/json",
        )


@app.put(
    "/api/users/profile",
    response_model=project.update_user_profile_service.UpdateUserProfileOutput,
)
async def api_put_update_user_profile(
    username: Optional[str], password: Optional[str]
) -> project.update_user_profile_service.UpdateUserProfileOutput | Response:
    """
        Updates the profile of the logged-in user.

    Request Body: JSON object with fields that can be updated, such as 'username' or 'password'. This route requires a valid JWT token in the Authorization header and updates the user's profile information in the database.

    Expected Response: JSON object with 'message' indicating success and updated user details.
    """
    try:
        res = project.update_user_profile_service.update_user_profile(
            username, password
        )
        return res
    except Exception as e:
        logger.exception("Error processing request")
        res = dict()
        res["error"] = str(e)
        return Response(
            content=jsonable_encoder(res),
            status_code=500,
            media_type="application/json",
        )


@app.post("/api/users/login", response_model=project.login_user_service.UserLoginOutput)
async def api_post_login_user(
    username: str, password: str
) -> project.login_user_service.UserLoginOutput | Response:
    """
        Logs in an existing user.

    Request Body: JSON object with 'username' and 'password' fields. This route will verify the credentials and issue a JSON Web Token (JWT) for authenticated access.

    Expected Response: JSON object with 'message' indicating success and 'token' for accessing protected routes.
    """
    try:
        res = await project.login_user_service.login_user(username, password)
        return res
    except Exception as e:
        logger.exception("Error processing request")
        res = dict()
        res["error"] = str(e)
        return Response(
            content=jsonable_encoder(res),
            status_code=500,
            media_type="application/json",
        )


@app.get(
    "/api/hello", response_model=project.getHelloWorld_service.GetHelloWorldResponse
)
async def api_get_getHelloWorld(
    request: project.getHelloWorld_service.GetHelloWorldRequest,
) -> project.getHelloWorld_service.GetHelloWorldResponse | Response:
    """
    This endpoint returns 'Hello World' to authenticated users. It interacts with the UserManagement module to check if the user is authenticated before returning the response. If the user is authenticated, it responds with a 200 OK status and a JSON object containing the message 'Hello World'. If the user is not authenticated, it responds with a 401 Unauthorized status.
    """
    try:
        res = await project.getHelloWorld_service.getHelloWorld(request)
        return res
    except Exception as e:
        logger.exception("Error processing request")
        res = dict()
        res["error"] = str(e)
        return Response(
            content=jsonable_encoder(res),
            status_code=500,
            media_type="application/json",
        )


@app.post(
    "/api/users/register",
    response_model=project.register_user_service.UserRegistrationResponse,
)
async def api_post_register_user(
    username: str, password: str
) -> project.register_user_service.UserRegistrationResponse | Response:
    """
        Registers a new user.

    Request Body: JSON object with 'username' and 'password' fields. This route will create a new user in the database.

    Expected Response: JSON object with 'message' indicating success, user 'id', and 'username'.
    """
    try:
        res = await project.register_user_service.register_user(username, password)
        return res
    except Exception as e:
        logger.exception("Error processing request")
        res = dict()
        res["error"] = str(e)
        return Response(
            content=jsonable_encoder(res),
            status_code=500,
            media_type="application/json",
        )


@app.get(
    "/api/hello", response_model=project.say_hello_world_service.HelloWorldResponseModel
)
async def api_get_say_hello_world(
    request: project.say_hello_world_service.HelloWorldRequestModel,
) -> project.say_hello_world_service.HelloWorldResponseModel | Response:
    """
        Returns a 'Hello World' message.

    This route requires a valid JWT token and checks the user's role. Only authenticated users can access this route. It returns a simple 'Hello World' message.

    Expected Response: JSON object with 'message' field containing 'Hello World'.
    """
    try:
        res = project.say_hello_world_service.say_hello_world(request)
        return res
    except Exception as e:
        logger.exception("Error processing request")
        res = dict()
        res["error"] = str(e)
        return Response(
            content=jsonable_encoder(res),
            status_code=500,
            media_type="application/json",
        )


@app.get(
    "/api/hello-world",
    response_model=project.get_hello_world_service.HelloWorldResponseModel,
)
async def api_get_get_hello_world(
    request: project.get_hello_world_service.HelloWorldRequestModel,
) -> project.get_hello_world_service.HelloWorldResponseModel | Response:
    """
    This endpoint returns the string 'Hello World'. It serves as a basic greeting endpoint for the application. To ensure security, this endpoint requires the user to be authenticated. The authentication process should verify that the request originates from a valid session managed by the UserManagement module. If the user is authenticated and has the 'admin' or 'user' role, the endpoint will respond with a 200 HTTP status code and the body containing 'Hello World'. If the authentication fails, the endpoint will respond with a 401 Unauthorized error.
    """
    try:
        res = await project.get_hello_world_service.get_hello_world(request)
        return res
    except Exception as e:
        logger.exception("Error processing request")
        res = dict()
        res["error"] = str(e)
        return Response(
            content=jsonable_encoder(res),
            status_code=500,
            media_type="application/json",
        )


@app.delete(
    "/api/users/account",
    response_model=project.delete_user_account_service.DeleteAccountResponse,
)
async def api_delete_delete_user_account(
    request: project.delete_user_account_service.DeleteAccountRequest,
) -> project.delete_user_account_service.DeleteAccountResponse | Response:
    """
        Deletes the account of the logged-in user.

    This route requires a valid JWT token in the Authorization header. It removes the user's account from the database.

    Expected Response: JSON object with 'message' indicating success.
    """
    try:
        res = await project.delete_user_account_service.delete_user_account(request)
        return res
    except Exception as e:
        logger.exception("Error processing request")
        res = dict()
        res["error"] = str(e)
        return Response(
            content=jsonable_encoder(res),
            status_code=500,
            media_type="application/json",
        )
