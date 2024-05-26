import jwt
import prisma
import prisma.models
from fastapi import HTTPException, status
from pydantic import BaseModel


class DeleteAccountRequest(BaseModel):
    """
    This request does not require any additional parameters other than the JWT token in the Authorization header.
    """

    pass


class DeleteAccountResponse(BaseModel):
    """
    Response indicating the success of the account deletion operation.
    """

    message: str


async def get_user_id_from_token(token: str) -> int:
    """
    Decode the JWT token to retrieve the user ID.

    Args:
        token (str): JWT token from the Authorization header.

    Returns:
        int: ID of the user.

    Example:
        token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJqb2huRG9lQGVtYWlsLmNvbSIsInJvbGUiOiJVU0VSIiwiaWF0IjoxNjE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        get_user_id_from_token(token)
        > 1
    """
    try:
        payload = jwt.decode(token, "your_secret_key", algorithms=["HS256"])
        return int(payload.get("id"))
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


async def delete_user_account(request: DeleteAccountRequest) -> DeleteAccountResponse:
    """
    Deletes the account of the logged-in user.

    This route requires a valid JWT token in the Authorization header. It removes the user's account from the database.

    Expected Response: JSON object with 'message' indicating success.

    Args:
        request (DeleteAccountRequest): This request does not require any additional parameters other than the JWT token in the Authorization header.

    Returns:
        DeleteAccountResponse: Response indicating the success of the account deletion operation.

    Example:
        request = DeleteAccountRequest()
        delete_user_account(request)
        > DeleteAccountResponse(message='User account successfully deleted.')
    """
    try:
        headers = (
            request.headers
        )  # TODO(autogpt): Cannot access attribute "headers" for class "DeleteAccountRequest"
        #     Attribute "headers" is unknown. reportAttributeAccessIssue
        authorization_header = headers.get("Authorization")
        if not authorization_header:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Authorization header missing",
            )
        token = authorization_header.split(" ")[1]
        user_id = await get_user_id_from_token(token)
        user = await prisma.models.User.prisma().find_unique(where={"id": user_id})
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        await prisma.models.Answer.prisma().delete_many(where={"createdById": user_id})
        await prisma.models.Question.prisma().delete_many(
            where={"createdById": user_id}
        )
        await prisma.models.User.prisma().delete(where={"id": user_id})
        return DeleteAccountResponse(message="User account successfully deleted.")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
