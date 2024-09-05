from fastapi import APIRouter, Depends, status, BackgroundTasks
from sqlmodel.ext.asyncio.session import AsyncSession
from fastapi.exceptions import HTTPException
from src.auth.schemas import (
    UserCreateModel, UserLoginModel, UserBookModel,
    EmailModel, PasswordResetRequestModel, PasswordResetConfirmModel
)
from .service import UserService
from src.db.main import get_session
from .utils import (
    create_access_token, verify_password,
    create_url_safe_token, decode_url_safe_token, generate_hash
)
from datetime import timedelta, datetime
from fastapi.responses import JSONResponse
from .dependencies import RefreshTokenBearer, AccessTokenBearer,get_current_user, RoleChecker
from src.db.redis import add_jti_to_blocklist
from src.errors import UserAlreadyExists, InvalidCredentials, UserNotFound
from src.mail import create_message, fm
from ..config import Config

auth_router = APIRouter()
user_service = UserService()
role_checker = RoleChecker(['admin'])

REFRESH_TOKEN_EXPIRY = 2


@auth_router.post('/send_mail')
async def send_mail(emails: EmailModel):
    emails = emails.addresses

    html = "<h3>Welcome to the Bookly app. Thank you for signing up.</h3>"

    message = create_message(
        recipients=emails, subject="Welcome", body=html
    )

    await fm.send_message(message)
    return {"message": "Email sent successfully"}

@auth_router.post(
    '/signup',
    status_code=status.HTTP_201_CREATED,
)
async def create_user_account(
        user_data: UserCreateModel,
        bg_tasks: BackgroundTasks,
        session: AsyncSession = Depends(get_session)
):
    email = user_data.email
    user_exists = await user_service.user_exists(email, session)

    if user_exists:
        raise UserAlreadyExists()
    else:
        new_user = await user_service.create_user(user_data, session)

        token = create_url_safe_token({"email": email})

        link = f"http://{Config.DOMAIN}/api/v1/auth/verify/{token}"

        html_message = f""" 
        <h1>Verify your email</h1>
        <p>Please click this <a href="{link}">link</a> to verify your email</p>
        """
        message = create_message(
            recipients=[email], subject="Verify your email", body=html_message
        )

        # await fm.send_message(message)
        bg_tasks.add_task(fm.send_message,message)

        return {
            "message": "Account created! Check email to verify your account. ",
            "user": new_user
        }


@auth_router.get('/verify/{token}')
async def verify_user_account(token: str, session: AsyncSession = Depends(get_session)):
    token_data = decode_url_safe_token(token)

    user_email = token_data.get('email')

    if user_email:
        user = await user_service.get_user_by_email(user_email, session=session)

        if not user:
            raise UserNotFound()

        await user_service.update_user(user, {"isVerified": True}, session)

        return JSONResponse(
            content={
                "message": "Account verification successful."
            },
            status_code=status.HTTP_200_OK
        )
    return JSONResponse(
        content={"message": "Error occurred during verification"},
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
    )


@auth_router.post('/login')
async def login_user(
        login_data: UserLoginModel,
        session: AsyncSession = Depends(get_session)
):
    email = login_data.email
    password = login_data.password

    user = await user_service.get_user_by_email(email,session)
    if user is not None:
        is_password_valid = verify_password(password, user.password_hash)

        if is_password_valid:
            access_token = create_access_token(
                user_data={'email': user.email, 'user_uid': str(user.uid), "role": user.role}
            )

            refresh_token = create_access_token(
                user_data={'email': user.email, 'user_uid': str(user.uid)},
                refresh=True, expiry=timedelta(days=REFRESH_TOKEN_EXPIRY)
            )

            return JSONResponse(
                content={
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "email": user.email,
                        "uid": str(user.uid)
                    }
                }
            )

    raise InvalidCredentials()

@auth_router.get('/refresh_token')
async def get_new_access_token(token_details: dict = Depends(RefreshTokenBearer())):
    print('Details', token_details)
    expiry_timestamp = token_details['exp']

    if datetime.fromtimestamp(expiry_timestamp) > datetime.now():
        new_access_token = create_access_token(user_data=token_details['user'])

        return JSONResponse(content={"access_token" : new_access_token})

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid or expired token')


@auth_router.get('/me', response_model=UserBookModel)
async def get_current_user(
        user = Depends(get_current_user),
        _:bool = Depends(role_checker)
):
    return user

@auth_router.get('/logout')
async def revoke_token(token_details: dict = Depends(AccessTokenBearer())):
    jti = token_details['jti']
    await add_jti_to_blocklist(jti)
    return JSONResponse(
        content={
            "message": "Logged out successfully"
        },
        status_code=status.HTTP_200_OK
    )

@auth_router.post('/password-reset-request')
async def password_request_rest(email_data: PasswordResetRequestModel):
    email = email_data.email

    token = create_url_safe_token({"email": email})

    link = f"http://{Config.DOMAIN}/api/v1/auth/password-reset-confirm/{token}"

    html_message = f""" 
            <h1>Reset your password</h1>
            <p>Please click this <a href="{link}">link</a> to reset your password</p>
            """

    message = create_message(
        recipients=[email], subject="Verify your email", body=html_message
    )
    await fm.send_message(message)

    return JSONResponse(
        content={
        "message": "Password reset link has been sent to your email. "
        },
        status_code=status.HTTP_200_OK
    )


@auth_router.post('/password-reset-confirm/{token}')
async def reset_account_password(
        token: str, passwords: PasswordResetConfirmModel ,
        session: AsyncSession = Depends(get_session)
):
    new_password = passwords.new_password
    confirm_password = passwords.confirm_new_password

    if new_password != confirm_password:
        raise HTTPException(detail="Passwords do not match", status_code=status.HTTP_400_BAD_REQUEST)

    token_data = decode_url_safe_token(token)
    user_email = token_data.get('email')

    if user_email:
        user = await user_service.get_user_by_email(user_email, session=session)

        if not user:
            raise UserNotFound()

        password_hash = generate_hash(new_password)
        await user_service.update_user(user, {"password_hash": password_hash}, session)

        return JSONResponse(
            content={
                "message": "Password updated successfully."
            },
            status_code=status.HTTP_200_OK
        )
    return JSONResponse(
        content={"message": "Error occurred during password reset"},
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
    )