

from fastapi import APIRouter, Depends, status
from fastapi.exceptions import HTTPException
from src.db.models import User
from .schemas import ReviewCreateModel
from src.db.main import get_session
from sqlmodel.ext.asyncio.session import AsyncSession
from .service import ReviewService
from src.auth.dependencies import get_current_user

review_router = APIRouter()
review_service = ReviewService()

@review_router.post('/book/{book_uid}')
async def add_review_to_book(
        book_uid: str,
        review_data : ReviewCreateModel,
        current_user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_session)
):
    try:
        new_review = await review_service.add_review_to_book(
            user_email = current_user.email,
            review_data=review_data,
            book_uid=book_uid,
            session=session
        )
        return new_review
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Something went wrong.Failed to add review.'
        )



