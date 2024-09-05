from fastapi_mail import FastMail, ConnectionConfig, MessageSchema, MessageType
from pathlib import Path
from src.config import Config

BASE_DIR = Path(__file__).resolve().parent

conf = ConnectionConfig(
   MAIL_USERNAME=Config.MAIL_USERNAME,
   MAIL_PASSWORD=Config.MAIL_PASSWORD,
   MAIL_PORT=Config.MAIL_PORT,
   MAIL_SERVER="smtp.gmail.com",
    MAIL_FROM = Config.MAIL_FROM,
    MAIL_FROM_NAME = Config.MAIL_FROM_NAME,
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True,

    # TEMPLATE_FOLDER=Path(BASE_DIR, "templates"),
)

fm = FastMail(conf)

def create_message(recipients: list[str], subject: str, body: str):

    message = MessageSchema(recipients=recipients, subject=subject, body=body, subtype=MessageType.html)

    return message
