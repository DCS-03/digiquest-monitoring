import logging
from app.core.config import get_settings

log = logging.getLogger("digiquest.mailer")


def send_password_reset(email: str, token: str) -> None:
    """Delivery hook. SMTP is not wired up yet: in production this only warns,
    so tokens are never written to logs. In development the token is logged for testing."""
    if get_settings().APP_ENV == "development":
        log.warning("DEV ONLY password reset token for %s: %s", email, token)
    else:
        log.warning("Password reset requested but no mail transport is configured.")
