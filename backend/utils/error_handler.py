from functools import wraps
from utils.logger import get_logger

logger = get_logger(__name__)

def error_handler(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e}", exc_info=True)
            # Here you can decide whether to re-raise or handle the exception
            raise
    return wrapper 