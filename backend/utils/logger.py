import logging
import sys

LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
LOG_LEVEL = logging.INFO

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(LOG_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(LOG_LEVEL)
    return logger 