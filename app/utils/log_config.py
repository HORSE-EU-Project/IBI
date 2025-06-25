import logging
from constants import Const

def setup_logging():
    logger = logging.getLogger(Const.APP_NAME)
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        # Define log format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        # Log to console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO) # Console output typically INFO or higher
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger