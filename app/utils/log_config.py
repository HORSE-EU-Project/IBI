import logging
from constants import Const

def setup_logging(current_file=None):
    if current_file is None:
        current_file = Const.APP_NAME
        
    logger = logging.getLogger(current_file)
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        # Define log format
        formatter = logging.Formatter(
            '%(name)s - %(levelname)s - %(asctime)s - %(message)s'
        )
        # Log to console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG) # Console output typically INFO or higher
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger