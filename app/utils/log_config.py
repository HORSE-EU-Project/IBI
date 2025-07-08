import logging
from constants import Const

class CustomFormatter(logging.Formatter):
    """
    Logging colored formatter. 
    Adapted from https://stackoverflow.com/a/56944256/3638629
    """

    grey = '\x1b[38;21m'
    blue = '\x1b[38;5;39m'
    yellow = '\x1b[38;5;226m'
    red = '\x1b[38;5;196m'
    bold_red = '\x1b[31;1m'
    reset = '\x1b[0m'

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def setup_logging(current_file=None):
    if current_file is None:
        current_file = Const.APP_NAME
        
    logger = logging.getLogger(current_file)
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        # Define log format
        formatter = CustomFormatter(
            '%(name)s - %(levelname)s - %(asctime)s - %(message)s'
        )
        # Log to console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG) # Console output typically INFO or higher
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    return logger