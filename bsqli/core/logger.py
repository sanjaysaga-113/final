import logging
import sys
from colorama import Fore, Back, Style, init

# Initialize colorama for Windows compatibility
init(autoreset=True)

# Color mapping for log levels
LEVEL_COLORS = {
    logging.DEBUG: Fore.CYAN,
    logging.INFO: Fore.GREEN,
    logging.WARNING: Fore.YELLOW,
    logging.ERROR: Fore.RED,
    logging.CRITICAL: Fore.RED + Back.WHITE,
}

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output."""
    
    def format(self, record):
        # Get color for this level
        color = LEVEL_COLORS.get(record.levelno, Fore.WHITE)
        
        # Format: [LEVEL] message
        # Color the [LEVEL] part
        levelname = record.levelname
        colored_level = f"{color}[{levelname}]{Style.RESET_ALL}"
        
        # Build the message
        message = f"{colored_level} {record.getMessage()}"
        
        return message

def get_logger(name="bsqli"):
    """Get a logger with colored output support."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = ColoredFormatter()
        handler.setFormatter(fmt)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    return logger

