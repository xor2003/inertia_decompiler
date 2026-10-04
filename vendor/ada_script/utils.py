import logging
import sys

# Global logger instance
logger = logging.getLogger(__name__)

def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('ada_pipeline.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    global logger
    logger = logging.getLogger(__name__)
    return logger

def handle_error(msg, exc=None, fatal=False):
    global logger
    if logger.level == 0:  # Not configured yet
        logging.basicConfig(level=logging.ERROR)
        logger = logging.getLogger(__name__)
    logger.error(msg, exc_info=exc)
    if fatal:
        sys.exit(1)
    return False