import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_THIS_DIR = Path(__file__).parent.resolve()

def make_logger(name: str = __name__) -> logging.Logger:

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    log_folder = _THIS_DIR / "logs"
    if not log_folder.exists():
        log_folder.mkdir(parents=True, exist_ok=True)

    log_file_path = log_folder / "meta_tester.log"
    # Rotate log after 1MB, keep 1 backup
    file_handler = RotatingFileHandler(log_file_path, maxBytes=1048576, backupCount=1)
    file_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger

logger = make_logger()

