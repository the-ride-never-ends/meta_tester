import logging
from pathlib import Path

_THIS_DIR = Path(__file__).parent.resolve()

def _make_logger():

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    log_folder = _THIS_DIR / "logs"
    if not log_folder.exists():
        log_folder.mkdir(parents=True, exist_ok=True)

    log_file_path = log_folder / "meta_tester.log"
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger

logger = _make_logger()
