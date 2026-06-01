import logging
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parents[2] / "app.log"

logger = logging.getLogger("apk_analyzer")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
	formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

	file_handler = logging.FileHandler(LOG_FILE)
	file_handler.setFormatter(formatter)

	logger.addHandler(file_handler)


def log_info(message):
	logger.info(message)


def log_error(message):
	logger.error(message)


def log_warning(message):
	logger.warning(message)
