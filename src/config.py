import logging

# Directory where generated reports will be stored (can be relative or absolute)
REPORT_OUTPUT_DIR = "tests/tp1/utils/output"
# Default output format: 'txt' or 'pdf'
REPORT_DEFAULT_FORMAT = "txt"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("app.log", mode="a"), logging.StreamHandler()],
)
