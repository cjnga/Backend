import os
from dotenv import load_dotenv

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)

load_dotenv(os.path.join(CURRENT_DIR, ".env"))
load_dotenv(os.path.join(ROOT_DIR, ".env"), override=False)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
MONGODB_URI = os.getenv("MONGODB_URI", "")
PORT = int(os.getenv("PORT", "8000"))
