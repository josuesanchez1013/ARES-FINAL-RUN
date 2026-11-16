"""ASGI entry point: uvicorn ares_api.main:app"""

# Load .env the same way ui/streamlit_app.py does, so the token, agent IDs,
# MCP_SERVER_URL and ARES_* settings reach the service and the pipeline.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional (mock mode needs no .env)
    pass

from .app import create_app  # noqa: E402

app = create_app()
