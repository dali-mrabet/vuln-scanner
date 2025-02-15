import logging
from fastapi import FastAPI

from app.core.config import settings

from app.routers.v1 import dependencies
from app.routers.v1 import applications

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


def get_application():
    _app = FastAPI(title=settings.PROJECT_NAME)

    return _app


app = get_application()

# Include the routers
app.include_router(applications.router)
app.include_router(dependencies.router)


@app.get("/", tags=["Health"])
async def readiness_check():
    return {"ready": "Vulnerability Scanner "}
