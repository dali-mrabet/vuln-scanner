from pydantic import BaseModel
from typing import Optional


# Define the Response model for creating an application
class ApplicationModelResponse(BaseModel):
    message: str
    name: str
    description: Optional[str]
