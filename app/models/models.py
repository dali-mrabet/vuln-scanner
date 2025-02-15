from pydantic import BaseModel
from typing import Optional, List


# Define the Vulnerability model
class VulnerabilityModel(BaseModel):
    id: str  # The ID of the vulnerability
    summary: Optional[str] = "N/A"  # Summary of the vulnerability
    details: Optional[str] = "N/A"  # Details of the vulnerability


# Define the Package model
class PackageModel(BaseModel):
    name: str  # The name of the package
    version: str  # The version of the package
    vulnerabilities: List[VulnerabilityModel]  # List of vulnerabilities for the package


# Define the Application model
class ApplicationModel(BaseModel):
    name: str  # The name of the application
    description: Optional[str] = None  # Optional description of the application
    packages: List[PackageModel]  # List of packages in the application


# Define the Response model for creating an application
class ApplicationModelResponse(BaseModel):
    message: str
    name: str
    description: Optional[str]


#    packages: List[PackageModel]
