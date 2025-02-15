import logging

from fastapi import File, Form, UploadFile, HTTPException, APIRouter
from typing import Optional
from app.models.models import VulnerabilityModel, ApplicationModel, PackageModel
from app.models.serializers import ApplicationModelResponse
from app.services.scanner import scan_requirements_for_vulnerabilities
from app.core.database import applications_db

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1",
    responses={404: {"description": "Not found"}},
)


@router.post("/create-application/", tags=["Create an application"])
async def create_application(
    name: str = Form(...),
    description: Optional[str] = Form(None),
    requirements_file: UploadFile = File(...),
):
    """
    Endpoint to create a Python application by submitting a name, description, and requirements.txt file.
    """
    logger.info(f"Received request to create application: {name}")

    # Check if the application name already exists in the database
    if any(app.name == name for app in applications_db):
        logger.warning(f"Application with name '{name}' already exists.")
        raise HTTPException(
            status_code=400, detail=f"Application with name '{name}' already exists."
        )

    # Validate the file type
    if requirements_file.content_type != "text/plain":
        logger.error(
            f"Invalid file type for application {name}. Only text files are allowed."
        )
        raise HTTPException(
            status_code=400, detail="Invalid file type. Only text files are allowed."
        )

    # Read the contents of the requirements.txt file
    try:
        logger.info(f"Reading requirements file for application: {name}")
        requirements_content = await requirements_file.read()
        requirements_content = requirements_content.decode("utf-8")
        logger.info(f"Successfully read requirements file for application: {name}")
    except Exception as e:
        logger.error(f"Error reading the file for application {name}: {e}")
        raise HTTPException(status_code=500, detail="Error reading the file.")

    # Scan for vulnerabilities
    try:
        logger.info(f"Scanning dependencies for vulnerabilities in application: {name}")
        scanned_dependencies = await scan_requirements_for_vulnerabilities(
            requirements_content
        )
        logger.info(f"Successfully scanned dependencies for application: {name}")
    except Exception as e:
        logger.error(f"Error scanning dependencies for application {name}: {e}")
        raise HTTPException(status_code=500, detail="Error scanning dependencies.")

    # Build the list of packages with vulnerabilities
    try:
        logger.info(f"Building package list for application: {name}")
        packages = []
        for dependency in scanned_dependencies:
            vulnerabilities = [
                VulnerabilityModel(
                    id=vuln["id"], summary=vuln["summary"], details=vuln["details"]
                )
                for vuln in dependency.get("vulnerabilities", [])
            ]
            packages.append(
                PackageModel(
                    name=dependency["package"],
                    version=dependency["version"],
                    vulnerabilities=vulnerabilities,
                )
            )
        logger.info(f"Successfully built package list for application: {name}")
    except Exception as e:
        logger.error(f"Error building package list for application {name}: {e}")
        raise HTTPException(status_code=500, detail="Error processing package data.")

    # Create the application object
    try:
        logger.info(f"Creating application object for: {name}")
        application = ApplicationModel(
            name=name,
            description=description,
            packages=packages,
        )

        # Save the application to the temporary global object
        applications_db.append(application)
        logger.info(
            f"Application {name} created successfully and added to the database."
        )
    except Exception as e:
        logger.error(f"Error creating application object for {name}: {e}")
        raise HTTPException(status_code=500, detail="Error creating application.")

    # Return the response
    try:
        response = ApplicationModelResponse(
            message="Application created successfully.",
            name=application.name,
            description=application.description,
        )
        logger.info(f"Returning successful response for application: {name}")
        return response
    except Exception as e:
        logger.error(f"Error generating response for application {name}: {e}")
        raise HTTPException(status_code=500, detail="Error generating response.")


@router.get("/get-applications", tags=["Get all applications"])
async def get_applications():
    """
    Retrieve all applications and identify which ones are vulnerable.
    Each application will include an `is_vulnerable` field.
    """
    logger.info("Fetching all applications with vulnerability status.")

    try:
        # Check if there are any applications in the database
        if not applications_db:
            logger.warning("No applications found in the database.")
            raise HTTPException(status_code=404, detail="No applications found.")

        # List all applications and mark whether they are vulnerable
        applications_with_vulnerability_status = [
            {
                "name": application.name,
                "description": application.description,
                "is_vulnerable": any(
                    len(package.vulnerabilities) > 0 for package in application.packages
                ),
            }
            for application in applications_db
        ]

        logger.info(
            f"Successfully retrieved {len(applications_with_vulnerability_status)} applications."
        )
        return {
            "total_applications": len(applications_with_vulnerability_status),
            "applications": applications_with_vulnerability_status,
        }

    except HTTPException as http_exc:
        # Log the specific HTTP exception
        logger.error(f"HTTPException occurred: {http_exc.detail}")
        raise http_exc

    except Exception as e:
        # Log unexpected errors
        logger.error(f"An unexpected error occurred while fetching applications: {e}")
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while fetching applications.",
        )


@router.get(
    "/get-application-dependencies/{application_name}",
    tags=["Get an application dependencies"],
)
async def get_application_dependencies(application_name: str):
    """
    Retrieve the dependencies for a specified application and show only vulnerable packages.
    Each package will include an `is_vulnerable` field.
    """
    logger.info(f"Fetching dependencies for application: {application_name}")

    try:
        # Find the application by name
        application = next(
            (app for app in applications_db if app.name == application_name), None
        )

        if not application:
            logger.warning(f"Application '{application_name}' not found.")
            raise HTTPException(
                status_code=404, detail=f"Application '{application_name}' not found."
            )

        # Filter only vulnerable packages and add `is_vulnerable` field
        vulnerable_packages = [
            {
                "name": package.name,
                "version": package.version,
                "is_vulnerable": len(package.vulnerabilities) > 0,
            }
            for package in application.packages
        ]

        logger.info(
            f"Successfully retrieved dependencies for application: {application_name}"
        )
        return {
            "application_name": application.name,
            "description": application.description,
            "vulnerable_packages": vulnerable_packages,
        }

    except HTTPException as http_exc:
        # Log the specific HTTP exception
        logger.error(f"HTTPException occurred: {http_exc.detail}")
        raise http_exc

    except Exception as e:
        # Log unexpected errors
        logger.error(
            f"An unexpected error occurred while fetching dependencies for application '{application_name}': {e}"
        )
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while fetching application dependencies.",
        )
