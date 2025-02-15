import logging
from fastapi import HTTPException, APIRouter
from app.core.database import applications_db

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/v1",
    responses={404: {"description": "Not found"}},
)


@router.get("/get-dependencies/", tags=["Get all application dependencies"])
async def get_dependencies():
    """
    List all dependencies tracked across the user's applications and indicate whether they are vulnerable.

    Returns:
        Dict: A dictionary containing all dependencies, their vulnerabilities, and whether they are vulnerable.
    """
    logger.info("Fetching all dependencies across applications.")

    try:
        # Check if there are any applications in the database
        if not applications_db:
            logger.warning(
                "No applications found in the database. Cannot retrieve dependencies."
            )
            raise HTTPException(
                status_code=404,
                detail="No applications found. No dependencies to display.",
            )

        # Dictionary to track dependencies across all applications
        dependencies_map = {}

        # Iterate through all applications and their packages
        for application in applications_db:
            for package in application.packages:
                package_key = f"{package.name}=={package.version}"  # Unique key for each package-version pair

                # If the package is already in the map, extend its vulnerabilities
                if package_key in dependencies_map:
                    dependencies_map[package_key]["vulnerabilities"].extend(
                        package.vulnerabilities
                    )
                else:
                    # Add the package to the map with its vulnerabilities
                    dependencies_map[package_key] = {
                        "name": package.name,
                        "version": package.version,
                        "vulnerabilities": package.vulnerabilities,
                    }

        # Convert the map to a list of dependencies
        dependencies_list = [
            {
                "name": dep["name"],
                "version": dep["version"],
                "is_vulnerable": len(dep["vulnerabilities"])
                > 0,  # True if there are vulnerabilities
            }
            for dep in dependencies_map.values()
        ]

        # Check if there are no dependencies
        if not dependencies_list:
            logger.warning("No dependencies found across applications.")
            raise HTTPException(
                status_code=404, detail="No dependencies found across applications."
            )

        logger.info(f"Successfully retrieved {len(dependencies_list)} dependencies.")
        return {
            "total_dependencies": len(dependencies_list),
            "dependencies": dependencies_list,
        }

    except HTTPException as http_exc:
        # Log the specific HTTP exception
        logger.error(f"HTTPException occurred: {http_exc.detail}")
        raise http_exc

    except Exception as e:
        # Log unexpected errors
        logger.error(f"An unexpected error occurred while fetching dependencies: {e}")
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while fetching dependencies.",
        )


@router.get("/get-dependency/", tags=["Get dependency information"])
async def get_dependency(name: str, version: str):
    """
    Provide details about a specific dependency, including usage across applications and associated vulnerabilities.

    Args:
        name (str): The name of the dependency.
        version (str): The version of the dependency.

    Returns:
        Dict: A dictionary containing details about the dependency, its usage, and vulnerabilities.
    """
    logger.info(f"Fetching details for dependency: {name}=={version}")

    try:
        # Initialize usage and vulnerabilities
        usage = []
        vulnerabilities = []

        # Check where the dependency is used across applications
        for application in applications_db:
            for package in application.packages:
                if package.name == name and package.version == version:
                    # Add application usage details
                    usage.append(
                        {
                            "application_name": application.name,
                            "application_description": application.description,
                        }
                    )
                    # Collect vulnerabilities directly from the package
                    vulnerabilities.extend(package.vulnerabilities)

        # If the dependency is not found in any application
        if not usage:
            logger.warning(
                f"Dependency '{name}=={version}' not found in any application."
            )
            raise HTTPException(
                status_code=404,
                detail=f"Dependency '{name}=={version}' not found in any application.",
            )

        # Prepare the response
        logger.info(f"Successfully retrieved details for dependency: {name}=={version}")
        return {
            "dependency": {
                "name": name,
                "version": version,
                "is_vulnerable": len(vulnerabilities)
                > 0,  # True if there are any vulnerabilities
                "vulnerabilities": [
                    {
                        "id": vuln.id,
                        "summary": vuln.summary,
                        "details": vuln.details,
                    }
                    for vuln in vulnerabilities
                ],
            },
            "usage": usage,
        }

    except HTTPException as http_exc:
        # Log the specific HTTP exception
        logger.error(f"HTTPException occurred: {http_exc.detail}")
        raise http_exc

    except Exception as e:
        # Log unexpected errors
        logger.error(
            f"An unexpected error occurred while fetching dependency '{name}=={version}': {e}"
        )
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while fetching the dependency details.",
        )
