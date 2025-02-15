import httpx
from typing import List, Dict
from app.services.parser import parse_requirements
from app.core.config import settings


async def fetch_vulnerabilities_from_osv(package_name: str, version: str) -> Dict:
    """
    Check vulnerabilities for a given package using the OSV.dev API.

    Args:
        package_name (str): Name of the package.
        version (str): Version of the package.

    Returns:
        Dict: Response from the OSV.dev API.
    """
    url = settings.SCANNER_ENDPOINT
    payload = {
        "package": {"name": package_name, "ecosystem": "PyPI"},
        "version": version,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=payload)

    if response.status_code == 200:
        return response.json().get("vulns", [])
    else:
        return {"error": f"Failed to query OSV API for {package_name}=={version}"}


async def scan_requirements_for_vulnerabilities(
    requirements_content: str,
) -> List[Dict]:
    """
    Scan all dependencies in a requirements.txt file for vulnerabilities.

    Args:
        requirements_content (str): Content of the requirements.txt file.

    Returns:
        List[Dict]: A list of results for each dependency, including vulnerabilities.
    """
    dependencies = await parse_requirements(requirements_content)
    results = []

    for dependency in dependencies:
        name = dependency["name"]
        version = dependency["version"]

        # Skip packages without a version
        if not version:
            results.append(
                {
                    "package": name,
                    "version": "unknown",
                    "vulnerabilities": [],
                    "error": "Version not specified in requirements.txt",
                }
            )
            continue

        # Check vulnerabilities using OSV.dev API
        vulnerability_info = await fetch_vulnerabilities_from_osv(name, version)

        # Extract vulnerabilities
        vulns = vulnerability_info
        vuln_data = []
        for vuln in vulns:
            vuln_data.append(
                {
                    "id": vuln.get("id", "N/A"),
                    "summary": vuln.get("summary", "N/A"),
                    "details": vuln.get("details", "N/A"),
                }
            )

        results.append(
            {
                "package": name,
                "version": version,
                "vulnerabilities": vuln_data,
            }
        )

    return results
