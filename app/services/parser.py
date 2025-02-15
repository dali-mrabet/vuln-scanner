from typing import List, Dict


async def parse_requirements(requirements_content: str) -> List[Dict[str, str]]:
    """
    Parse the requirements.txt content and extract package names and versions.

    Args:
        requirements_content (str): Content of the requirements.txt file.

    Returns:
        List[Dict[str, str]]: A list of dictionaries with 'name' and 'version' keys.
    """
    dependencies = []
    lines = requirements_content.splitlines()
    for line in lines:
        # Skip comments and empty lines
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Split package name and version (e.g., "package==1.0.0")
        if "==" in line:
            name, version = line.split("==")
            dependencies.append({"name": name.strip(), "version": version.strip()})
        else:
            # If no version is specified, assume latest version (optional handling)
            dependencies.append({"name": line.strip(), "version": None})
    return dependencies
