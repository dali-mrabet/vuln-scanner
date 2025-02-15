
**vuln-scanner** is a Python-based web application built with FastAPI that allows users to upload Python application dependencies (via `requirements.txt`) and scan them for known vulnerabilities. It also provides endpoints to manage and retrieve information about applications and their dependencies.

## Features

- Upload a `requirements.txt` file to create an application and scan its dependencies for vulnerabilities.
- Retrieve a list of all applications and their dependencies.
- Get detailed information about a specific dependency, including its vulnerabilities and usage across applications.
- Health check endpoint to verify the service is running.

## Endpoints

### 1. Create an Application
- **Endpoint**: `/create-application/`
- **Method**: `POST`
- **Description**: Upload a Python application's name, description, and `requirements.txt` file to scan for vulnerabilities and store the application in the database.

### 2. List All Applications
- **Endpoint**: `/applications/get-applications`
- **Method**: `GET`
- **Description**: Retrieve a list of all applications stored in the database.

### 3. Get Dependency Details
- **Endpoint**: `/get-dependency/`
- **Method**: `GET`
- **Description**: Retrieve detailed information about a specific dependency, including its vulnerabilities and usage across applications.

### 4. Health Check
- **Endpoint**: `/`
- **Method**: `GET`
- **Description**: Verify that the service is running.

## Requirements

- Python 3.9+
- Poetry (for dependency management)
- Other dependencies specified in `pyproject.toml`

## Installation

Clone the repository:

``1. git clone https://github.com/your-username/vuln-scanner.git``
   
``cd vuln-scanner``

``2. poetry install``

``3. poetry shell``

``4. chmod +x start_server.sh``

``5. ./start_server.sh``

- Access the application at http://127.0.0.1:8000.

## Create .env file

```
PROJECT_NAME=vuln-scanner
SCANNER_ENDPOINT=https://api.osv.dev/v1/query
```

## Project Structure
```
vuln-scanner/
│
├── app.py                # Main FastAPI application
├── db.py                 # In-memory database for applications and dependencies
├── dependencies.py       # Dependency injection for shared resources
├── models.py             # Pydantic models for applications, packages, and vulnerabilities
├── routers/
│   ├── applications.py   # Router for application-related endpoints
│   ├── dependencies.py   # Router for dependency-related endpoints
│
├── utils/
│   ├── scanner.py        # Utility functions for scanning vulnerabilities
│
├── start_server.sh       # Script to start the FastAPI server
├── pyproject.toml        # Poetry configuration file (includes Ruff settings)
├── poetry.lock           # Poetry lock file for dependencies
└── README.md             # Project documentation
```

## License

This project is licensed under the terms of the MIT license.
