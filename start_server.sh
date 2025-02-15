#!/bin/bash

echo "Starting server with Uvicorn..."
poetry run uvicorn app.main:app --reload "${@:2}"
