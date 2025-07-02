#!/bin/bash
# Script to start the backend FastAPI development server using uvicorn

uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
