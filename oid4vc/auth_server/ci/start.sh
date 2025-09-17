#!/bin/bash

# Check if RUN_MODE is provided
if [ -z "$RUN_MODE" ]; then
  echo "Error: RUN_MODE is not set. Please set it to 'admin' or 'tenant'."
  exit 1
fi

# Start the appropriate server based on RUN_MODE
if [ "$RUN_MODE" == "admin" ]; then
  echo "Creating database tables..."
  python /app/alembic/admin/migrate.py
  echo "Starting admin server..."
  uvicorn admin.main:app --host 0.0.0.0 --port 8000
elif [ "$RUN_MODE" == "tenant" ]; then
  echo "Starting tenant server..."
  uvicorn tenant.main:app --host 0.0.0.0 --port 8001
else
  echo "Error: Invalid RUN_MODE. Please set it to 'admin' or 'tenant'."
  exit 1
fi