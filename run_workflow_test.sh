#!/bin/bash
# Script to run workflow tests in the virtual environment

# Change to the manus-use directory
cd "$(dirname "$0")"

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Creating one..."
    python3 -m venv venv
fi

# Activate the virtual environment
source venv/bin/activate

# Install dependencies if needed
echo "Installing dependencies..."
pip install -q strands-sdk

# Run the workflow test
echo "Running workflow tests..."
python test_manus_workflow.py

# Deactivate the virtual environment
deactivate