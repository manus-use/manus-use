#!/bin/bash
# Setup script for ManusUse with AWS Bedrock

echo "Setting up ManusUse environment..."

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install Strands SDK dependencies first
echo "Installing Strands SDK..."
cd ../sdk-python
pip install -e .

# Return to ManusUse
cd ../ManusUse

# Install ManusUse dependencies
echo "Installing ManusUse dependencies..."
pip install -r requirements.txt

# Install additional dependencies for testing
echo "Installing test dependencies..."
pip install boto3 pytest pytest-asyncio

# Install development dependencies
pip install -e .

echo "Setup complete!"
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To test with AWS Bedrock, run:"
echo "  python test_minimal.py"