#!/bin/bash

# Pre-deployment check script for PR-Agent
# This script verifies that all required dependencies are available

echo "🔍 Checking PR-Agent dependencies..."

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Error: pyproject.toml not found. Run this script from the project root."
    exit 1
fi

# Check Python version
python_version=$(python3 --version 2>&1)
echo "📍 Python version: $python_version"

# Check if required packages are installed
echo "📦 Checking required packages..."

check_package() {
    package_name=$1
    if python3 -c "import $package_name" 2>/dev/null; then
        echo "✅ $package_name - OK"
        return 0
    else
        echo "❌ $package_name - MISSING"
        return 1
    fi
}

# Check core dependencies
missing_count=0

if ! check_package "crewai"; then
    ((missing_count++))
fi

if ! check_package "github"; then
    ((missing_count++))
fi

if ! check_package "fastapi"; then
    ((missing_count++))
fi

if ! check_package "uvicorn"; then
    ((missing_count++))
fi

if ! check_package "google.generativeai"; then
    ((missing_count++))
fi

echo ""
if [ $missing_count -eq 0 ]; then
    echo "🎉 All dependencies are available! PR-Agent should run in production mode."
    echo "🚀 You can deploy this version."
    exit 0
else
    echo "⚠️  $missing_count dependencies are missing. PR-Agent will run in simulation mode."
    echo ""
    echo "To install missing dependencies, run:"
    echo "pip install -r requirements.txt"
    echo ""
    echo "Or if using the project setup:"
    echo "pip install -e ."
    exit 1
fi