#!/bin/bash

# Validate one (and only one) positional argument is supplied
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 {setup|package}"
    exit 1
fi

# exit immediately if a command exits with a non-zero status
set -e

case "$1" in
    setup)
        echo "> Setting up a local environment"
        
        # check if venv exits; if not, install it
        if ! python3 -m venv --help &> /dev/null; then
            echo "> The venv module, which is required, is not installed"
            sudo apt update
            sudo apt install -y python3-venv
        fi

        # create and activate a virtual environment
        python3 -m venv .venv
        source .venv/bin/activate
        
        # update pip and install python dependencies
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        ;;
    package)
        echo "> Packaging project for AWS Lambda"

        # pre-execution cleanup
        ZIP_FILE="lambda_function.zip"
        if [ -f "$ZIP_FILE" ]; then
            echo "> Removing existing $ZIP_FILE"
            rm "$ZIP_FILE"
        fi

        # Check if zip exists; if not, install it
        if ! command -v zip &> /dev/null; then
            echo "> The zip program, which is required, is not installed"
            sudo apt update
            sudo apt install -y zip
        fi

        # Create a temporary directory for the Lambda package
        TEMP_DIR=$(mktemp -d)
        echo "> Created temporary directory $TEMP_DIR"

        # Copy the Python project files to the temporary directory
        echo "> Copying project files"
        cp ./*.py "$TEMP_DIR"

        # Copy the dependencies from the .venv directory
        echo "> Copying dependencies from .venv directory"
        cp -r ./.venv/lib/python3.*/site-packages/* "$TEMP_DIR"

        # TODO: Remove __pycache__ directories
        echo "> Cleaning up extraneous items"
        find "$TEMP_DIR" -type d -name "__pycache__" -exec rm -r {} +

        # Create the zip file
        echo "> Creating zip file $ZIP_FILE"
        zip -q -r "$ZIP_FILE" -j "$TEMP_DIR"/*

        # post-execution cleanup
        echo "> Removing temporary directory $TEMP_DIR"
        rm -r -f "$TEMP_DIR"
        ;;
    *)
        echo "Invalid argument. Use either 'setup' or 'package'"
        exit 1
        ;;
esac