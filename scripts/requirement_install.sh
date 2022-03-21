#!/bin/sh
# Installs a pip package and updates requirements.txt

PACKAGE="$1"

if [ -z $VIRTUAL_ENV ]; then
    echo "'$0' must be run from a virtual environment"
    exit 1
fi
if [ ! -d ".git" ]; then
    echo "'$0' must be run from the root repository dir"
    exit 1
fi
if [ -z $PACKAGE ]; then
    echo "Specify a pip package to install"
    exit 1
fi

echo "Installing $PACKAGE..."
pip install --force-reinstall $PACKAGE
pip freeze > requirements.txt