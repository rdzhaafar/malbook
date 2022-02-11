#!/bin/sh
# Releases a new version of malbook into the wild

test -z $VIRTUAL_ENV && echo "'release.sh' must be run from a virtual environment" && exit 1

echo "WARNING: This script will release the repository to PyPi as-is, meaning"
echo "that any bugs or unwanted details will end up in public."
read -p "Are you sure you want to proceed? (Y/n) " -r
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Bumping the version number"
    bumpversion patch
    echo "Pushing changes to GitHub..."
    git push origin main

    echo "Building..."
    python3 -m build

    echo "Uploading to PyPi..."
    python3 -m twine upload dist/*
fi
