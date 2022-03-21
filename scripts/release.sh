#!/bin/sh
# Releases a new version of malbook to PyPi

if [ -z $VIRTUAL_ENV ]; then
    echo "'$0' must be run from a virtual environment"
    exit 1
fi
if [ ! -d ".git" ]; then
    echo "'$0' must be run from the root repository dir"
    exit 1
fi
if [ ! -f ~/.pypirc ]; then
    echo "'.pypirc' is not configured"
    exit 1
fi

read -p "Are you absolutely sure? (Y/n) " -r
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd Malbook
    if [ -d dist ]; then
        rm -rf dist
    fi
    bumpversion patch
    git push origin main
    python3 -m build
    python3 -m twine upload dist/*
else
    exit 1
fi