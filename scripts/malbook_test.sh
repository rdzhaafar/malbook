#!/bin/sh
# Deploys a dev build of malbook

if [ -z $VIRTUAL_ENV ]; then
    echo "'$0' must be run from a virtual environment"
    exit 1
fi
if [ ! -d ".git" ]; then
    echo "'$0' must be run from the root repository dir"
    exit 1
fi

echo "Cleaning up..."
jupyter notebook stop -y
if [ -d malbook/test ]; then
    rm -rf malbook/test/.malbook
else
    mkdir malbook/test
fi
if [ -d malbook/dist ]; then
    rm -rf malbook/dist
fi

echo "Building malbook..."
cd malbook
python3 -m build
export MALBOOK_WHEEL_PATH="$(pwd)/$(ls dist/*.whl)"

echo "Installing malbook..."
python3 -m pip install --force-reinstall $MALBOOK_WHEEL_PATH

echo "Launching notebook..."
cd test
malbook new
malbook run