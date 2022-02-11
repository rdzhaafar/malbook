#!/bin/sh
# This scripts deploys a development build of malbook to `test` directory
# and runs it.

test -z $VIRTUAL_ENV && echo "'test.sh' must be run from a virtual environment" && exit 1

echo "Cleaning up running instances of malbook (if any)..."

jupyter notebook stop -y

if test -d test; then
    rm -rf test
fi

if test -d dist; then
    rm -rf dist
fi

echo "Running build..."

python3 -m build

export MALBOOK_WHEEL_PATH="$(pwd)/$(ls dist/*.whl)"

echo "Creating test directory..."
mkdir test
cd test

echo "Installing the build wheel..."
python3 -m pip uninstall malbook -y
python3 -m pip install $MALBOOK_WHEEL_PATH

echo "Creating a new malbook notebook..."
malbook new
malbook run