#!/bin/sh
# Builds and uploads the package to PyPi.

python3 -m build
python3 -m twine upload --skip-existing dist/*