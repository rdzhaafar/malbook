#!/bin/sh
# Sets up, builds and publishes a new version of the package

test -z $VIRTUAL_ENV && echo "'release.sh' must be run from a virtual environment" && exit 1

bumpversion patch
git push origin main
python3 -m build
python3 -m twine upload dist/*
