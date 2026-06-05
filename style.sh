#!/bin/sh

echo Formatting with ruff
export LD_LIBRARY_PATH=/run/current-system/profile/lib:/home/laura/.guix-home/profile/lib
~/ruff/target/release/ruff format --preview

echo Checking with flake8
python3 -m flake8 .

echo Checking with mypy
python3 -m mypy -p ruminant
