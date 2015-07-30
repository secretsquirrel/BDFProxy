#!/bin/bash
git submodule init
git submodule update
pip install libmagic
./update.sh
