#!/bin/bash
git submodule init
git submodule update

pip install --upgrade magic
pip install python-magic
pip install configobj
./update.sh
