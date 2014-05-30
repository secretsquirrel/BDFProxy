#!/bin/bash
git submodule init
git submodule update
echo 'Updating BDFProxy'
git pull
echo 'Updating BDF'
cd bdf/
git pull
