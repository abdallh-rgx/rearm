#!/bin/bash
# Keep-alive version: relies on agent-browser internal timeouts only.
LOG=/home/z/rearm/test-data/turnstile-loop.log
URLFILE=/home/z/rearm/test-data/download-url.txt
echo "loop v3 start $(date)" >> $LOG
while true; do
  echo "=== attempt $(date)" >> $LOG
  agent-browser reload >> $LOG 2>&1
  sleep 6
  agent-browser find role button click --name "Download" >> $LOG 2>&1
  for w in 1 2 3 4 5 6 7 8 9 10; do
    sleep 5
    REQ=$(agent-browser network requests --filter "dw.uptodown" 2>/dev/null | grep -oE 'https://dw\.uptodown[^ ]*' | head -1)
    if [ -n "$REQ" ]; then
      echo "$REQ" > $URLFILE
      echo "CAPTURED: $REQ" >> $LOG
      exit 0
    fi
  done
  echo "  attempt done, retrying" >> $LOG
done
