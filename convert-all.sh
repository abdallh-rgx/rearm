#!/bin/bash
# Convert all PUBG 0.12.0 armeabi-v7a libs to arm64-v8a via rearm so64.
set -u
cd /home/z/rearm
mkdir -p out/arm64-v8a pubg-apk/convert-logs
FAIL=0
for so in pubg-apk/lib/armeabi-v7a/*.so; do
  name=$(basename "$so")
  log="pubg-apk/convert-logs/$name.log"
  if ./target/release/rearm so64 "$so" "out/arm64-v8a/$name" > "$log" 2>&1; then
    words=$(rg -o "a64_words: ([0-9]+)" -r '$1' "$log" | head -1)
    unsup=$(rg -o "unsupported: ([0-9]+)" -r '$1' "$log" | head -1)
    echo "OK   $name  (a64_words=$words unsupported=$unsup)"
  else
    echo "FAIL $name  -> see $log"
    tail -3 "$log" | sed 's/^/       /'
    FAIL=1
  fi
done
exit $FAIL
