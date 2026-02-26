#!/bin/bash

# Repeatedly freezes and unfreezes the target process.
# The target process is determined by a process_pgrep_match
# pattern, so the pattern "oboe" will match
# "com.mobileer.oboetester"
#
# Usage:
#
# freeze.sh <process_pgrep_pattern> [count]
#
# Example:
#
# ./freeze.sh oboe
#

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <process_pgrep_pattern> [count]"
    exit 1
fi

# set internal variables
process_pgrep_pattern=$1
count=${2:-1000} # {argument:-default}

# validate
if ! [[ "$count" =~ ^[0-9]+$ ]]; then
    echo "Error: count $count must be a positive integer."
    exit 1
fi

matches="$(adb shell pgrep $process_pgrep_pattern | wc -l)"

if [ "$matches" -ne 1 ]; then
    echo "Error: name $name matches $matches processes, not unique"
    exit 1
fi

# We repeatedly call pgrep for the pid as the process may be killed (and restarted)
# due to binder blocking during the freeze.
# This shows up as a logcat line:
# "ActivityManager: Kill app due to repeated failure to freeze binder: <pid> <proc_name>"
#
# Turning the screen off during testing (i.e. audio playback) helps mitigates this,
# as freezing a top app with the screen on may occasionally lead to the app being
# restarted because of binder activity (shows as a different pid).

for ((i = 1; i <= count; i++)); do
  echo "$i of $count"
  adb shell "am freeze $(adb shell pgrep $process_pgrep_pattern) -- sticky"
  sleep 5
  adb shell "am unfreeze $(adb shell pgrep $process_pgrep_pattern) -- sticky"
  sleep 5
done
