#!/bin/bash

# Runs oboe_cycletest for common testing options
# passing through arguments.  The output is a CSV
# table for insertion into a spreadsheet (e.g. Google
# Sheets).
#
# Usage:
#   oboe_cycleall.sh [OPTIONS] [pass-thru arguments for oboe_cycletest.sh]
#
# Options:
#   -h, --help       : Display this help message.
#   -e [METRICS]     : Comma-separated list of metrics from simpleperf
#                      (default: cpu-cycles,instructions,cache-misses).
#
# Examples:
#   $ ./oboe_cycleall.sh -d 10 -e context-switches,cpu-migrations
#     10 second trial, check context-switches and cpu-migrations
#
#   $ ./oboe_cycleall.sh
#     run the default test suite (60 seconds per test)
#
# To dump the available simpleperf event metrics on the device
# use $ adb shell simpleperf list

##############
# Function to display help message
show_help() {
  grep "^# " "$0" | cut -c 3- | head -17
}

##############
# Parse arguments

# default metric_array if -e doesn't exist
# this matches with oboe_cycletest.sh
metric_array=("cpu-cycles" "instructions" "cache-misses")

# create a temporary copy of the args.
args=("$@")
for (( i=0; i<${#args[@]}; i++ )); do
  case "${args[$i]}" in
    -h|--help)
      show_help
      exit 0
      ;;
    -e)
      val="${args[$((i+1))]}"
      if [ -n "$val" ] && ! [[ "$val" =~ ^- ]]; then
        IFS=',' read -r -a metric_array <<< "$val"
        ((i++))
      else
        echo "Error: -e option requires a value." >&2
        exit 1
      fi
      ;;
  esac
done

# Temporary file for saving.
savelocation=$(mktemp)

# Function to clean up on exit
cleanup() {
  echo "Waking up display"
  adb shell input keyevent KEYCODE_WAKEUP
  if [ -f "$savelocation" ]; then
    rm -f "$savelocation"
  fi
}

# Trap signals for cleanup
trap cleanup EXIT

echo "Turning off display to reduce oboetester cycles"
adb shell input keyevent KEYCODE_SLEEP

./oboe_cycletest.sh "$@" --deep | tee $savelocation

echo "Normal at 10ms Buffer"
adb shell setprop persist.audio.normal_playback_period_ms 10
# kill audioserver so property takes effect
adb shell pkill audioserver
./oboe_cycletest.sh "$@" --normal | tee -a $savelocation

echo "Normal at 20ms Buffer"
adb shell setprop persist.audio.normal_playback_period_ms 20
# kill audioserver so property takes effect
adb shell pkill audioserver
./oboe_cycletest.sh "$@" --normal | tee -a $savelocation

./oboe_cycletest.sh "$@" --fast | tee -a $savelocation
./oboe_cycletest.sh "$@" --mmap | tee -a $savelocation
./oboe_cycletest.sh "$@" --mmap_offload -t 500 | tee -a $savelocation
./oboe_cycletest.sh "$@" --mmap_offload -t 20000 | tee -a $savelocation
./oboe_cycletest.sh "$@" --offload | tee -a $savelocation

echo ""

# create CSV tables for insertion into Sheets

for metric in "${metric_array[@]}"; do
    echo "$metric"
    grep "${metric}," $savelocation | cut -d',' -f 1 --complement
done
