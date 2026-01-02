#!/bin/bash

# Runs OboeTester and computes the cycle time
#
# Usage:
#   oboe_cycletest.sh [OPTIONS]
#
# Options:
#   -a               : Set airplane mode (disables WiFi and Bluetooth).
#   [--deep|--fast|--mmap|--mmap_offload|--normal|--offload]
#   [--proc|--stat]  : choice of simpleperf data collection
#   -d [SECONDS]     : Duration of each test in seconds (default: 60).
#   -e [METRICS]     : Comma-separated list of simpleperf metrics
#                      (default: cpu-cycles,instructions,cache-misses).
#   -h, --help       : Display this help message,
#   -p               : Use perfetto for tracing.
#   -s [RATE]        : Sample rate in Hz (default: 48000).
#   -t [BUFFER_SIZE] : buffer size in ms.  Not supported for --offload.
#
# Notes:
#     --proc mode dumps the top 20 processes during the run. (not common)
#     --stat mode dumps cycle and instruction statistics.
#
#   To dump the available simpleperf event metrics on the device
#   use $ adb shell simpleperf list
#
# Examples:
#
# $ ./oboe_cycletest.sh --deep -d 10 -e context-switches,cpu-migrations
#    Run the test on deep buffer, duration 10 seconds,
#    measuring context-switches and cpu-migrations.
#
# $ ./oboe_cycletest.sh
#    Run the test on fast path (default), duration 60 seconds (default),
#    measuring cpu-cycles,instructions,cache-misses (default).

##############
# Function to display help message
show_help() {
  grep "^# " "$0" | cut -c 3- | head -26
}

# Test Configuration

# Sample rate in Hz
# Override with -s [RATE]
sample_rate=48000

# Array of buffer size in milliseconds for testing
# negative values use deep buffer
#time_array=(20000 10000 5000 2000 -500 -1000)
time_array=(0)

# Set airplane mode
# Override with -a
airplane=""

# Duration of each test in seconds
# Override with -d [SECONDS]
duration=60

# what audio mode is used (deep, fast, mmap, mmap_offload, normal, offload)
mode="fast"

# what perf recording to do (proc, stat)
operation="stat"

# Default metric array for stat operation
metric_array=("cpu-cycles" "instructions" "cache-misses")

# Configuration to use for oboetester.
# (note that a duration of 1000000 is for practical purposes infinite.)
base_configuration="--es test output --ei duration 1000000"
base_configuration+=" --es out_channel_mask stereo --es out_format pcm_16_bit"
base_configuration+=" --ez background true --ez foreground_service 1"

##############
# Loop through all the command-line arguments until none are left.
while (( "$#" )); do
  case "$1" in
    -a)
      airplane="true"
      # Consume the -a flag by shifting the arguments.
      shift
      ;;
    --deep)
      mode="deep"
      shift
      ;;
    -e)
      # Check if there is a next argument and it's not another flag.
      if [ -n "$2" ] && ! [[ "$2" =~ ^- ]]; then
        # Use comma as a delimiter to read the array elements.
        IFS=',' read -r -a metric_array <<< "$2"
        # Consume both the -e flag and its value by shifting twice.
        shift 2
      else
        # If no value is provided for -e, print an error to standard error and exit.
        echo "Error: -e option requires a value (e.g., 'cpu-cycles,instructions')." >&2
        exit 1
      fi
      ;;
    --fast)
      mode="fast"
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    --legacy)
       mode="legacy"
       shift
       ;;
    --mmap)
      mode="mmap"
      shift
      ;;
    --mmap_offload)
      mode="mmap_offload"
      shift
      ;;
    # If the argument is -d, handle setting the duration.
    -d)
      # Check if there is a next argument and it's not another flag.
      if [ -n "$2" ] && ! [[ "$2" =~ ^- ]]; then
        # Check if the provided value is an integer.
        if [[ "$2" =~ ^[0-9]+$ ]]; then
          # Assign the next argument to the duration variable.
          duration="$2"
          # Consume both the -d flag and its value by shifting twice.
          shift 2
        else
          # If the value is not an integer, print an error and exit.
          echo "Error: -d option requires an integer value." >&2
          exit 1
        fi
      else
        # If no value is provided for -d, print an error to standard error and exit.
        echo "Error: -d option requires a value." >&2
        exit 1
      fi
      ;;
    --normal)
      mode="normal"
      shift
      ;;
    --offload)
      mode="offload"
      shift
      ;;
    --proc)
      operation="proc"
      shift
      ;;
    # If the argument is -s, handle setting the sample rate.
    -s)
      # Check if there is a next argument and it's not another flag.
      if [ -n "$2" ] && ! [[ "$2" =~ ^- ]]; then
        # Check if the provided value is an integer.
        if [[ "$2" =~ ^[0-9]+$ ]]; then
          # Assign the next argument to the sample_rate variable.
          sample_rate="$2"
          # Consume both the -s flag and its value by shifting twice.
          shift 2
        else
          # If the value is not an integer, print an error and exit.
          echo "Error: -s option requires an integer value." >&2
          exit 1
        fi
      else
        # If no value is provided for -s, print an error to standard error and exit.
        echo "Error: -s option requires a value." >&2
        exit 1
      fi
      ;;
    # If the argument is -t, handle setting the time array.
    -t)
      # Check if there is a next argument and it's not another flag.
      if [ -n "$2" ] && ! [[ "$2" =~ ^- ]]; then
        # Use comma as a delimiter to read the array elements.
        IFS=',' read -r -a new_time_array <<< "$2"
        # Validate each element in the new_time_array to ensure they are integers.
        for item in "${new_time_array[@]}"; do
          if ! [[ "$item" =~ ^-?[0-9]+$ ]]; then
            echo "Error: -t option requires a comma-separated list of integers. $item" >&2
            exit 1
          fi
        done
        # Assign the new array to time_array, overriding the default.
        time_array=("${new_time_array[@]}")
        # Consume both the -t flag and its value by shifting twice.
        shift 2
      else
        # If no value is provided for -t, print an error to standard error and exit.
        echo "Error: -t option requires a value (e.g., '1000,500,-250')." >&2
        exit 1
      fi
      ;;
    --stat)
      operation="stat"
      shift
      ;;
    # Handle any other unsupported arguments.
    *)
      echo "Error: Unsupported argument $1" >&2
      exit 1
      ;;
  esac
done

# After parsing all arguments, print for verification
if [ -n "$airplane" ]; then
  echo "Enter airplane mode"
fi
if [ -n "$duration" ]; then
  echo "Duration was set to: $duration"
fi
if [ -n "$sample_rate" ]; then
  echo "Sample rate was set to: $sample_rate"
fi
if [ -n "$mode" ]; then
  echo "Use mode $mode"
fi

echo "Time array was set to: ${time_array[@]}"
echo "Metric array was set to: ${metric_array[@]}"

base_configuration+=" --ei sample_rate $sample_rate"

##############
# System Configuration
# Configure 5 second screen timeout
adb shell settings put system doff_screen_timeout_ms 5000
adb shell settings put system screen_off_timeout 5000

# Set media volume to 1
adb shell cmd media_session volume --set 1

if [ -n "$airplane" ]; then
  # Enable Airplane mode, disable WiFi and Bluetooth
  adb shell settings put global airplane_mode_on 1
  adb shell am broadcast -a android.intent.action.AIRPLANE_MODE --ez "state" true
  adb shell svc wifi disable
  adb shell cmd bluetooth_manager disable
fi

# Test loop:  iterate through each buffer size in time
for time in "${time_array[@]}"; do
  configuration="$base_configuration"

  # ensure oboetester foreground service set properly
 # echo "restarting oboetester"
 # adb shell pkill oboetester

  # ensure similar stats collection state
 # echo "restarting audioserver and waiting 5 seconds"
 # adb shell pkill audioserver
 # sleep 5

  # echo "$OUT"
  echo "----------------------------------------------------------------"


  if [[ "$mode" == "deep" ]]; then

    if [[ "$time" -eq "0" ]]; then
      time=500
    fi
    frames=$((time * sample_rate / 1000))

    configuration+=" --es out_perf powersave --ei buffer_capacity $frames"
    configuration+=" --ez out_use_mmap false"

    echo "(deep buffer): testing $duration seconds  buffer: $frames frames $time ms"

  elif [[ "$mode" == "fast" ]]; then

    configuration+=" --es out_perf lowlat"
    configuration+=" --ez out_use_mmap false"

    echo "(fast): testing $duration seconds"

  elif [[ "$mode" == "mmap" ]]; then

    configuration+=" --es out_perf lowlat"
    configuration+=" --ez out_use_mmap true"

    echo "(mmap): testing $duration seconds"

  elif [[ "$mode" == "mmap_offload" ]]; then
    if [[ "$time" -eq "0" ]]; then
      time=500
    fi
    frames=$((time * sample_rate / 1000))

    configuration+=" --es out_perf powersave_offload --ei buffer_frames $frames"
    configuration+=" --ez out_use_mmap true --es out_sharing exclusive"
    echo "(mmap offload): testing $duration seconds  buffer: $frames frames $time ms"

  elif [[ "$mode" == "normal" ]]; then

    if [[ "$time" -eq "0" ]]; then
      time=500
    fi
    frames=$((time * sample_rate / 1000))

    configuration+=" --es out_perf none --ei buffer_capacity $frames"
    configuration+=" --ez out_use_mmap false"

    echo "(normal): testing $duration seconds  buffer: $frames frames $time ms"

  elif [[ "$mode" == "offload" ]]; then
    configuration+=" --es out_perf powersave_offload"
    configuration+=" --ez out_use_mmap false"
    echo "(classic offload): testing $duration seconds"
  else
    echo "unknown mode $mode"
    exit -1
  fi

  echo "Configuration: $configuration"
  adb shell am start -n com.mobileer.oboetester/.MainActivity $configuration

  # 5s is too short, 15s still has issues, so we do 30s.
  echo "Sleeping 30 seconds for oboetester stability"
  sleep 30
  echo "Sleep done"

  if [[ "$operation" == "stat" ]]; then

    #configure perf
    perf_metrics=""
    for metric in "${metric_array[@]}"; do
      perf_metrics+=" -e $metric"
    done
    perfconfig=" stat $perf_metrics --duration $duration"
    savelocation="/data/local/tmp/perf.txt"
    echo "SimplePerf Configuration: $perfconfig"

    echo -e "\n[oboetester]"

    adb shell "simpleperf $perfconfig --app com.mobileer.oboetester  | tee $savelocation"

    echo -e "\n[audioserver]"

    adb shell "simpleperf $perfconfig -p audioserver  | tee -a $savelocation"

    echo -e "\n[audio hal]"

    adb shell "simpleperf $perfconfig -p android.hardware.audio.service-aidl  | tee -a $savelocation"

    echo -e "\n[all]"

# --exclude-perf not allowed.
    adb shell "simpleperf $perfconfig -a  | tee -a $savelocation"

    echo -e "\nCumulative table"

    for metric in "${metric_array[@]}"; do
         echo -e -n "${metric},"
         adb shell cat $savelocation | grep " ${metric}   " | awk '{print $1}' | \
                 sed 's/,//g' | awk '{printf "%s%s", $0, (NR%4 ? "," : ORS)}'
    done

  elif [[ "$operation" == "proc" ]]; then
    perfconfig=" record -a --exclude-perf -o "/data/local/tmp/perf.data" --duration $duration"
    echo "SimplePerf Configuration: $perfconfig"
    adb shell simpleperf $perfconfig
    adb shell simpleperf report -i "/data/local/tmp/perf.data" --sort pid -n | head -20

  else
    echo "unknown operation $operation"
    exit -1
  fi

  # stop oboetester
  adb shell am force-stop com.mobileer.oboetester

done
