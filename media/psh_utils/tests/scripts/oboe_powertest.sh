#!/bin/bash

# Runs OboeTester with different buffer sizes.
# Uses cable_breaker to temporarily disconnect the device
# to allow suspend when display is off (while connected through
# usb to the host).
#
# Works on Pixel devices with eng/userdebug(root) builds
#
# Usage:
#   oboe_powertest_script [OPTIONS]
#
# Options:
#   -a            : Set airplane mode (disables WiFi and Bluetooth).
#   -c            : Use classic mode (disables MMAP).
#   -d [SECONDS]  : Duration of each test in seconds (default: 600).
#   -h, --help    : Display this help message.
#   -p            : Use perfetto for tracing.
#   -s [RATE]     : Sample rate in Hz (default: 48000).
#   -t [ARRAY]    : Comma-separated list of buffer sizes in milliseconds for testing.
#                   Negative values use deep buffer (e.g., '20000,1000,500,250,-500').
#                   Overrides the default time_array.
#

# Notes:
# 1) During the test, cable_breaker will disconnect the device from
#    USB to allow suspend during a particular time period.  cable_breaker is
#    only available for Pixel devices (eng/userdebug) at this time.
# 2) audioserver will be restarted periodically to ensure a clean test start.
# 3) We disable SELinux as a precaution as some branches may not allow
#    access the power and health HALs.
# 4) adb errors may be ignored.
#

##############
# Function to display help message
show_help() {
  grep "^# " "$0" | cut -c 3- | head -17
}

# Test Configuration

# Sample rate in Hz
# Override with -s [RATE]
sample_rate=48000

# Array of buffer size in milliseconds for testing
# negative values use deep buffer
#time_array=(20000 10000 5000 2000 -500 -1000)
time_array=(20000 5000 1000 500 250 -500)

# Set airplane mode
# Override with -a
airplane=""

# Duration of each test in seconds
# Override with -d [SECONDS]
duration=600

# Whether classic mode is used
# Override with -c
use_classic=""

# Whether perfetto is used
# Override with -p
use_perfetto=""

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
    -c)
      use_classic="true"
      # Consume the -c flag by shifting the arguments.
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    -p)
      use_perfetto="true"
      # Consume the -p flag by shifting the arguments.
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
if [ -n "$use_classic" ]; then
  echo "Use classic mode"
fi
if [ -n "$use_perfetto" ]; then
  echo "Tracing with perfetto"
fi

echo "Time array was set to: ${time_array[@]}"

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

# Enable AudioFlinger power stats
adb shell setenforce 0
adb shell setprop persist.audio.power_stats.enabled true

# Test loop:  iterate through each buffer size in time
for time in "${time_array[@]}"; do
  configuration="$base_configuration"

  # ensure oboetester foreground service set properly
  echo "restarting oboetester"
  adb shell pkill oboetester

  # ensure similar stats collection state
  echo "restarting audioserver and waiting 5 seconds"
  adb shell pkill audioserver
  sleep 5

  # echo "$OUT"
  echo "----------------------------------------------------------------"

  if [ -n "$use_perfetto" ]; then
    # We can't use the perfetto background option with suspend.
    # Instead, we must use detach to allow perfetto to run in the background
    # and attach to perfetto to stop it when we reconnect to the device.
    # adb shell perfetto audio sched freq hal --background --time "${duration}s" --out "/data/misc/perfetto-traces/trace_${time}.pf"
    adb shell "echo ' \
write_into_file: true \
file_write_period_ms: 1000000000 \
buffers { \
  size_kb: 32768 \
} \
buffers: { \
    size_kb: 2048 \
} \
buffers: { \
    size_kb: 1024 \
} \
data_sources { \
  config { \
    name: \"linux.ftrace\" \
    target_buffer: 0 \
    ftrace_config { \
      atrace_categories: \"audio\" \
      atrace_categories: \"sched\" \
      atrace_categories: \"freq\" \
      atrace_categories: \"hal\" \
      symbolize_ksyms: true \
    } \
  } \
} \
data_sources { \
  config { \
    name: \"linux.process_stats\" \
    target_buffer: 1 \
  } \
} \
data_sources { \
  config { \
    name: \"linux.system_info\" \
    target_buffer: 2 \
  } \
} \
data_sources: { \
    config { \
        name: \"android.packages_list\" \
        target_buffer: 2 \
    } \
} \
' | perfetto -c - --txt --detach=oboeperf1 -o \"/data/misc/perfetto-traces/trace_${time}.pf\""

  fi # use_perfetto

  if [[ $time -lt 0 ]]; then

    frames=$((time * -sample_rate / 1000))
    abstime=$((time * -1))
    configuration+=" --es out_perf powersave --ei buffer_capacity $frames"
    echo "(deep buffer): testing $duration seconds  buffer: $frames frames $abstime ms"

  else

    frames=$((time * sample_rate / 1000))

    configuration+=" --es out_perf powersave_offload --ei buffer_frames $frames"
    if [ -n "$use_classic" ]; then
        configuration+=" --ez out_use_mmap false"
        echo "(classic offload): testing $duration seconds  buffer: $frames frames $time ms"
    else
        configuration+=" --ez out_use_mmap true --es out_sharing exclusive"
        echo "(mmap offload): testing $duration seconds  buffer: $frames frames $time ms"
    fi
  fi

  echo "Configuration: $configuration"
  adb shell am start -n com.mobileer.oboetester/.MainActivity $configuration

  # adb shell input keyevent KEYCODE_SLEEP

  echo "suspending now by cable_breaker"
  adb shell cable_breaker -a break:$duration

  # add 5 seconds for the track to complete and shut down
  sleep 5
  sleep $duration

  # we should be reconnected now.

  if [ -n "$use_perfetto" ]; then
    adb shell perfetto --attach=oboeperf1 --stop
    adb pull "/data/misc/perfetto-traces/trace_${time}.pf"
  fi

  # stop oboetester
  adb shell am force-stop com.mobileer.oboetester

  # get stats from AudioFlinger
  sleep 3
  adb shell dumpsys media.audio_flinger | grep -A 28  "uid.*com.mobileer.oboetester"

done
