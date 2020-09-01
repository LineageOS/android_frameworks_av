#!/bin/bash
LOCAL_DIR="$( dirname "${BASH_SOURCE}" )"

MAINLINE_FRAMEWORKS_AV_PATHS=(
    media/extractors/
    media/codec2/components/
    media/libstagefright/codecs/amrnb
    media/libstagefright/codecs/amrwb
    media/libstagefright/codecs/amrwbenc
    media/libstagefright/codecs/common
    media/libstagefright/codecs/mp3dec
    media/libstagefright/codecs/m4v_h263
    media/libstagefright/flac/dec
    media/libstagefright/mpeg2ts
)

MAINLINE_EXTERNAL_PROJECTS=(
    external/aac
    external/flac
    external/libaac
    external/libaom
    external/libavc
    external/libgav1
    external/libgsm
    external/libhevc
    external/libmpeg2
    external/libopus
    external/libvpx
    external/libxaac
    external/sonivox
    external/tremolo
)

DEV_BRANCH=qt-aml-media-dev
RED=$(tput setaf 1)
NORMAL=$(tput sgr0)
WARNING_FULL="${RED}Please upload this change in ${DEV_BRANCH} unless it is restricted
from mainline release until next dessert release. Low/moderate security bugs
are restricted this way.${NORMAL}"
WARNING_PARTIAL="${RED}It looks like your change has mainline and non-mainline changes;
Consider separating them into two separate CLs -- one for mainline files,
one for non-mainline files.${NORMAL}"
PWD=`pwd`

if git branch -vv | grep -q -P "^\*[^\[]+\[goog/qt-aml-media-dev"; then
    # Change appears to be in mainline dev branch
    exit 0
fi

for path in "${MAINLINE_EXTERNAL_PROJECTS[@]}"; do
    if [[ $PWD =~ $path ]]; then
        echo -e "${RED}The source of truth for '$path' is in ${DEV_BRANCH}.${NORMAL}"
        echo -e ${WARNING_FULL}
        exit 1
    fi
done

if [[ ! $PWD =~ frameworks/av ]]; then
    exit 0
fi

mainline_count=0
total_count=0
echo
while read -r file ; do
    (( total_count++ ))
    for path in "${MAINLINE_FRAMEWORKS_AV_PATHS[@]}"; do
        if [[ $file =~ ^$path ]]; then
            echo -e "${RED}The source of truth for '$file' is in ${DEV_BRANCH}.${NORMAL}"
            (( mainline_count++ ))
            break
        fi
    done
done < <(git show --name-only --pretty=format: $1 | grep -- "$2")

if (( mainline_count != 0 )); then
    if (( mainline_count == total_count )); then
        echo -e ${WARNING_FULL}
    else
        echo -e ${WARNING_PARTIAL}
    fi
    exit 1
fi
exit 0
