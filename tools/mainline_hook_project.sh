#!/bin/bash
#set -x

# called for repo projects that are part of the media mainline modules
# this is for projects where the entire project is part of mainline.
# we have a separate script for projects where only part of that project gets
# pulled into mainline.
#
# if the project's PREUPLOAD.cfg points to this script, it is by definition a project
# which is entirely within mainline.
#
# example PREUPLOAD.cfg using this script
# [Hook Scripts]
# mainline_hook = ${REPO_ROOT}/frameworks/av/tools/mainline_hook_project.sh
#


# tunables
DEV_BRANCH=main
MAINLINE_BRANCH=udc-mainline-prod

###
RED=$(tput setaf 1)
NORMAL=$(tput sgr0)

## check the active branch:
## * b131183694 d198c6a [goog/master] Fix to handle missing checks on error returned
##
current=`git branch -vv | grep -P "^\*[^\[]+\[goog/"|sed -e 's/^.*\[//' | sed -e 's/\].*$//'|sed -e 's/:.*$//'| sed -e 's/^goog\///'`
if [ "${current}" = "" ] ; then
        current=unknown
fi

# simple reminder that it should also land in mainline branch
#
if [ "${current}" != "${MAINLINE_BRANCH}" ] ; then
        # simple reminder to ensure it hits mainline
        cat - <<EOF
You are uploading repo  ${RED}${REPO_PATH}${NORMAL} to branch ${RED}${current}${NORMAL}.
The mainline branch for ${RED}${REPO_PATH}${NORMAL} is branch ${RED}${MAINLINE_BRANCH}${NORMAL}.

Ensure an appropriate cherry pick or equivalent lands in branch ${RED}${MAINLINE_BRANCH}${NORMAL}.
Security bulletin timing or unreleased functionality may determine when that can be landed.

EOF
fi

# exit 0 is "all good, no output passed along to user"
# exit 77 is "all ok, but output is passed along to the user"
#
exit 77

