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
DEV_BRANCH=rvc-dev

###
RED=$(tput setaf 1)
NORMAL=$(tput sgr0)

## check the active branch:
## * b131183694 d198c6a [goog/master] Fix to handle missing checks on error returned
##
current=`git branch -vv | grep -P "^\*[^\[]+\[goog/"|sed -e 's/^.*\[//' | sed -e 's/:.*$//'| sed -e 's/^goog\///'`
if [ "${current}" = "" ] ; then
        current=unknown
fi

if [ "${current}" = "${DEV_BRANCH}" ] ; then
    # Change appears to be in mainline dev branch
    exit 0
fi

## warn the user that about not being on the typical/desired branch.

cat - <<EOF

You are uploading repo  ${RED}${REPO_PATH}${NORMAL} to branch ${RED}${current}${NORMAL}. 
The source of truth for ${RED}${REPO_PATH}${NORMAL} is branch ${RED}${DEV_BRANCH}${NORMAL}. 

Please upload this change to branch ${RED}${DEV_BRANCH}${NORMAL} unless one or more of
the following apply:
- this is a security bug prohibited from disclosure before the next dessert release.
  (moderate security bugs fall into this category).
- this is new functionality prohibitied from disclosure before the next dessert release.
EOF


##
## TODO: prompt the user y/n to continue right now instead of re-invoking with no-verify
## this has to get around how repo buffers stdout from this script such that the output
## is not flushed before we try to read the input.
## 

cat - <<EOF
If you are sure you want to proceed uploading to branch ${RED}${current}${NORMAL},
re-run your repo upload command with the '--no-verify' option

EOF
exit 1

