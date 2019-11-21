/*
**
** Copyright 2008, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "mediadrmserver"
//#define LOG_NDEBUG 0

#include <signal.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>

using namespace android;

/*
 * Keep mediadrmserver in case it is referenced by build files we don't know of.
 * todo(robertshih): remove after verifying with `build_test.bash --dist --incremental`
 */
int main()
{
    signal(SIGPIPE, SIG_IGN);
    ProcessState::self()->startThreadPool();
    IPCThreadState::self()->joinThreadPool();
}
