/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaExtractorFactory"
#include <utils/Log.h>

#include <binder/IServiceManager.h>
#include <media/DataSource.h>
#include <media/MediaAnalyticsItem.h>
#include <media/MediaExtractor.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/FileSource.h>
#include <media/stagefright/InterfaceUtils.h>
#include <media/stagefright/MediaExtractorFactory.h>
#include <media/stagefright/MetaData.h>
#include <media/IMediaExtractor.h>
#include <media/IMediaExtractorService.h>
#include <cutils/properties.h>
#include <utils/String8.h>
#include <ziparchive/zip_archive.h>

#include <dirent.h>
#include <dlfcn.h>

namespace android {

static const char *kSystemApkPath = "/system/app/MediaComponents/MediaComponents.apk";

// static
sp<IMediaExtractor> MediaExtractorFactory::Create(
        const sp<DataSource> &source, const char *mime) {
    ALOGV("MediaExtractorFactory::%s %s", __func__, mime);

    if (!property_get_bool("media.stagefright.extractremote", true)) {
        // local extractor
        ALOGW("creating media extractor in calling process");
        return CreateFromService(source, mime);
    } else {
        // remote extractor
        ALOGV("get service manager");
        sp<IBinder> binder = defaultServiceManager()->getService(String16("media.extractor"));

        if (binder != 0) {
            sp<IMediaExtractorService> mediaExService(interface_cast<IMediaExtractorService>(binder));
            sp<IMediaExtractor> ex = mediaExService->makeExtractor(
                    CreateIDataSourceFromDataSource(source), mime);
            return ex;
        } else {
            ALOGE("extractor service not running");
            return NULL;
        }
    }
    return NULL;
}

// static
sp<IMediaExtractor> MediaExtractorFactory::CreateFromFd(
        int fd, int64_t offset, int64_t length, const char *mime, sp<DataSource> *out) {
    ALOGV("MediaExtractorFactory::%s %s", __func__, mime);

    if (property_get_bool("media.stagefright.extractremote", true)) {
        // remote extractor
        ALOGV("get service manager");
        sp<IBinder> binder = defaultServiceManager()->getService(String16("media.extractor"));

        if (binder != 0) {
            sp<IMediaExtractorService> mediaExService(
                    interface_cast<IMediaExtractorService>(binder));
            if (!FileSource::requiresDrm(fd, offset, length, nullptr /* mime */)) {
                ALOGD("FileSource remote");
                sp<IDataSource> remoteSource =
                    mediaExService->makeIDataSource(fd, offset, length);
                ALOGV("IDataSource(FileSource): %p %d %lld %lld",
                        remoteSource.get(), fd, (long long)offset, (long long)length);
                if (remoteSource.get() != nullptr) {
                    // replace the caller's local source with remote source.
                    *out = CreateDataSourceFromIDataSource(remoteSource);
                    return mediaExService->makeExtractor(remoteSource, mime);
                } else {
                    ALOGW("extractor service cannot make file source."
                            " falling back to local file source.");
                }
            }
            // Falls back.
        } else {
            ALOGE("extractor service not running");
            return nullptr;
        }
    }
    *out = new FileSource(fd, offset, length);
    return Create(*out, mime);
}

sp<IMediaExtractor> MediaExtractorFactory::CreateFromService(
        const sp<DataSource> &source, const char *mime) {

    ALOGV("MediaExtractorFactory::CreateFromService %s", mime);

    UpdateExtractors(nullptr);

    // initialize source decryption if needed
    source->DrmInitialization(nullptr /* mime */);

    sp<AMessage> meta;

    MediaExtractor::CreatorFunc creator = NULL;
    String8 tmp;
    float confidence;
    sp<ExtractorPlugin> plugin;
    creator = sniff(source, &tmp, &confidence, &meta, plugin);
    if (!creator) {
        ALOGV("FAILED to autodetect media content.");
        return NULL;
    }

    mime = tmp.string();
    ALOGV("Autodetected media content as '%s' with confidence %.2f",
         mime, confidence);

    MediaExtractor *ret = creator(source, meta);
    return CreateIMediaExtractorFromMediaExtractor(ret, plugin);
}

//static
void MediaExtractorFactory::LoadPlugins(const ::std::string& apkPath) {
    // TODO: Verify apk path with package manager in extractor process.
    ALOGV("Load plugins from: %s", apkPath.c_str());
    UpdateExtractors(apkPath.empty() ? nullptr : apkPath.c_str());
}

struct ExtractorPlugin : public RefBase {
    MediaExtractor::ExtractorDef def;
    void *libHandle;
    String8 libPath;
    String8 uuidString;

    ExtractorPlugin(MediaExtractor::ExtractorDef definition, void *handle, String8 &path)
        : def(definition), libHandle(handle), libPath(path) {
        for (size_t i = 0; i < sizeof MediaExtractor::ExtractorDef::extractor_uuid; i++) {
            uuidString.appendFormat("%02x", def.extractor_uuid.b[i]);
        }
    }
    ~ExtractorPlugin() {
        if (libHandle != nullptr) {
            ALOGV("closing handle for %s %d", libPath.c_str(), def.extractor_version);
            dlclose(libHandle);
        }
    }
};

Mutex MediaExtractorFactory::gPluginMutex;
std::shared_ptr<List<sp<ExtractorPlugin>>> MediaExtractorFactory::gPlugins;
bool MediaExtractorFactory::gPluginsRegistered = false;

// static
MediaExtractor::CreatorFunc MediaExtractorFactory::sniff(
        const sp<DataSource> &source, String8 *mimeType, float *confidence, sp<AMessage> *meta,
        sp<ExtractorPlugin> &plugin) {
    *mimeType = "";
    *confidence = 0.0f;
    meta->clear();

    std::shared_ptr<List<sp<ExtractorPlugin>>> plugins;
    {
        Mutex::Autolock autoLock(gPluginMutex);
        if (!gPluginsRegistered) {
            return NULL;
        }
        plugins = gPlugins;
    }

    MediaExtractor::CreatorFunc curCreator = NULL;
    MediaExtractor::CreatorFunc bestCreator = NULL;
    for (auto it = plugins->begin(); it != plugins->end(); ++it) {
        String8 newMimeType;
        float newConfidence;
        sp<AMessage> newMeta;
        if ((curCreator = (*it)->def.sniff(source, &newMimeType, &newConfidence, &newMeta))) {
            if (newConfidence > *confidence) {
                *mimeType = newMimeType;
                *confidence = newConfidence;
                *meta = newMeta;
                plugin = *it;
                bestCreator = curCreator;
            }
        }
    }

    return bestCreator;
}

// static
void MediaExtractorFactory::RegisterExtractor(const sp<ExtractorPlugin> &plugin,
        List<sp<ExtractorPlugin>> &pluginList) {
    // sanity check check struct version, uuid, name
    if (plugin->def.def_version == 0
            || plugin->def.def_version > MediaExtractor::EXTRACTORDEF_VERSION) {
        ALOGE("don't understand extractor format %u, ignoring.", plugin->def.def_version);
        return;
    }
    if (memcmp(&plugin->def.extractor_uuid, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0) {
        ALOGE("invalid UUID, ignoring");
        return;
    }
    if (plugin->def.extractor_name == NULL || strlen(plugin->def.extractor_name) == 0) {
        ALOGE("extractors should have a name, ignoring");
        return;
    }

    for (auto it = pluginList.begin(); it != pluginList.end(); ++it) {
        if (memcmp(&((*it)->def.extractor_uuid), &plugin->def.extractor_uuid, 16) == 0) {
            // there's already an extractor with the same uuid
            if ((*it)->def.extractor_version < plugin->def.extractor_version) {
                // this one is newer, replace the old one
                ALOGW("replacing extractor '%s' version %u with version %u",
                        plugin->def.extractor_name,
                        (*it)->def.extractor_version,
                        plugin->def.extractor_version);
                pluginList.erase(it);
                break;
            } else {
                ALOGW("ignoring extractor '%s' version %u in favor of version %u",
                        plugin->def.extractor_name,
                        plugin->def.extractor_version,
                        (*it)->def.extractor_version);
                return;
            }
        }
    }
    ALOGV("registering extractor for %s", plugin->def.extractor_name);
    pluginList.push_back(plugin);
}

//static
void MediaExtractorFactory::RegisterExtractors(
        const char *apkPath, List<sp<ExtractorPlugin>> &pluginList) {
    ALOGV("search for plugins at %s", apkPath);
    ZipArchiveHandle zipHandle;
    int32_t ret = OpenArchive(apkPath, &zipHandle);
    if (ret == 0) {
        char abi[PROPERTY_VALUE_MAX];
        property_get("ro.product.cpu.abi", abi, "arm64-v8a");
        ZipString prefix(String8::format("lib/%s/", abi).c_str());
        ZipString suffix("extractor.so");
        void* cookie;
        ret = StartIteration(zipHandle, &cookie, &prefix, &suffix);
        if (ret == 0) {
            ZipEntry entry;
            ZipString name;
            while (Next(cookie, &entry, &name) == 0) {
                String8 libPath = String8(apkPath) + "!/" +
                    String8(reinterpret_cast<const char*>(name.name), name.name_length);
                void *libHandle = dlopen(libPath.string(), RTLD_NOW | RTLD_LOCAL);
                if (libHandle) {
                    MediaExtractor::GetExtractorDef getDef =
                        (MediaExtractor::GetExtractorDef) dlsym(libHandle, "GETEXTRACTORDEF");
                    if (getDef) {
                        ALOGV("registering sniffer for %s", libPath.string());
                        RegisterExtractor(
                                new ExtractorPlugin(getDef(), libHandle, libPath), pluginList);
                    } else {
                        ALOGW("%s does not contain sniffer", libPath.string());
                        dlclose(libHandle);
                    }
                } else {
                    ALOGW("couldn't dlopen(%s) %s", libPath.string(), strerror(errno));
                }
            }
            EndIteration(cookie);
        } else {
            ALOGW("couldn't find plugins from %s, %d", apkPath, ret);
        }
        CloseArchive(zipHandle);
    } else {
        ALOGW("couldn't open(%s) %d", apkPath, ret);
    }
}

// static
void MediaExtractorFactory::UpdateExtractors(const char *newUpdateApkPath) {
    Mutex::Autolock autoLock(gPluginMutex);
    if (newUpdateApkPath != nullptr) {
        gPluginsRegistered = false;
    }
    if (gPluginsRegistered) {
        return;
    }

    std::shared_ptr<List<sp<ExtractorPlugin>>> newList(new List<sp<ExtractorPlugin>>());

    RegisterExtractors(kSystemApkPath, *newList);

    if (newUpdateApkPath != nullptr) {
        RegisterExtractors(newUpdateApkPath, *newList);
    }

    gPlugins = newList;
    gPluginsRegistered = true;
}

status_t MediaExtractorFactory::dump(int fd, const Vector<String16>&) {
    Mutex::Autolock autoLock(gPluginMutex);
    String8 out;
    out.append("Available extractors:\n");
    for (auto it = gPlugins->begin(); it != gPlugins->end(); ++it) {
        out.appendFormat("  %25s: uuid(%s), version(%u), path(%s)\n",
                (*it)->def.extractor_name,
                (*it)->uuidString.c_str(),
                (*it)->def.extractor_version,
                (*it)->libPath.c_str());
    }
    write(fd, out.string(), out.size());
    return OK;
}


}  // namespace android
