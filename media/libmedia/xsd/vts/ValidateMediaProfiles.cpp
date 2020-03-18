/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <fstream>
#include <string>

#include <android-base/file.h>
#include <android-base/properties.h>
#include "utility/ValidateXml.h"

bool isFileReadable(std::string const& path) {
  std::ifstream f(path);
  return f.good();
}

TEST(CheckConfig, mediaProfilesValidation) {
    RecordProperty("description",
                   "Verify that the media profiles file "
                   "is valid according to the schema");

    // Schema path.
    constexpr char const* xsdPath = "/data/local/tmp/media_profiles.xsd";

    // If "media.settings.xml" is set, it will be used as an absolute path.
    std::string mediaSettingsPath = android::base::GetProperty("media.settings.xml", "");
    if (mediaSettingsPath.empty()) {
        // If "media.settings.xml" is not set, we will search through a list of
        // file paths.

        constexpr char const* xmlSearchDirs[] = {
                "/product/etc/",
                "/odm/etc/",
                "/vendor/etc/",
            };

        // The vendor may provide a vendor variant for the file name.
        std::string variant = android::base::GetProperty(
                "ro.media.xml_variant.profiles", "_V1_0");
        std::string fileName = "media_profiles" + variant + ".xml";

        // Fallback path does not depend on the property defined from the vendor
        // partition.
        constexpr char const* fallbackXmlPath =
                "/system/etc/media_profiles_V1_0.xml";

        std::vector<std::string> xmlPaths = {
                xmlSearchDirs[0] + fileName,
                xmlSearchDirs[1] + fileName,
                xmlSearchDirs[2] + fileName,
                fallbackXmlPath
            };

        auto findXmlPath =
            std::find_if(xmlPaths.begin(), xmlPaths.end(), isFileReadable);
        ASSERT_TRUE(findXmlPath != xmlPaths.end())
                << "Cannot read from " << fileName
                << " in any search directories ("
                << xmlSearchDirs[0] << ", "
                << xmlSearchDirs[1] << ", "
                << xmlSearchDirs[2] << ") and from "
                << fallbackXmlPath << ".";

        char const* xmlPath = findXmlPath->c_str();
        EXPECT_VALID_XML(xmlPath, xsdPath);
    } else {
        EXPECT_VALID_XML(mediaSettingsPath.c_str(), xsdPath);
    }
}
