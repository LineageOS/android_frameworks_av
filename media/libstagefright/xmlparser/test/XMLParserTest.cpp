/*
 * Copyright (C) 2020 The Android Open Source Project
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
#define LOG_TAG "XMLParserTest"

#include <utils/Log.h>

#include <fstream>

#include <media/stagefright/xmlparser/MediaCodecsXmlParser.h>

#include "XMLParserTestEnvironment.h"

#define XML_FILE_NAME "media_codecs_unit_test_caller.xml"

using namespace android;

static XMLParserTestEnvironment *gEnv = nullptr;

struct CodecProperties {
    string codecName;
    MediaCodecsXmlParser::CodecProperties codecProp;
};

struct RoleProperties {
    string roleName;
    string typeName;
    string codecName;
    bool isEncoder;
    size_t order;
    vector<pair<string, string>> attributeMap;
};

class XMLParseTest : public ::testing::Test {
  public:
    ~XMLParseTest() {
        if (mEleStream.is_open()) mEleStream.close();
        mInputDataVector.clear();
        mInputRoleVector.clear();
    }

    virtual void SetUp() override { setUpDatabase(); }

    void setUpDatabase();

    void setCodecProperties(string codecName, bool isEncoder, int32_t order, set<string> quirkSet,
                            set<string> domainSet, set<string> variantSet, string typeName,
                            vector<pair<string, string>> domain, vector<string> aliases,
                            string rank);

    void setRoleProperties(string roleName, bool isEncoder, int32_t order, string typeName,
                           string codecName, vector<pair<string, string>> domain);

    void setServiceAttribute(map<string, string> serviceAttributeNameValuePair);

    void printCodecMap(const MediaCodecsXmlParser::Codec mcodec);

    void checkRoleMap(int32_t index, bool isEncoder, string typeName, string codecName,
                      vector<pair<string, string>> attrMap);

    bool compareMap(const map<string, string> &lhs, const map<string, string> &rhs);

    ifstream mEleStream;
    MediaCodecsXmlParser mParser;
    vector<CodecProperties> mInputDataVector;
    vector<RoleProperties> mInputRoleVector;
    map<string, string> mInputServiceAttributeMap;
};

void XMLParseTest::setUpDatabase() {
    // The values set below are specific to test vector testdata/media_codecs_unit_test.xml
    setCodecProperties("test1.decoder", false, 1, {"attribute::disabled", "quirk::quirk1"},
                       {"telephony"}, {}, "audio/mpeg", {}, {"alias1.decoder"}, "4");

    setCodecProperties("test2.decoder", false, 2, {"quirk::quirk1"}, {}, {}, "audio/3gpp", {}, {},
                       "");

    setCodecProperties("test3.decoder", false, 3, {}, {}, {}, "audio/amr-wb",
                       {
                               pair<string, string>("feature-feature1", "feature1Val"),
                               pair<string, string>("feature-feature2", "0"),
                               pair<string, string>("feature-feature3", "0"),
                       },
                       {}, "");

    setCodecProperties("test4.decoder", false, 4, {}, {}, {}, "audio/flac",
                       {pair<string, string>("feature-feature1", "feature1Val")}, {}, "");

    setCodecProperties("test5.decoder", false, 5, {"attribute::attributeQuirk1"}, {}, {},
                       "audio/g711-mlaw", {}, {}, "");

    setCodecProperties("test6.decoder", false, 6, {}, {}, {"variant1", "variant2"},
                       "audio/mp4a-latm",
                       {pair<string, string>("variant1:::variant1Limit1-range",
                                             "variant1Limit1Min-variant1Limit1Max"),
                        pair<string, string>("variant1:::variant1Limit2-range",
                                             "variant1Limit2Low-variant1Limit2High"),
                        pair<string, string>("variant2:::variant2Limit1", "variant2Limit1Value")},
                       {}, "");

    setCodecProperties(
            "test7.decoder", false, 7, {}, {}, {}, "audio/vorbis",
            {
                    pair<string, string>("-min-limit1", "limit1Min"),
                    /*pair<string, string>("limit1-in", "limit1In"),*/
                    pair<string, string>("limit2-range", "limit2Min-limit2Max"),
                    pair<string, string>("limit2-scale", "limit2Scale"),
                    pair<string, string>("limit3-default", "limit3Val3"),
                    pair<string, string>("limit3-ranges", "limit3Val1,limit3Val2,limit3Val3"),
            },
            {}, "");

    setCodecProperties("test8.encoder", true, 8, {}, {}, {}, "audio/opus",
                       {pair<string, string>("max-limit1", "limit1Max")}, {}, "");

    setRoleProperties("audio_decoder.mp3", false, 1, "audio/mpeg", "test1.decoder",
                      {pair<string, string>("attribute::disabled", "present"),
                       pair<string, string>("rank", "4")});

    setRoleProperties("audio_decoder.amrnb", false, 2, "audio/3gpp", "test2.decoder", {});

    setRoleProperties("audio_decoder.amrwb", false, 3, "audio/amr-wb", "test3.decoder",
                      {pair<string, string>("feature-feature1", "feature1Val"),
                       pair<string, string>("feature-feature2", "0"),
                       pair<string, string>("feature-feature3", "0")});

    setRoleProperties("audio/flac", false, 4, "audio/flac", "test4.decoder",
                      {pair<string, string>("feature-feature1", "feature1Val")});

    setRoleProperties("audio_decoder.g711mlaw", false, 5, "audio/g711-mlaw", "test5.decoder",
                      {pair<string, string>("attribute::attributeQuirk1", "present")});

    setRoleProperties("audio_decoder.aac", false, 6, "audio/mp4a-latm", "test6.decoder",
                      {pair<string, string>("variant1:::variant1Limit1-range",
                                            "variant1Limit1Min-variant1Limit1Max"),
                       pair<string, string>("variant1:::variant1Limit2-range",
                                            "variant1Limit2Low-variant1Limit2High"),
                       pair<string, string>("variant2:::variant2Limit1", "variant2Limit1Value")});

    setRoleProperties("audio_decoder.vorbis", false, 7, "audio/vorbis", "test7.decoder",
                      {pair<string, string>("-min-limit1", "limit1Min"),
                       /*pair<string, string>("limit1-in", "limit1In"),*/
                       pair<string, string>("limit2-range", "limit2Min-limit2Max"),
                       pair<string, string>("limit2-scale", "limit2Scale"),
                       pair<string, string>("limit3-default", "limit3Val3"),
                       pair<string, string>("limit3-ranges", "limit3Val1,limit3Val2,limit3Val3")});

    setRoleProperties("audio_encoder.opus", true, 8, "audio/opus", "test8.encoder",
                      {pair<string, string>("max-limit1", "limit1Max")});

    setServiceAttribute(
            {pair<string, string>("domain-telephony", "0"), pair<string, string>("domain-tv", "0"),
             pair<string, string>("setting2", "0"), pair<string, string>("variant-variant1", "0")});
}

bool XMLParseTest::compareMap(const map<string, string> &lhs, const map<string, string> &rhs) {
    return lhs.size() == rhs.size() && equal(lhs.begin(), lhs.end(), rhs.begin());
}

void XMLParseTest::setCodecProperties(string codecName, bool isEncoder, int32_t order,
                                      set<string> quirkSet, set<string> domainSet,
                                      set<string> variantSet, string typeName,
                                      vector<pair<string, string>> domain, vector<string> aliases,
                                      string rank) {
    map<string, string> AttributeMapDB;
    for (const auto &AttrStr : domain) {
        AttributeMapDB.insert(AttrStr);
    }
    map<string, MediaCodecsXmlParser::AttributeMap> TypeMapDataBase;
    TypeMapDataBase.insert(
            pair<string, MediaCodecsXmlParser::AttributeMap>(typeName, AttributeMapDB));
    CodecProperties codecProperty;
    codecProperty.codecName = codecName;
    codecProperty.codecProp.isEncoder = isEncoder;
    codecProperty.codecProp.order = order;
    codecProperty.codecProp.quirkSet = quirkSet;
    codecProperty.codecProp.domainSet = domainSet;
    codecProperty.codecProp.variantSet = variantSet;
    codecProperty.codecProp.typeMap = TypeMapDataBase;
    codecProperty.codecProp.aliases = aliases;
    codecProperty.codecProp.rank = rank;
    mInputDataVector.push_back(codecProperty);
}

void XMLParseTest::setRoleProperties(string roleName, bool isEncoder, int32_t order,
                                     string typeName, string codecName,
                                     vector<pair<string, string>> attributeNameValuePair) {
    struct RoleProperties roleProperty;
    roleProperty.roleName = roleName;
    roleProperty.typeName = typeName;
    roleProperty.codecName = codecName;
    roleProperty.isEncoder = isEncoder;
    roleProperty.order = order;
    roleProperty.attributeMap = attributeNameValuePair;
    mInputRoleVector.push_back(roleProperty);
}

void XMLParseTest::setServiceAttribute(map<string, string> serviceAttributeNameValuePair) {
    for (const auto &serviceAttrStr : serviceAttributeNameValuePair) {
        mInputServiceAttributeMap.insert(serviceAttrStr);
    }
}

void XMLParseTest::printCodecMap(const MediaCodecsXmlParser::Codec mcodec) {
    const string &name = mcodec.first;
    ALOGV("codec name = %s\n", name.c_str());
    const MediaCodecsXmlParser::CodecProperties &properties = mcodec.second;
    bool isEncoder = properties.isEncoder;
    ALOGV("isEncoder = %d\n", isEncoder);
    size_t order = properties.order;
    ALOGV("order = %zu\n", order);
    string rank = properties.rank;
    ALOGV("rank = %s\n", rank.c_str());

    for (auto &itrQuirkSet : properties.quirkSet) {
        ALOGV("quirkSet= %s", itrQuirkSet.c_str());
    }

    for (auto &itrDomainSet : properties.domainSet) {
        ALOGV("domainSet= %s", itrDomainSet.c_str());
    }

    for (auto &itrVariantSet : properties.variantSet) {
        ALOGV("variantSet= %s", itrVariantSet.c_str());
    }

    map<string, MediaCodecsXmlParser::AttributeMap> TypeMap = properties.typeMap;
    ALOGV("The TypeMap is :");

    for (auto &itrTypeMap : TypeMap) {
        ALOGV("itrTypeMap->first\t%s\t", itrTypeMap.first.c_str());

        for (auto &itrAttributeMap : itrTypeMap.second) {
            ALOGV("AttributeMap->first = %s", itrAttributeMap.first.c_str());
            ALOGV("AttributeMap->second = %s", itrAttributeMap.second.c_str());
        }
    }
}

void XMLParseTest::checkRoleMap(int32_t index, bool isEncoder, string typeName, string codecName,
                                vector<pair<string, string>> AttributePairMap) {
    ASSERT_EQ(isEncoder, mInputRoleVector.at(index).isEncoder)
            << "Invalid RoleMap data. IsEncoder mismatch";
    ASSERT_EQ(typeName, mInputRoleVector.at(index).typeName)
            << "Invalid RoleMap data. typeName mismatch";
    ASSERT_EQ(codecName, mInputRoleVector.at(index).codecName)
            << "Invalid RoleMap data. codecName mismatch";

    vector<pair<string, string>>::iterator itr_attributeMapDB =
            (mInputRoleVector.at(index).attributeMap).begin();
    vector<pair<string, string>>::iterator itr_attributeMap = AttributePairMap.begin();
    for (; itr_attributeMap != AttributePairMap.end() &&
           itr_attributeMapDB != mInputRoleVector.at(index).attributeMap.end();
         ++itr_attributeMap, ++itr_attributeMapDB) {
        string attributeName = itr_attributeMap->first;
        string attributeNameDB = itr_attributeMapDB->first;
        string attributevalue = itr_attributeMap->second;
        string attributeValueDB = itr_attributeMapDB->second;
        ASSERT_EQ(attributeName, attributeNameDB)
                << "Invalid RoleMap data. Attribute name mismatch\t" << attributeName << " != "
                << "attributeNameDB";
        ASSERT_EQ(attributevalue, attributeValueDB)
                << "Invalid RoleMap data. Attribute value mismatch\t" << attributevalue << " != "
                << "attributeValueDB";
    }
}

TEST_F(XMLParseTest, CodecMapParseTest) {
    string inputFileName = gEnv->getRes() + XML_FILE_NAME;
    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true) << "Failed to open inputfile " << inputFileName;

    mParser.parseXmlPath(inputFileName);
    for (const MediaCodecsXmlParser::Codec &mcodec : mParser.getCodecMap()) {
        printCodecMap(mcodec);
        const MediaCodecsXmlParser::CodecProperties &properties = mcodec.second;
        int32_t index = properties.order - 1;
        ASSERT_GE(index, 0) << "Invalid order";
        ASSERT_EQ(mInputDataVector.at(index).codecName, mcodec.first.c_str())
                << "Invalid CodecMap data. codecName mismatch";
        ASSERT_EQ(properties.isEncoder, mInputDataVector.at(index).codecProp.isEncoder)
                << "Invalid CodecMap data. isEncoder mismatch";
        ASSERT_EQ(properties.order, mInputDataVector.at(index).codecProp.order)
                << "Invalid CodecMap data. order mismatch";

        set<string> quirkSetDB = mInputDataVector.at(index).codecProp.quirkSet;
        set<string> quirkSet = properties.quirkSet;
        set<string> quirkDifference;
        set_difference(quirkSetDB.begin(), quirkSetDB.end(), quirkSet.begin(), quirkSet.end(),
                       inserter(quirkDifference, quirkDifference.end()));
        ASSERT_EQ(quirkDifference.size(), 0) << "CodecMap:quirk mismatch";

        map<string, MediaCodecsXmlParser::AttributeMap> TypeMapDB =
                mInputDataVector.at(index).codecProp.typeMap;
        map<string, MediaCodecsXmlParser::AttributeMap> TypeMap = properties.typeMap;
        map<string, MediaCodecsXmlParser::AttributeMap>::iterator itr_TypeMapDB = TypeMapDB.begin();
        map<string, MediaCodecsXmlParser::AttributeMap>::iterator itr_TypeMap = TypeMap.begin();

        ASSERT_EQ(TypeMapDB.size(), TypeMap.size())
                << "Invalid CodecMap data. Typemap size mismatch";

        for (; itr_TypeMap != TypeMap.end() && itr_TypeMapDB != TypeMapDB.end();
             ++itr_TypeMap, ++itr_TypeMapDB) {
            ASSERT_EQ(itr_TypeMap->first, itr_TypeMapDB->first)
                    << "Invalid CodecMap data. type mismatch";
            bool flag = compareMap(itr_TypeMap->second, itr_TypeMapDB->second);
            ASSERT_TRUE(flag) << "typeMap mismatch";
        }
        ASSERT_EQ(mInputDataVector.at(index).codecProp.rank, properties.rank)
                << "Invalid CodecMap data. rank mismatch";
    }
}

TEST_F(XMLParseTest, RoleMapParseTest) {
    string inputFileName = gEnv->getRes() + XML_FILE_NAME;
    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true) << "Failed to open inputfile " << inputFileName;

    mParser.parseXmlPath(inputFileName);

    for (auto &mRole : mParser.getRoleMap()) {
        typedef pair<string, string> Attribute;
        const string &roleName = mRole.first;
        ALOGV("Role map:name = %s\n", roleName.c_str());
        const MediaCodecsXmlParser::RoleProperties &properties = mRole.second;
        string type = properties.type;
        ALOGV("Role map: type = %s\n", type.c_str());

        bool isEncoder = properties.isEncoder;
        ALOGV("Role map: isEncoder = %d\n", isEncoder);

        multimap<size_t, MediaCodecsXmlParser::NodeInfo> nodeList = properties.nodeList;
        multimap<size_t, MediaCodecsXmlParser::NodeInfo>::iterator itr_Node;
        ALOGV("\nThe multimap nodeList is : \n");
        for (itr_Node = nodeList.begin(); itr_Node != nodeList.end(); ++itr_Node) {
            ALOGV("itr_Node->first=ORDER=\t%zu\t", itr_Node->first);
            int32_t index = itr_Node->first - 1;
            MediaCodecsXmlParser::NodeInfo nodePtr = itr_Node->second;
            ALOGV("Role map:itr_Node->second.name = %s\n", nodePtr.name.c_str());
            vector<Attribute> attrList = nodePtr.attributeList;
            for (auto attrNameValueList = attrList.begin(); attrNameValueList != attrList.end();
                 ++attrNameValueList) {
                ALOGV("Role map:nodePtr.attributeList->first = %s\n",
                      attrNameValueList->first.c_str());
                ALOGV("Role map:nodePtr.attributeList->second = %s\n",
                      attrNameValueList->second.c_str());
            }
            checkRoleMap(index, isEncoder, properties.type, nodePtr.name.c_str(), attrList);
        }
    }
}

TEST_F(XMLParseTest, ServiceAttributeMapParseTest) {
    string inputFileName = gEnv->getRes() + XML_FILE_NAME;
    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true) << "Failed to open inputfile " << inputFileName;

    mParser.parseXmlPath(inputFileName);
    const auto serviceAttributeMap = mParser.getServiceAttributeMap();
    for (const auto &attributePair : serviceAttributeMap) {
        ALOGV("serviceAttribute.key = %s \t serviceAttribute.value = %s",
              attributePair.first.c_str(), attributePair.second.c_str());
    }
    bool flag = compareMap(mInputServiceAttributeMap, serviceAttributeMap);
    ASSERT_TRUE(flag) << "ServiceMapParseTest: typeMap mismatch";
}

int main(int argc, char **argv) {
    gEnv = new XMLParserTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGD("XML Parser Test Result = %d\n", status);
    }
    return status;
}
