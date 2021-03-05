/*
 * Copyright (C) 2014 The Android Open Source Project
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
#define LOG_TAG "Netd"

#include "Network.h"

#include "RouteController.h"
#include "SockDiag.h"
#include "log/log.h"

#include <android-base/strings.h>
#include <sstream>

namespace android {
namespace net {

Network::~Network() {
    if (!mInterfaces.empty()) {
        ALOGE("deleting network with netId %u without clearing its interfaces", mNetId);
    }
}

unsigned Network::getNetId() const {
    return mNetId;
}

bool Network::hasInterface(const std::string& interface) const {
    return mInterfaces.find(interface) != mInterfaces.end();
}

const std::set<std::string>& Network::getInterfaces() const {
    return mInterfaces;
}

int Network::clearInterfaces() {
    while (!mInterfaces.empty()) {
        // Make a copy of the string, so removeInterface() doesn't lose its parameter when it
        // removes the string from the set.
        std::string interface = *mInterfaces.begin();
        if (int ret = removeInterface(interface)) {
            return ret;
        }
    }
    return 0;
}

std::string Network::toString() const {
    const char kSeparator[] = " ";
    std::stringstream repr;

    repr << mNetId;

    repr << kSeparator;
    switch (getType()) {
        case DUMMY:
            repr << "DUMMY";
            break;
        case LOCAL:
            repr << "LOCAL";
            break;
        case PHYSICAL:
            repr << "PHYSICAL";
            break;
        case VIRTUAL:
            repr << "VIRTUAL";
            break;
        default:
            repr << "unknown";
    }

    if (mInterfaces.size() > 0) {
        repr << kSeparator << android::base::Join(mInterfaces, ",");
    }

    return repr.str();
}

bool Network::appliesToUser(uid_t uid) const {
    return mUidRanges.hasUid(uid);
}

bool Network::hasInvalidUidRanges(const UidRanges& uidRanges) const {
    if (uidRanges.overlapsSelf()) {
        ALOGE("uid range %s overlaps self", uidRanges.toString().c_str());
        return true;
    }

    if (uidRanges.overlaps(mUidRanges)) {
        ALOGE("uid range %s overlaps %s", uidRanges.toString().c_str(),
              mUidRanges.toString().c_str());
        return true;
    }
    return false;
}

int Network::addUsers(const UidRanges& uidRanges) {
    if (hasInvalidUidRanges(uidRanges)) {
        return -EINVAL;
    }

    for (const std::string& interface : mInterfaces) {
        int ret;
        if (isVirtual()) {
            ret = RouteController::addUsersToVirtualNetwork(mNetId, interface.c_str(), mSecure,
                                                            uidRanges);
        } else if (isPhysical()) {
            ret = RouteController::addUsersToPhysicalNetwork(mNetId, interface.c_str(), uidRanges);
        } else {
            ALOGE("failed to add users. Invalid network type %d, netId %d", getType(), mNetId);
            return -EINVAL;
        }
        if (ret) {
            ALOGE("failed to add users on interface %s of netId %u", interface.c_str(), mNetId);
            return ret;
        }
    }
    mUidRanges.add(uidRanges);
    return 0;
}

int Network::removeUsers(const UidRanges& uidRanges) {
    for (const std::string& interface : mInterfaces) {
        int ret;
        if (isVirtual()) {
            ret = RouteController::removeUsersFromVirtualNetwork(mNetId, interface.c_str(), mSecure,
                                                                 uidRanges);
        } else if (isPhysical()) {
            ret = RouteController::removeUsersFromPhysicalNetwork(mNetId, interface.c_str(),
                                                                  uidRanges);
        } else {
            ALOGE("failed to remove users. Invalid network type %d, netId %d", getType(), mNetId);
            return -EINVAL;
        }
        if (ret) {
            ALOGE("failed to remove users on interface %s of netId %u", interface.c_str(), mNetId);
            return ret;
        }
    }
    mUidRanges.remove(uidRanges);
    return 0;
}

bool Network::isSecure() const {
    return mSecure;
}

Network::Network(unsigned netId, bool secure) : mNetId(netId), mSecure(secure) {}

}  // namespace net
}  // namespace android
