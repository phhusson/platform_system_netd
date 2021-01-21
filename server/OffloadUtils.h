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

#pragma once

#include <android-base/result.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>

#include <string>

#include "bpf/BpfUtils.h"
#include "netdbpf/bpf_shared.h"

namespace android {
namespace net {

// For better code clarity - do not change values - used for booleans like
// with_ethernet_header or isEthernet.
constexpr bool RAWIP = false;
constexpr bool ETHER = true;

// For better code clarity when used for 'bool ingress' parameter.
constexpr bool EGRESS = false;
constexpr bool INGRESS = true;

// For better code clarify when used for 'bool downstream' parameter.
//
// This is talking about the direction of travel of the offloaded packets.
//
// Upstream means packets heading towards the internet/uplink (upload),
// thus for tethering this is attached to ingress on the downstream interface,
// while for clat this is attached to egress on the v4-* clat interface.
//
// Downstream means packets coming from the internet/uplink (download), thus
// for both clat and tethering this is attached to ingress on the upstream interface.
constexpr bool UPSTREAM = false;
constexpr bool DOWNSTREAM = true;

// The priority of clat/tether hooks - smaller is higher priority.
// TC tether is higher priority then TC clat to match XDP winning over TC.
constexpr uint16_t PRIO_TETHER = 1;
constexpr uint16_t PRIO_CLAT = 3;

// this returns an ARPHRD_* constant or a -errno
int hardwareAddressType(const std::string& interface);

base::Result<bool> isEthernet(const std::string& interface);

inline int getClatEgress4MapFd(void) {
    const int fd = bpf::mapRetrieveRW(CLAT_EGRESS4_MAP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getClatEgress4ProgFd(bool with_ethernet_header) {
    const int fd = bpf::retrieveProgram(with_ethernet_header ? CLAT_EGRESS4_PROG_ETHER_PATH
                                                             : CLAT_EGRESS4_PROG_RAWIP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getClatIngress6MapFd(void) {
    const int fd = bpf::mapRetrieveRW(CLAT_INGRESS6_MAP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getClatIngress6ProgFd(bool with_ethernet_header) {
    const int fd = bpf::retrieveProgram(with_ethernet_header ? CLAT_INGRESS6_PROG_ETHER_PATH
                                                             : CLAT_INGRESS6_PROG_RAWIP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherDownstream6MapFd(void) {
    const int fd = bpf::mapRetrieveRW(TETHER_DOWNSTREAM6_MAP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherDownstream64MapFd(void) {
    const int fd = bpf::mapRetrieveRW(TETHER_DOWNSTREAM64_MAP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherDownstream4MapFd(void) {
    const int fd = bpf::mapRetrieveRW(TETHER_DOWNSTREAM4_MAP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherDownstream6TcProgFd(bool with_ethernet_header) {
    const int fd =
            bpf::retrieveProgram(with_ethernet_header ? TETHER_DOWNSTREAM6_TC_PROG_ETHER_PATH
                                                      : TETHER_DOWNSTREAM6_TC_PROG_RAWIP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherDownstream4TcProgFd(bool with_ethernet_header) {
    const int fd =
            bpf::retrieveProgram(with_ethernet_header ? TETHER_DOWNSTREAM4_TC_PROG_ETHER_PATH
                                                      : TETHER_DOWNSTREAM4_TC_PROG_RAWIP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherUpstream6MapFd(void) {
    const int fd = bpf::mapRetrieveRW(TETHER_UPSTREAM6_MAP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherUpstream4MapFd(void) {
    const int fd = bpf::mapRetrieveRW(TETHER_UPSTREAM4_MAP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherUpstream6TcProgFd(bool with_ethernet_header) {
    const int fd = bpf::retrieveProgram(with_ethernet_header ? TETHER_UPSTREAM6_TC_PROG_ETHER_PATH
                                                             : TETHER_UPSTREAM6_TC_PROG_RAWIP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherUpstream4TcProgFd(bool with_ethernet_header) {
    const int fd = bpf::retrieveProgram(with_ethernet_header ? TETHER_UPSTREAM4_TC_PROG_ETHER_PATH
                                                             : TETHER_UPSTREAM4_TC_PROG_RAWIP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherStatsMapFd(void) {
    const int fd = bpf::mapRetrieveRW(TETHER_STATS_MAP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherLimitMapFd(void) {
    const int fd = bpf::mapRetrieveRW(TETHER_LIMIT_MAP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherDownstreamXdpProgFd(bool with_ethernet_header) {
    const int fd =
            bpf::retrieveProgram(with_ethernet_header ? TETHER_DOWNSTREAM_XDP_PROG_ETHER_PATH
                                                      : TETHER_DOWNSTREAM_XDP_PROG_RAWIP_PATH);
    return (fd == -1) ? -errno : fd;
}

inline int getTetherUpstreamXdpProgFd(bool with_ethernet_header) {
    const int fd = bpf::retrieveProgram(with_ethernet_header ? TETHER_UPSTREAM_XDP_PROG_ETHER_PATH
                                                             : TETHER_UPSTREAM_XDP_PROG_RAWIP_PATH);
    return (fd == -1) ? -errno : fd;
}

int doTcQdiscClsact(int ifIndex, uint16_t nlMsgType, uint16_t nlMsgFlags);

inline int tcQdiscAddDevClsact(int ifIndex) {
    return doTcQdiscClsact(ifIndex, RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE);
}

inline int tcQdiscReplaceDevClsact(int ifIndex) {
    return doTcQdiscClsact(ifIndex, RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE);
}

inline int tcQdiscDelDevClsact(int ifIndex) {
    return doTcQdiscClsact(ifIndex, RTM_DELQDISC, 0);
}

// tc filter add dev .. in/egress prio ? protocol ipv6/ip bpf object-pinned /sys/fs/bpf/...
// direct-action
int tcFilterAddDevBpf(int ifIndex, bool ingress, uint16_t prio, uint16_t proto, int bpfFd,
                      bool ethernet, bool downstream);

// tc filter add dev .. ingress prio 3 protocol ipv6 bpf object-pinned /sys/fs/bpf/... direct-action
inline int tcFilterAddDevIngressClatIpv6(int ifIndex, int bpfFd, bool ethernet) {
    return tcFilterAddDevBpf(ifIndex, INGRESS, PRIO_CLAT, ETH_P_IPV6, bpfFd, ethernet, DOWNSTREAM);
}

// tc filter add dev .. egress prio 3 protocol ip bpf object-pinned /sys/fs/bpf/... direct-action
inline int tcFilterAddDevEgressClatIpv4(int ifIndex, int bpfFd, bool ethernet) {
    return tcFilterAddDevBpf(ifIndex, EGRESS, PRIO_CLAT, ETH_P_IP, bpfFd, ethernet, UPSTREAM);
}

// tc filter add dev .. ingress prio 1 protocol ipv6 bpf object-pinned /sys/fs/bpf/... direct-action
inline int tcFilterAddDevIngressTether(int ifIndex, int bpfFd, bool ethernet, bool downstream) {
    return tcFilterAddDevBpf(ifIndex, INGRESS, PRIO_TETHER, ETH_P_IPV6, bpfFd, ethernet,
                             downstream);
}

// tc filter del dev .. in/egress prio .. protocol ..
int tcFilterDelDev(int ifIndex, bool ingress, uint16_t prio, uint16_t proto);

// tc filter del dev .. ingress prio 3 protocol ipv6
inline int tcFilterDelDevIngressClatIpv6(int ifIndex) {
    return tcFilterDelDev(ifIndex, INGRESS, PRIO_CLAT, ETH_P_IPV6);
}

// tc filter del dev .. egress prio 3 protocol ip
inline int tcFilterDelDevEgressClatIpv4(int ifIndex) {
    return tcFilterDelDev(ifIndex, EGRESS, PRIO_CLAT, ETH_P_IP);
}

// tc filter del dev .. ingress prio 1 protocol ipv6
inline int tcFilterDelDevIngressTether(int ifIndex) {
    return tcFilterDelDev(ifIndex, INGRESS, PRIO_TETHER, ETH_P_IPV6);
}

}  // namespace net
}  // namespace android
