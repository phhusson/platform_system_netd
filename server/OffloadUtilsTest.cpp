/*
 * Copyright 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * OffloadUtilsTest.cpp - unit tests for OffloadUtils.cpp
 */

#include <gtest/gtest.h>

#include "OffloadUtils.h"

#include <linux/if_arp.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "bpf/BpfUtils.h"
#include "netdbpf/bpf_shared.h"

namespace android {
namespace net {

class OffloadUtilsTest : public ::testing::Test {
  public:
    void SetUp() {}
};

TEST_F(OffloadUtilsTest, HardwareAddressTypeOfNonExistingIf) {
    ASSERT_EQ(-ENODEV, hardwareAddressType("not_existing_if"));
}

TEST_F(OffloadUtilsTest, HardwareAddressTypeOfLoopback) {
    ASSERT_EQ(ARPHRD_LOOPBACK, hardwareAddressType("lo"));
}

// If wireless 'wlan0' interface exists it should be Ethernet.
TEST_F(OffloadUtilsTest, HardwareAddressTypeOfWireless) {
    int type = hardwareAddressType("wlan0");
    if (type == -ENODEV) return;

    ASSERT_EQ(ARPHRD_ETHER, type);
}

// If cellular 'rmnet_data0' interface exists it should
// *probably* not be Ethernet and instead be RawIp.
TEST_F(OffloadUtilsTest, HardwareAddressTypeOfCellular) {
    int type = hardwareAddressType("rmnet_data0");
    if (type == -ENODEV) return;

    ASSERT_NE(ARPHRD_ETHER, type);

    // ARPHRD_RAWIP is 530 on some pre-4.14 Qualcomm devices.
    if (type == 530) return;

    ASSERT_EQ(ARPHRD_RAWIP, type);
}

TEST_F(OffloadUtilsTest, IsEthernetOfNonExistingIf) {
    auto res = isEthernet("not_existing_if");
    ASSERT_FALSE(res.ok());
    ASSERT_EQ(ENODEV, res.error().code());
}

TEST_F(OffloadUtilsTest, IsEthernetOfLoopback) {
    auto res = isEthernet("lo");
    ASSERT_FALSE(res.ok());
    ASSERT_EQ(EAFNOSUPPORT, res.error().code());
}

// If wireless 'wlan0' interface exists it should be Ethernet.
// See also HardwareAddressTypeOfWireless.
TEST_F(OffloadUtilsTest, IsEthernetOfWireless) {
    auto res = isEthernet("wlan0");
    if (!res.ok() && res.error().code() == ENODEV) return;

    ASSERT_RESULT_OK(res);
    ASSERT_TRUE(res.value());
}

// If cellular 'rmnet_data0' interface exists it should
// *probably* not be Ethernet and instead be RawIp.
// See also HardwareAddressTypeOfCellular.
TEST_F(OffloadUtilsTest, IsEthernetOfCellular) {
    auto res = isEthernet("rmnet_data0");
    if (!res.ok() && res.error().code() == ENODEV) return;

    ASSERT_RESULT_OK(res);
    ASSERT_FALSE(res.value());
}

TEST_F(OffloadUtilsTest, GetClatEgress4MapFd) {
    int fd = getClatEgress4MapFd();
    ASSERT_GE(fd, 3);  // 0,1,2 - stdin/out/err, thus fd >= 3
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetClatEgress4RawIpProgFd) {
    int fd = getClatEgress4ProgFd(RAWIP);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetClatEgress4EtherProgFd) {
    int fd = getClatEgress4ProgFd(ETHER);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetClatIngress6MapFd) {
    int fd = getClatIngress6MapFd();
    ASSERT_GE(fd, 3);  // 0,1,2 - stdin/out/err, thus fd >= 3
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetClatIngress6RawIpProgFd) {
    int fd = getClatIngress6ProgFd(RAWIP);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetClatIngress6EtherProgFd) {
    int fd = getClatIngress6ProgFd(ETHER);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherDownstream6MapFd) {
    int fd = getTetherDownstream6MapFd();
    ASSERT_GE(fd, 3);  // 0,1,2 - stdin/out/err, thus fd >= 3
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherDownstream64MapFd) {
    int fd = getTetherDownstream64MapFd();
    ASSERT_GE(fd, 3);  // 0,1,2 - stdin/out/err, thus fd >= 3
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherDownstream4MapFd) {
    int fd = getTetherDownstream4MapFd();
    ASSERT_GE(fd, 3);  // 0,1,2 - stdin/out/err, thus fd >= 3
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherDownstream6RawIpTcProgFd) {
    // RX Rawip -> TX Ether requires header adjustments and thus 4.14.
    SKIP_IF_EXTENDED_BPF_NOT_SUPPORTED;

    int fd = getTetherDownstream6TcProgFd(RAWIP);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherDownstream6EtherTcProgFd) {
    // RX Ether -> TX Ether does not require header adjustments
    int fd = getTetherDownstream6TcProgFd(ETHER);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherDownstream4RawIpTcProgFd) {
    // RX Rawip -> TX Ether requires header adjustments and thus 4.14.
    SKIP_IF_EXTENDED_BPF_NOT_SUPPORTED;

    int fd = getTetherDownstream4TcProgFd(RAWIP);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherDownstream4EtherTcProgFd) {
    // RX Ether -> TX Ether does not require header adjustments
    int fd = getTetherDownstream4TcProgFd(ETHER);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherUpstream6MapFd) {
    int fd = getTetherUpstream6MapFd();
    ASSERT_GE(fd, 3);  // 0,1,2 - stdin/out/err, thus fd >= 3
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherUpstream4MapFd) {
    int fd = getTetherUpstream4MapFd();
    ASSERT_GE(fd, 3);  // 0,1,2 - stdin/out/err, thus fd >= 3
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherUpstream6RawIpTcProgFd) {
    // RX Rawip -> TX Ether requires header adjustments and thus 4.14.
    SKIP_IF_EXTENDED_BPF_NOT_SUPPORTED;

    int fd = getTetherUpstream6TcProgFd(RAWIP);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherUpstream6EtherTcProgFd) {
    // RX Ether -> TX Ether does not require header adjustments
    int fd = getTetherUpstream6TcProgFd(ETHER);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherUpstream4RawIpTcProgFd) {
    // RX Rawip -> TX Ether requires header adjustments and thus 4.14.
    SKIP_IF_EXTENDED_BPF_NOT_SUPPORTED;

    int fd = getTetherUpstream4TcProgFd(RAWIP);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherUpstream4EtherTcProgFd) {
    // RX Ether -> TX Ether does not require header adjustments
    int fd = getTetherUpstream4TcProgFd(ETHER);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherDownstreamRawIpXdpProgFd) {
    SKIP_IF_XDP_NOT_SUPPORTED;

    int fd = getTetherDownstreamXdpProgFd(RAWIP);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherDownstreamEtherXdpProgFd) {
    SKIP_IF_XDP_NOT_SUPPORTED;

    int fd = getTetherDownstreamXdpProgFd(ETHER);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherUpstreamRawIpXdpProgFd) {
    SKIP_IF_XDP_NOT_SUPPORTED;

    int fd = getTetherUpstreamXdpProgFd(RAWIP);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherUpstreamEtherXdpProgFd) {
    SKIP_IF_XDP_NOT_SUPPORTED;

    int fd = getTetherUpstreamXdpProgFd(ETHER);
    ASSERT_GE(fd, 3);
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherStatsMapFd) {
    int fd = getTetherStatsMapFd();
    ASSERT_GE(fd, 3);  // 0,1,2 - stdin/out/err, thus fd >= 3
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

TEST_F(OffloadUtilsTest, GetTetherLimitMapFd) {
    int fd = getTetherLimitMapFd();
    ASSERT_GE(fd, 3);  // 0,1,2 - stdin/out/err, thus fd >= 3
    EXPECT_EQ(FD_CLOEXEC, fcntl(fd, F_GETFD));
    close(fd);
}

// See Linux kernel source in include/net/flow.h
#define LOOPBACK_IFINDEX 1

TEST_F(OffloadUtilsTest, AttachReplaceDetachClsactLo) {
    // This attaches and detaches a configuration-less and thus no-op clsact
    // qdisc to loopback interface (and it takes fractions of a second)
    EXPECT_EQ(0, tcQdiscAddDevClsact(LOOPBACK_IFINDEX));
    EXPECT_EQ(0, tcQdiscReplaceDevClsact(LOOPBACK_IFINDEX));
    EXPECT_EQ(0, tcQdiscDelDevClsact(LOOPBACK_IFINDEX));
    EXPECT_EQ(-EINVAL, tcQdiscDelDevClsact(LOOPBACK_IFINDEX));
}

static void checkAttachDetachBpfFilterClsactLo(const bool ingress, const bool ethernet,
                                               const bool downstream) {
    const bool extended = android::bpf::isAtLeastKernelVersion(4, 14, 0);
    // Older kernels return EINVAL instead of ENOENT due to lacking proper error propagation...
    const int errNOENT = android::bpf::isAtLeastKernelVersion(4, 19, 0) ? ENOENT : EINVAL;

    int clatBpfFd = ingress ? getClatIngress6ProgFd(ethernet) : getClatEgress4ProgFd(ethernet);
    ASSERT_GE(clatBpfFd, 3);

    int tether6BpfFd = -1;
    int tether4BpfFd = -1;
    if (extended && ingress) {
        tether6BpfFd = downstream ? getTetherDownstream6TcProgFd(ethernet)
                                  : getTetherUpstream6TcProgFd(ethernet);
        ASSERT_GE(tether6BpfFd, 3);
        tether4BpfFd = downstream ? getTetherDownstream4TcProgFd(ethernet)
                                  : getTetherUpstream4TcProgFd(ethernet);
        ASSERT_GE(tether4BpfFd, 3);
    }

    // This attaches and detaches a clsact plus ebpf program to loopback
    // interface, but it should not affect traffic by virtue of us not
    // actually populating the ebpf control map.
    // Furthermore: it only takes fractions of a second.
    EXPECT_EQ(-EINVAL, tcFilterDelDevIngressClatIpv6(LOOPBACK_IFINDEX));
    EXPECT_EQ(-EINVAL, tcFilterDelDevEgressClatIpv4(LOOPBACK_IFINDEX));
    EXPECT_EQ(0, tcQdiscAddDevClsact(LOOPBACK_IFINDEX));
    EXPECT_EQ(-errNOENT, tcFilterDelDevIngressClatIpv6(LOOPBACK_IFINDEX));
    EXPECT_EQ(-errNOENT, tcFilterDelDevEgressClatIpv4(LOOPBACK_IFINDEX));
    if (ingress) {
        EXPECT_EQ(0, tcFilterAddDevIngressClatIpv6(LOOPBACK_IFINDEX, clatBpfFd, ethernet));
        if (extended) {
            EXPECT_EQ(0, tcFilterAddDevIngress6Tether(LOOPBACK_IFINDEX, tether6BpfFd, ethernet,
                                                      downstream));
            EXPECT_EQ(0, tcFilterAddDevIngress4Tether(LOOPBACK_IFINDEX, tether4BpfFd, ethernet,
                                                      downstream));
            EXPECT_EQ(0, tcFilterDelDevIngress6Tether(LOOPBACK_IFINDEX));
            EXPECT_EQ(0, tcFilterDelDevIngress4Tether(LOOPBACK_IFINDEX));
        }
        EXPECT_EQ(0, tcFilterDelDevIngressClatIpv6(LOOPBACK_IFINDEX));
    } else {
        EXPECT_EQ(0, tcFilterAddDevEgressClatIpv4(LOOPBACK_IFINDEX, clatBpfFd, ethernet));
        EXPECT_EQ(0, tcFilterDelDevEgressClatIpv4(LOOPBACK_IFINDEX));
    }
    EXPECT_EQ(-errNOENT, tcFilterDelDevIngressClatIpv6(LOOPBACK_IFINDEX));
    EXPECT_EQ(-errNOENT, tcFilterDelDevEgressClatIpv4(LOOPBACK_IFINDEX));
    EXPECT_EQ(0, tcQdiscDelDevClsact(LOOPBACK_IFINDEX));
    EXPECT_EQ(-EINVAL, tcFilterDelDevIngressClatIpv6(LOOPBACK_IFINDEX));
    EXPECT_EQ(-EINVAL, tcFilterDelDevEgressClatIpv4(LOOPBACK_IFINDEX));

    if (tether4BpfFd != -1) close(tether4BpfFd);
    if (tether6BpfFd != -1) close(tether6BpfFd);
    close(clatBpfFd);
}

TEST_F(OffloadUtilsTest, CheckAttachBpfFilterRawIpClsactEgressLo) {
    checkAttachDetachBpfFilterClsactLo(EGRESS, RAWIP, UPSTREAM);
}

TEST_F(OffloadUtilsTest, CheckAttachBpfFilterEthernetClsactEgressLo) {
    checkAttachDetachBpfFilterClsactLo(EGRESS, ETHER, UPSTREAM);
}

TEST_F(OffloadUtilsTest, CheckAttachBpfFilterRawIpClsactIngressLo) {
    checkAttachDetachBpfFilterClsactLo(INGRESS, RAWIP, DOWNSTREAM);
    checkAttachDetachBpfFilterClsactLo(INGRESS, RAWIP, UPSTREAM);
}

TEST_F(OffloadUtilsTest, CheckAttachBpfFilterEthernetClsactIngressLo) {
    checkAttachDetachBpfFilterClsactLo(INGRESS, ETHER, DOWNSTREAM);
    checkAttachDetachBpfFilterClsactLo(INGRESS, ETHER, UPSTREAM);
}

static int tryLoUdp4(bool expectSuccess) {
    errno = 0;

    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    EXPECT_GE(fd, 3);
    if (fd < 0) return -errno;

    struct sockaddr_in addr4 = {
            .sin_family = AF_INET,
    };
    int rv = bind(fd, (struct sockaddr*)&addr4, sizeof(addr4));
    EXPECT_EQ(0, rv);
    if (rv) return -errno;

    socklen_t addr4len = sizeof(addr4);
    rv = getsockname(fd, (struct sockaddr*)&addr4, &addr4len);
    EXPECT_EQ(0, rv);
    if (rv) return -errno;
    EXPECT_EQ(static_cast<socklen_t>(sizeof(addr4)), addr4len);

    rv = connect(fd, (struct sockaddr*)&addr4, sizeof(addr4));
    EXPECT_EQ(0, rv);
    if (rv) return -errno;

    char sendBuf[] = "hello";
    rv = send(fd, &sendBuf, sizeof(sendBuf), MSG_DONTWAIT);
    EXPECT_EQ(static_cast<int>(sizeof(sendBuf)), rv);

    char recvBuf[sizeof(sendBuf) + 1] = {};
    rv = recv(fd, &recvBuf, sizeof(recvBuf), MSG_DONTWAIT);

    if (expectSuccess) {
        EXPECT_EQ(static_cast<int>(sizeof(sendBuf)), rv);
        EXPECT_EQ(0, memcmp(sendBuf, recvBuf, sizeof(sendBuf)));
    } else {
        EXPECT_EQ(-1, rv);
        EXPECT_EQ(EAGAIN, errno);
    }

    rv = close(fd);
    EXPECT_EQ(0, rv);
    if (rv) return -errno;

    return 0;
}

TEST_F(OffloadUtilsTest, CheckAttachXdpLo) {
    SKIP_IF_XDP_NOT_SUPPORTED;

    const int xdpFd =
            bpf::retrieveProgram("/sys/fs/bpf/tethering/prog_test_xdp_drop_ipv4_udp_ether");
    ASSERT_GE(xdpFd, 3);  // 0,1,2 - stdin/out/err, thus fd >= 3
    EXPECT_EQ(FD_CLOEXEC, fcntl(xdpFd, F_GETFD));

    EXPECT_EQ(0, tryLoUdp4(true));
    EXPECT_EQ(0, addXDP(LOOPBACK_IFINDEX, xdpFd, XDP_FLAGS_SKB_MODE));
    EXPECT_EQ(0, tryLoUdp4(false));
    EXPECT_EQ(-EBUSY, addXDP(LOOPBACK_IFINDEX, xdpFd, XDP_FLAGS_SKB_MODE));
    EXPECT_EQ(0, tryLoUdp4(false));
    EXPECT_EQ(0, setXDP(LOOPBACK_IFINDEX, xdpFd, XDP_FLAGS_SKB_MODE));
    EXPECT_EQ(0, tryLoUdp4(false));
    EXPECT_EQ(0, removeXDP(LOOPBACK_IFINDEX, XDP_FLAGS_SKB_MODE));
    EXPECT_EQ(0, tryLoUdp4(true));

    close(xdpFd);
}

}  // namespace net
}  // namespace android
