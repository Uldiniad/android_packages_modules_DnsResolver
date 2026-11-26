/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "resolv_answer_callback_test"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <mutex>
#include <string>
#include <vector>

#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <netdutils/NetNativeTestBase.h>
#include <openssl/base64.h>
#include <private/android_filesystem_config.h>
#include <sysutils/SocketClient.h>

#include "DnsProxyListener.h"
#include "DnsResolver.h"
#include "dnsproxyd_protocol/DnsProxydProtocol.h"
#include "res_comp.h"
#include "tests/dns_responder/dns_responder.h"
#include "tests/resolv_test_callbacks.h"
#include "tests/resolv_test_utils.h"

namespace android::net {
namespace {

using android::base::unique_fd;

struct Answer {
    std::string name;
    std::vector<std::string> addresses;
    std::vector<std::string> cnames;
    bool operator==(const Answer&) const = default;
};

void PrintTo(const Answer& answer, std::ostream* os) {
    *os << answer.name << " " << ::testing::PrintToString(answer.addresses) << " "
        << ::testing::PrintToString(answer.cnames);
}

std::mutex gLock;
std::vector<Answer> gAnswers;
// The uids the answers were for.
std::vector<uid_t> gUids;
// Whether netd refuses the answers, as the firewall does those that point to a blocked name.
bool gRefuse = false;

bool recordAnswer(const android_net_context& netcontext, const char* name,
                  const char* const* cnames, size_t cnameCount, const in6_addr* addresses,
                  size_t count) {
    Answer answer = {.name = name};
    for (size_t i = 0; i < count; i++) {
        char text[INET6_ADDRSTRLEN];
        answer.addresses.push_back(inet_ntop(AF_INET6, &addresses[i], text, sizeof(text)));
    }
    answer.cnames.assign(cnames, cnames + cnameCount);
    std::lock_guard lock(gLock);
    gAnswers.push_back(answer);
    gUids.push_back(netcontext.uid);
    return !gRefuse;
}

std::vector<Answer> answers() {
    std::lock_guard lock(gLock);
    return gAnswers;
}

std::vector<uid_t> uids() {
    std::lock_guard lock(gLock);
    return gUids;
}

// What netd gives the resolver for an app's lookup on the network.
// The tethered client netd gives a uid of its own, and that uid.
constexpr const char* kTetheredClient = "192.0.2.99";
constexpr uid_t kTetheredClientUid = 8000;

uid_t tetheringClientUid(const in6_addr* address) {
    in6_addr client = {};
    client.s6_addr[10] = client.s6_addr[11] = 0xff;
    inet_pton(AF_INET, kTetheredClient, &client.s6_addr[12]);
    return memcmp(address, &client, sizeof(client)) == 0 ? kTetheredClientUid
                                                         : static_cast<uid_t>(-1);
}

void networkContext(uint32_t netId, uint32_t uid, android_net_context* netcontext) {
    *netcontext = {.app_netid = netId,
                   .app_mark = MARK_UNSET,
                   .dns_netid = netId,
                   .dns_mark = MARK_UNSET,
                   .uid = uid};
}

// A query for the name's records of the type, base64-encoded as resnsend takes it.
std::string query(const std::string& name, ns_type type) {
    std::vector<uint8_t> packet = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    for (size_t start = 0; start <= name.size();) {
        size_t end = std::min(name.find('.', start), name.size());
        packet.push_back(static_cast<uint8_t>(end - start));
        packet.insert(packet.end(), name.begin() + start, name.begin() + end);
        start = end + 1;
    }
    packet.insert(packet.end(), {0, 0, static_cast<uint8_t>(type), 0, ns_c_in});
    size_t length;
    EVP_EncodedLength(&length, packet.size());
    std::string encoded(length, '\0');
    encoded.resize(EVP_EncodeBlock(reinterpret_cast<uint8_t*>(encoded.data()), packet.data(),
                                   packet.size()));
    return encoded;
}

// Takes an app's commands as netd's dnsproxyd socket does, from a socket pair.
class TestListener : public DnsProxyListener {
  public:
    using DnsProxyListener::onDataAvailable;
};

// One for all tests and never destroyed, as netd's isn't: destroying a listener that never
// started closes descriptors it doesn't own.
TestListener& listener() {
    static TestListener* listener = new TestListener();
    return *listener;
}

}  // namespace

class AnswerCallbackTest : public NetNativeTestBase {
  protected:
    void SetUp() override {
        const ResolverNetdCallbacks callbacks = {
                .check_calling_permission = &noop_checkCallingPermissionCallback,
                .get_network_context = &networkContext,
                .log = &noop_logCallback,
                .tagSocket = &noop_tagSocketCallback,
                .evaluate_domain_name = &noop_evaluateDomainNameCallback,
                .on_dns_answer = &recordAnswer,
                .tethering_client_uid = &tetheringClientUid,
        };
        // Fails to listen, as netd holds the dnsproxyd socket, but takes the callbacks.
        resolv_init(&callbacks);
        gDnsResolv->resolverCtrl.createNetworkCache(TEST_NETID);
        const res_params params = {
                .sample_validity = 300,
                .success_threshold = 25,
                .min_samples = 8,
                .max_samples = 8,
                .base_timeout_msec = 1000,
                .retry_count = 2,
        };
        ASSERT_EQ(0, resolv_set_nameservers(TEST_NETID, {test::kDefaultListenAddr},
                                            {"example.com"}, params, std::nullopt));
        std::lock_guard lock(gLock);
        gAnswers.clear();
        gUids.clear();
        gRefuse = false;
    }

    void TearDown() override {
        resetDnsResolverCallbacks();
        gDnsResolv->resolverCtrl.destroyNetworkCache(TEST_NETID);
    }

    // Sends the command as an app does. Returns what was reported by the time the reply reached
    // the app, after the handler is done with the socket, so the next test gets its own.
    std::vector<Answer> send(const std::string& command) {
        int fds[2];
        EXPECT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds));
        unique_fd app(fds[0]);
        SocketClient* client = new SocketClient(fds[1], true, false);
        EXPECT_EQ(static_cast<ssize_t>(command.size() + 1),
                  write(app.get(), command.c_str(), command.size() + 1));
        listener().onDataAvailable(client);
        client->decRef();
        std::vector<Answer> reported;
        bool replied = false;
        char buffer[1024];
        mReply.clear();
        pollfd reply = {.fd = app.get(), .events = POLLIN};
        while (poll(&reply, 1, 5000) == 1) {
            if (!replied) reported = answers();
            replied = true;
            ssize_t length = read(app.get(), buffer, sizeof(buffer));
            if (length <= 0) break;
            mReply.append(buffer, length);
        }
        EXPECT_TRUE(replied);
        return reported;
    }

    // A chain of two CNAME records to the test server's address for hello.example.com.
    void addCnameChain(test::DNSResponder& dns) {
        dns.addMapping(kHelloExampleCom, ns_type::ns_t_cname, "alias.example.com.");
        dns.addMapping("alias.example.com.", ns_type::ns_t_cname, "edge.example.net.");
        dns.addMapping("edge.example.net.", ns_type::ns_t_a, kHelloExampleComAddrV4);
    }

    const std::string mNetId = std::to_string(TEST_NETID);
    // The bytes the app got back for the last command.
    std::string mReply;
};

TEST_F(AnswerCallbackTest, GetAddrInfoReportsTheAnswerBeforeTheAppGetsIt) {
    test::DNSResponder dns;
    dns.addMapping(kHelloExampleCom, ns_type::ns_t_a, kHelloExampleComAddrV4);
    ASSERT_TRUE(dns.startServer());
    // As Java's lookups ask: one result per address, not one per socket type.
    EXPECT_EQ((std::vector<Answer>{{"hello", {"::ffff:1.2.3.4"}}}),
              send("getaddrinfo hello ^ 0 " + std::to_string(AF_INET) + " " +
                   std::to_string(SOCK_STREAM) + " 0 " + mNetId));
}

TEST_F(AnswerCallbackTest, GetHostByNameReportsTheAnswerBeforeTheAppGetsIt) {
    test::DNSResponder dns;
    dns.addMapping(kHelloExampleCom, ns_type::ns_t_aaaa, "2001:db8::1");
    ASSERT_TRUE(dns.startServer());
    EXPECT_EQ((std::vector<Answer>{{"hello", {"2001:db8::1"}}}),
              send("gethostbyname " + mNetId + " hello " + std::to_string(AF_INET6)));
}

TEST_F(AnswerCallbackTest, ResNSendReportsTheAnswerBeforeTheAppGetsIt) {
    test::DNSResponder dns;
    dns.addMapping(kHelloExampleCom, ns_type::ns_t_a, kHelloExampleComAddrV4);
    ASSERT_TRUE(dns.startServer());
    EXPECT_EQ((std::vector<Answer>{{"hello.example.com", {"::ffff:1.2.3.4"}}}),
              send("resnsend " + mNetId + " 0 " + query("hello.example.com", ns_type::ns_t_a)));
}

TEST_F(AnswerCallbackTest, RequestsAfterForUidAreForThatAppWhenTheCallerMayChargeIt) {
    test::DNSResponder dns;
    dns.addMapping(kHelloExampleCom, ns_type::ns_t_a, kHelloExampleComAddrV4);
    ASSERT_TRUE(dns.startServer());
    const std::string lookup = "getaddrinfo hello ^ 0 " + std::to_string(AF_INET) + " " +
                               std::to_string(SOCK_STREAM) + " 0 " + mNetId;
    send(lookup);
    // As NetdClient sends them, in one write. Root, which runs this test, may charge others.
    // Android's restrictions on the app, such as on apps in the background, don't stop it.
    const uid_t app = 99 * AID_USER_OFFSET + AID_APP_START;
    send(std::string(DNSPROXYD_FOR_UID " ") + std::to_string(app) + '\0' + lookup);
    EXPECT_EQ((std::vector<uid_t>{getuid(), app}), uids());
}

TEST_F(AnswerCallbackTest, RequestsAfterForClientAreForTheUidNetdGivesThatClient) {
    test::DNSResponder dns;
    dns.addMapping(kHelloExampleCom, ns_type::ns_t_a, kHelloExampleComAddrV4);
    ASSERT_TRUE(dns.startServer());
    const std::string lookup = "getaddrinfo hello ^ 0 " + std::to_string(AF_INET) + " " +
                               std::to_string(SOCK_STREAM) + " 0 " + mNetId;
    const std::string forClient = std::string(DNSPROXYD_FOR_CLIENT " ") + kTetheredClient + '\0';
    // Only the tethering DNS proxy may name the client it asks for.
    send(forClient + lookup);
    // The socket pair takes the uid it's made with, as dnsmasq's connection has dnsmasq's.
    ASSERT_EQ(0, seteuid(AID_DNS_TETHER));
    send(forClient + lookup);
    send(std::string(DNSPROXYD_FOR_CLIENT " 192.0.2.98") + '\0' + lookup);
    ASSERT_EQ(0, seteuid(0));
    EXPECT_EQ((std::vector<uid_t>{0, kTetheredClientUid, AID_DNS_TETHER}), uids());
}

TEST_F(AnswerCallbackTest, AnswersReportTheNamesTheirCnamesPointTo) {
    test::DNSResponder dns;
    addCnameChain(dns);
    ASSERT_TRUE(dns.startServer());
    const std::vector<std::string> chain = {"alias.example.com", "edge.example.net"};
    EXPECT_EQ((std::vector<Answer>{{"hello", {"::ffff:1.2.3.4"}, chain}}),
              send("getaddrinfo hello ^ 0 " + std::to_string(AF_INET) + " " +
                   std::to_string(SOCK_STREAM) + " 0 " + mNetId));
    EXPECT_EQ((std::vector<Answer>{{"hello", {"::ffff:1.2.3.4"}, chain},
                                   {"hello", {"::ffff:1.2.3.4"}, chain}}),
              send("gethostbyname " + mNetId + " hello " + std::to_string(AF_INET)));
    send("resnsend " + mNetId + " 0 " + query("hello.example.com", ns_type::ns_t_a));
    EXPECT_EQ((Answer{"hello.example.com", {"::ffff:1.2.3.4"}, chain}), answers().back());
}

TEST_F(AnswerCallbackTest, AnAnswerNetdRefusesFailsAsARefusedNameDoes) {
    test::DNSResponder dns;
    addCnameChain(dns);
    ASSERT_TRUE(dns.startServer());
    gRefuse = true;
    // DnsProxyOperationFailed instead of DnsProxyQueryResult, with EAI_SYSTEM.
    send("getaddrinfo hello ^ 0 " + std::to_string(AF_INET) + " " + std::to_string(SOCK_STREAM) +
         " 0 " + mNetId);
    EXPECT_EQ("401", mReply.substr(0, 3));
    send("gethostbyname " + mNetId + " hello " + std::to_string(AF_INET));
    EXPECT_EQ("401", mReply.substr(0, 3));
    // -EAI_SYSTEM in place of the rcode, and no answer.
    send("resnsend " + mNetId + " 0 " + query("hello.example.com", ns_type::ns_t_a));
    const uint32_t refused = htonl(static_cast<uint32_t>(-EAI_SYSTEM));
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(&refused), sizeof(refused)), mReply);
}

// netd's name in place of hello.example.com, as a firewall has search engines' safe-search
// names looked up in place of theirs.
bool replaceHello(const android_net_context&, const char* name, char* buffer, size_t size) {
    if (strcmp(name, "hello.example.com") != 0) return false;
    strlcpy(buffer, "safe.example.com", size);
    return true;
}

TEST_F(AnswerCallbackTest, ANameNetdReplacesGetsTheOtherNamesAnswerUnderACname) {
    test::DNSResponder dns;
    dns.addMapping(kHelloExampleCom, ns_type::ns_t_a, kHelloExampleComAddrV4);
    dns.addMapping("safe.example.com.", ns_type::ns_t_a, "1.2.3.5");
    dns.addMapping("other.example.com.", ns_type::ns_t_a, kHelloExampleComAddrV4);
    ASSERT_TRUE(dns.startServer());
    gResNetdCallbacks.query_name = &replaceHello;
    const Answer safe = {"hello.example.com", {"::ffff:1.2.3.5"}, {"safe.example.com"}};
    send("getaddrinfo hello.example.com ^ 0 " + std::to_string(AF_INET) + " " +
         std::to_string(SOCK_STREAM) + " 0 " + mNetId);
    EXPECT_EQ(safe, answers().back());
    send("gethostbyname " + mNetId + " hello.example.com " + std::to_string(AF_INET));
    EXPECT_EQ(safe, answers().back());

    // A raw query gets back its own question, answered by a CNAME record to the other name, then
    // that name's records: after the rcode and the length, as the reply frames them.
    send("resnsend " + mNetId + " 0 " + query("hello.example.com", ns_type::ns_t_a));
    EXPECT_EQ(safe, answers().back());
    ASSERT_GT(mReply.size(), 8u);
    ns_msg handle;
    ASSERT_EQ(0, ns_initparse(reinterpret_cast<const uint8_t*>(mReply.data()) + 8,
                              mReply.size() - 8, &handle));
    EXPECT_EQ(0x1234, ns_msg_id(handle));
    ns_rr rr;
    ASSERT_EQ(0, ns_parserr(&handle, ns_s_qd, 0, &rr));
    EXPECT_STREQ("hello.example.com", ns_rr_name(rr));
    EXPECT_EQ(ns_t_a, ns_rr_type(rr));
    ASSERT_EQ(2, ns_msg_count(handle, ns_s_an));
    ASSERT_EQ(0, ns_parserr(&handle, ns_s_an, 0, &rr));
    EXPECT_STREQ("hello.example.com", ns_rr_name(rr));
    ASSERT_EQ(ns_t_cname, ns_rr_type(rr));
    char target[NS_MAXDNAME];
    ASSERT_LT(0, dn_expand(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr), target,
                           sizeof(target)));
    EXPECT_STREQ("safe.example.com", target);
    ASSERT_EQ(0, ns_parserr(&handle, ns_s_an, 1, &rr));
    EXPECT_STREQ("safe.example.com", ns_rr_name(rr));
    EXPECT_EQ(ns_t_a, ns_rr_type(rr));

    // Other names are looked up as asked.
    send("getaddrinfo other.example.com ^ 0 " + std::to_string(AF_INET) + " " +
         std::to_string(SOCK_STREAM) + " 0 " + mNetId);
    EXPECT_EQ((Answer{"other.example.com", {"::ffff:1.2.3.4"}}), answers().back());
}

TEST_F(AnswerCallbackTest, FailedLookupsReportNothing) {
    test::DNSResponder dns;
    ASSERT_TRUE(dns.startServer());
    send("getaddrinfo hello ^ 0 " + std::to_string(AF_INET) + " 0 0 " + mNetId);
    send("resnsend " + mNetId + " 0 " + query("hello.example.com", ns_type::ns_t_a));
    EXPECT_EQ(std::vector<Answer>{}, answers());
}

}  // namespace android::net
