// EOS P2P <-> UDP relay for Antigravity Crossplay Adapter.
// Connects to Epic Online Services under Klei deployment, accepts P2P connections on "EOSSocket",
// forwards datagrams to the local DST bridge over UDP (one socket per peer),
// and returns the bridge's replies to the mobile client over EOS P2P.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <time.h>
#include <errno.h>
#include <signal.h>
#ifdef _WIN32
// Windows build (mingw-w64): winsock instead of BSD sockets, see relay/build_win.sh.
#include <winsock2.h>
#include <windows.h>
#define usleep(us) Sleep((us) / 1000)
#define close_socket closesocket
static void set_nonblocking(int fd) {
    u_long on = 1;
    ioctlsocket(fd, FIONBIO, &on);
}
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define close_socket close
static void set_nonblocking(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}
#endif
#include <eos_sdk.h>
#include <eos_init.h>
#include <eos_connect.h>
#include <eos_p2p.h>
#include <eos_logging.h>

static EOS_HPlatform g_platform = nullptr;
static EOS_HP2P g_p2p = nullptr;
static EOS_HConnect g_connect = nullptr;
static EOS_ProductUserId g_local = nullptr;
static char g_puid[EOS_PRODUCTUSERID_MAX_LENGTH + 1] = {0};
static int g_udp_port = 11002;
static volatile sig_atomic_t g_running = 1;

static void EOS_CALL on_eos_log(const EOS_LogMessage* msg) {
    if (msg && msg->Message) {
        printf("[eos:%s] %s\n", msg->Category ? msg->Category : "?", msg->Message);
        fflush(stdout);
    }
}

static volatile int g_dev_done = 0, g_login_done = 0, g_nat_done = 0;
static EOS_EResult g_dev_res = EOS_EResult::EOS_UnexpectedError;
static EOS_EResult g_login_res = EOS_EResult::EOS_UnexpectedError;

struct Peer {
    EOS_ProductUserId id;
    char name[40];
    int fd;
    uint8_t channel;
    unsigned long long from_peer, to_peer;
    time_t last_seen;
    bool active;
};

#define MAX_PEERS 32
static Peer g_peers[MAX_PEERS];
static int g_npeers = 0;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static void EOS_CALL on_deviceid(const EOS_Connect_CreateDeviceIdCallbackInfo* d) {
    g_dev_res = d->ResultCode;
    g_dev_done = 1;
}

static void EOS_CALL on_login(const EOS_Connect_LoginCallbackInfo* d) {
    g_login_res = d->ResultCode;
    if (d->ResultCode == EOS_EResult::EOS_Success && d->LocalUserId) {
        g_local = d->LocalUserId;
        int32_t n = sizeof(g_puid);
        EOS_ProductUserId_ToString(g_local, g_puid, &n);
    }
    g_login_done = 1;
}

static void EOS_CALL on_nat(const EOS_P2P_OnQueryNATTypeCompleteInfo* d) {
    g_nat_done = 1;
    printf("[relay] QueryNATType -> %s (NAT Type: %d)\n", EOS_EResult_ToString(d->ResultCode), (int)d->NATType);
    fflush(stdout);
}

// Token refresh. The Connect token lives about an hour; EOS warns shortly before it
// expires. Logging in again with the same device id renews it in place and keeps the
// PUID, the P2P sockets and every connected player. Exiting here instead would drop
// them all once an hour.
enum { REFRESH_IDLE, REFRESH_WANTED, REFRESH_PENDING, REFRESH_BACKOFF };
#define REFRESH_RETRY_S 30
#define REFRESH_MAX_FAILS 5
#define INVALID_AUTH_MAX 3
static volatile int g_refresh = REFRESH_IDLE;
static int g_refresh_fails = 0;
static int g_invalid_auth = 0;
static time_t g_refresh_retry_at = 0;

static void connect_login() {
    EOS_Connect_Credentials cred = {};
    cred.ApiVersion = EOS_CONNECT_CREDENTIALS_API_LATEST;
    cred.Token = nullptr;
    cred.Type = EOS_EExternalCredentialType::EOS_ECT_DEVICEID_ACCESS_TOKEN;

    EOS_Connect_UserLoginInfo uli = {};
    uli.ApiVersion = EOS_CONNECT_USERLOGININFO_API_LATEST;
    uli.DisplayName = "dst-antigravity";

    EOS_Connect_LoginOptions o2 = {};
    o2.ApiVersion = EOS_CONNECT_LOGIN_API_LATEST;
    o2.Credentials = &cred;
    o2.UserLoginInfo = &uli;
    g_login_done = 0;
    EOS_Connect_Login(g_connect, &o2, nullptr, on_login);
}

static void EOS_CALL on_auth_expiration(const EOS_Connect_AuthExpirationCallbackInfo* d) {
    (void)d;
    printf("[relay] EOS Connect auth about to expire, refreshing the login\n");
    fflush(stdout);
    if (g_refresh == REFRESH_IDLE) g_refresh = REFRESH_WANTED;
}

static void refresh_step() {
    if (g_refresh == REFRESH_BACKOFF && time(NULL) >= g_refresh_retry_at) g_refresh = REFRESH_WANTED;
    if (g_refresh == REFRESH_WANTED) {
        g_refresh = REFRESH_PENDING;
        connect_login();
    } else if (g_refresh == REFRESH_PENDING && g_login_done) {
        if (g_login_res == EOS_EResult::EOS_Success) {
            printf("[relay] Login refreshed, PUID %s\n", g_puid);
            g_refresh = REFRESH_IDLE;
            g_refresh_fails = 0;
        } else {
            printf("[relay] Login refresh failed: %s (%d/%d)\n", EOS_EResult_ToString(g_login_res),
                   g_refresh_fails + 1, REFRESH_MAX_FAILS);
            if (++g_refresh_fails >= REFRESH_MAX_FAILS) {
                printf("[relay] Giving up on refresh, exiting for a supervised restart\n");
                fflush(stdout);
                exit(1);
            }
            g_refresh = REFRESH_BACKOFF;
            g_refresh_retry_at = time(NULL) + REFRESH_RETRY_S;
        }
        fflush(stdout);
    }
}

static void EOS_CALL on_interrupted(const EOS_P2P_OnPeerConnectionInterruptedInfo* d) {
    char r[40] = {0};
    int32_t n = sizeof(r);
    EOS_ProductUserId_ToString(d->RemoteUserId, r, &n);
    printf("[relay] Interrupted with %s (socket %s)\n", r, d->SocketId ? d->SocketId->SocketName : "?");
    fflush(stdout);
}

static void EOS_CALL on_conn_request(const EOS_P2P_OnIncomingConnectionRequestInfo* d) {
    char r[40] = {0};
    int32_t n = sizeof(r);
    EOS_ProductUserId_ToString(d->RemoteUserId, r, &n);
    printf("[relay] Connection request from %s (socket %s) -> accepting\n",
           r, d->SocketId ? d->SocketId->SocketName : "?");
    fflush(stdout);

    EOS_P2P_AcceptConnectionOptions a = {};
    a.ApiVersion = EOS_P2P_ACCEPTCONNECTION_API_LATEST;
    a.LocalUserId = d->LocalUserId;
    a.RemoteUserId = d->RemoteUserId;
    a.SocketId = d->SocketId;
    EOS_EResult res = EOS_P2P_AcceptConnection(g_p2p, &a);
    printf("[relay] AcceptConnection -> %s\n", EOS_EResult_ToString(res));
    fflush(stdout);
}

static void EOS_CALL on_established(const EOS_P2P_OnPeerConnectionEstablishedInfo* d) {
    char r[40] = {0};
    int32_t n = sizeof(r);
    EOS_ProductUserId_ToString(d->RemoteUserId, r, &n);
    printf("[relay] ESTABLISHED with %s (type %d)\n", r, (int)d->ConnectionType);
    fflush(stdout);
}

static void EOS_CALL on_closed(const EOS_P2P_OnRemoteConnectionClosedInfo* d) {
    char r[40] = {0};
    int32_t n = sizeof(r);
    EOS_ProductUserId_ToString(d->RemoteUserId, r, &n);
    printf("[relay] Closed with %s (reason %d)\n", r, (int)d->Reason);
    fflush(stdout);

    // Close the UDP socket for this peer so reconnect gets fresh socket/state
    for (int i = 0; i < g_npeers; i++) {
        if (g_peers[i].active && strcmp(g_peers[i].name, r) == 0) {
            if (g_peers[i].fd >= 0) close_socket(g_peers[i].fd);
            g_peers[i].fd = -1;
            g_peers[i].active = false;
            printf("[relay] Released UDP socket for %s\n", r);
            fflush(stdout);
            break;
        }
    }
}

static Peer* peer_for(EOS_ProductUserId id) {
    char key[40] = {0};
    int32_t kn = sizeof(key);
    EOS_ProductUserId_ToString(id, key, &kn);

    // Look for existing active peer
    for (int i = 0; i < g_npeers; i++) {
        if (g_peers[i].active && strcmp(g_peers[i].name, key) == 0) {
            g_peers[i].last_seen = time(NULL);
            return &g_peers[i];
        }
    }

    // Look for inactive slot or allocate new
    Peer* p = nullptr;
    for (int i = 0; i < g_npeers; i++) {
        if (!g_peers[i].active) {
            p = &g_peers[i];
            break;
        }
    }
    if (!p) {
        if (g_npeers >= MAX_PEERS) return nullptr;
        p = &g_peers[g_npeers++];
    }

    p->id = id;
    p->channel = 2; // Default to channel 2 (DST Mobile ping/data channel)
    p->from_peer = p->to_peer = 0;
    p->last_seen = time(NULL);
    p->active = true;
    strncpy(p->name, key, sizeof(p->name) - 1);

    p->fd = (int)socket(AF_INET, SOCK_DGRAM, 0);
    if (p->fd < 0) {
        perror("socket");
        p->active = false;
        return nullptr;
    }
    set_nonblocking(p->fd);

    sockaddr_in to = {};
    to.sin_family = AF_INET;
    to.sin_port = htons(g_udp_port);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(p->fd, (sockaddr*)&to, sizeof(to)) != 0) {
        perror("connect");
        close_socket(p->fd);
        p->fd = -1;
        p->active = false;
        return nullptr;
    }

    printf("[relay] Peer %s bound to new UDP socket -> 127.0.0.1:%d\n", p->name, g_udp_port);
    fflush(stdout);
    return p;
}

static void send_to_peer(Peer* p, const void* data, int len) {
    EOS_P2P_SendPacketOptions s = {};
    EOS_P2P_SocketId sid = {};
    sid.ApiVersion = EOS_P2P_SOCKETID_API_LATEST;
    strncpy(sid.SocketName, "EOSSocket", sizeof(sid.SocketName) - 1);

    s.ApiVersion = EOS_P2P_SENDPACKET_API_LATEST;
    s.LocalUserId = g_local;
    s.RemoteUserId = p->id;
    s.SocketId = &sid;
    // DST Mobile client's RakPeer::RunUpdateCycle ONLY reads incoming packets on channel 0 (GetGameIndex()).
    // EpicManager::Receive(0) strictly rejects any packet where packet.Channel != 0.
    // Therefore, all packets to mobile MUST be sent on channel 0!
    s.Channel = 0;
    s.DataLengthBytes = (uint32_t)len;
    s.Data = data;
    s.Reliability = EOS_EPacketReliability::EOS_PR_UnreliableUnordered;
    s.bAllowDelayedDelivery = EOS_TRUE;
    s.bDisableAutoAcceptConnection = EOS_FALSE;

    EOS_EResult r = EOS_P2P_SendPacket(g_p2p, &s);
    if (r != EOS_EResult::EOS_Success) {
        printf("[relay] SendPacket to %s failed: %s\n", p->name, EOS_EResult_ToString(r));
        fflush(stdout);
    }
    p->to_peer++;
}

int main(int argc, char** argv) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    timeBeginPeriod(1); // Sleep() is 15 ms coarse by default; the loop wants 2 ms
#endif

    int seconds = (argc > 1) ? atoi(argv[1]) : 0; // 0 = run indefinitely
    if (argc > 2) g_udp_port = atoi(argv[2]);

    const char* product = getenv("DST_EOS_PRODUCT_ID");
    const char* sandbox = getenv("DST_EOS_SANDBOX_ID");
    const char* deploy  = getenv("DST_EOS_DEPLOYMENT_ID");
    const char* cid     = getenv("DST_EOS_CLIENT_ID");
    const char* secret  = getenv("DST_EOS_CLIENT_SECRET");
    const char* puid_file = getenv("DST_EOS_PUID_FILE");
    const char* cache_dir = getenv("DST_EOS_CACHE_DIR");

    if (!product || !sandbox || !deploy || !cid || !secret) {
        fprintf(stderr, "missing DST_EOS_* env\n");
        return 2;
    }

    EOS_InitializeOptions io = {};
    io.ApiVersion = EOS_INITIALIZE_API_LATEST;
    io.ProductName = "AntigravityCrossplayAdapter";
    io.ProductVersion = "1.0.0";
    if (EOS_Initialize(&io) != EOS_EResult::EOS_Success) {
        fprintf(stderr, "EOS_Initialize failed\n");
        return 3;
    }

    EOS_Logging_SetCallback(on_eos_log);
    EOS_Logging_SetLogLevel(EOS_ELogCategory::EOS_LC_ALL_CATEGORIES, EOS_ELogLevel::EOS_LOG_VeryVerbose);

    EOS_Platform_ClientCredentials cc = {};
    cc.ClientId = cid;
    cc.ClientSecret = secret;

    EOS_Platform_Options po = {};
    po.ApiVersion = EOS_PLATFORM_OPTIONS_API_LATEST;
    po.ProductId = product;
    po.SandboxId = sandbox;
    po.DeploymentId = deploy;
    po.ClientCredentials = cc;
    po.bIsServer = EOS_FALSE;
    po.TickBudgetInMilliseconds = 50;
    if (cache_dir && cache_dir[0]) {
        po.CacheDirectory = cache_dir;
    }

    g_platform = EOS_Platform_Create(&po);
    if (!g_platform) {
        fprintf(stderr, "EOS_Platform_Create failed\n");
        EOS_Shutdown();
        return 4;
    }
    EOS_Platform_Tick(g_platform);

    g_connect = EOS_Platform_GetConnectInterface(g_platform);
    EOS_Connect_CreateDeviceIdOptions o1 = {};
    o1.ApiVersion = EOS_CONNECT_CREATEDEVICEID_API_LATEST;
    o1.DeviceModel = "LinuxAdapter";
    EOS_Connect_CreateDeviceId(g_connect, &o1, nullptr, on_deviceid);

    for (int i = 0; i < 2000 && !g_dev_done; i++) {
        EOS_Platform_Tick(g_platform);
        usleep(10000);
    }
    if (!g_dev_done || (g_dev_res != EOS_EResult::EOS_Success &&
                        g_dev_res != EOS_EResult::EOS_DuplicateNotAllowed)) {
        fprintf(stderr, "deviceid failed: %s\n", EOS_EResult_ToString(g_dev_res));
        return 5;
    }

    connect_login();

    for (int i = 0; i < 2000 && !g_login_done; i++) {
        EOS_Platform_Tick(g_platform);
        usleep(10000);
    }
    if (!g_login_done || g_login_res != EOS_EResult::EOS_Success) {
        fprintf(stderr, "login failed: %s\n", EOS_EResult_ToString(g_login_res));
        return 6;
    }

    EOS_Connect_AddNotifyAuthExpirationOptions aeo = {};
    aeo.ApiVersion = EOS_CONNECT_ADDNOTIFYAUTHEXPIRATION_API_LATEST;
    EOS_Connect_AddNotifyAuthExpiration(g_connect, &aeo, nullptr, on_auth_expiration);

    printf("==== ADAPTER PUID: %s ====\n", g_puid);
    fflush(stdout);

    // Save PUID to file if requested
    if (puid_file && puid_file[0]) {
        FILE* fp = fopen(puid_file, "w");
        if (fp) {
            fprintf(fp, "%s\n", g_puid);
            fclose(fp);
            printf("[relay] Saved PUID to %s\n", puid_file);
        }
    }

    g_p2p = EOS_Platform_GetP2PInterface(g_platform);

    // RelayControl decides which ICE candidates we offer. Per the EOS SDK compatibility
    // table, AllowRelays is the only setting that connects against ANY remote setting,
    // so it is the default; override with DST_EOS_RELAY_CONTROL=NoRelays|AllowRelays|ForceRelays
    // if a host's NAT needs it. (ForceRelays vs a NoRelays peer is a guaranteed failure.)
    EOS_ERelayControl relay_control = EOS_ERelayControl::EOS_RC_AllowRelays;
    const char* rc_env = getenv("DST_EOS_RELAY_CONTROL");
    if (rc_env && !strcmp(rc_env, "NoRelays"))    relay_control = EOS_ERelayControl::EOS_RC_NoRelays;
    if (rc_env && !strcmp(rc_env, "ForceRelays")) relay_control = EOS_ERelayControl::EOS_RC_ForceRelays;
    EOS_P2P_SetRelayControlOptions rco = {};
    rco.ApiVersion = EOS_P2P_SETRELAYCONTROL_API_LATEST;
    rco.RelayControl = relay_control;
    EOS_EResult rr = EOS_P2P_SetRelayControl(g_p2p, &rco);
    printf("[relay] SetRelayControl(%s) -> %s\n", rc_env ? rc_env : "AllowRelays", EOS_EResult_ToString(rr));

    EOS_P2P_SetPacketQueueSizeOptions pqs = {};
    pqs.ApiVersion = EOS_P2P_SETPACKETQUEUESIZE_API_LATEST;
    pqs.IncomingPacketQueueMaxSizeBytes = 16 * 1024 * 1024;
    pqs.OutgoingPacketQueueMaxSizeBytes = 16 * 1024 * 1024;
    EOS_P2P_SetPacketQueueSize(g_p2p, &pqs);

    EOS_P2P_SetPortRangeOptions pr = {};
    pr.ApiVersion = EOS_P2P_SETPORTRANGE_API_LATEST;
    pr.Port = 9000;
    pr.MaxAdditionalPortsToTry = 10;
    printf("[relay] SetPortRange -> %s\n", EOS_EResult_ToString(EOS_P2P_SetPortRange(g_p2p, &pr)));

    EOS_P2P_QueryNATTypeOptions qn = {};
    qn.ApiVersion = EOS_P2P_QUERYNATTYPE_API_LATEST;
    EOS_P2P_QueryNATType(g_p2p, &qn, nullptr, on_nat);
    for (int i = 0; i < 500 && !g_nat_done; i++) {
        EOS_Platform_Tick(g_platform);
        usleep(10000);
    }

    EOS_P2P_AddNotifyPeerConnectionRequestOptions nr = {};
    nr.ApiVersion = EOS_P2P_ADDNOTIFYPEERCONNECTIONREQUEST_API_LATEST;
    nr.LocalUserId = g_local;
    EOS_NotificationId nid_req = EOS_P2P_AddNotifyPeerConnectionRequest(g_p2p, &nr, nullptr, on_conn_request);
    printf("[relay] AddNotifyPeerConnectionRequest -> %llu\n", (unsigned long long)nid_req);

    EOS_P2P_AddNotifyPeerConnectionEstablishedOptions ne = {};
    ne.ApiVersion = EOS_P2P_ADDNOTIFYPEERCONNECTIONESTABLISHED_API_LATEST;
    ne.LocalUserId = g_local;
    EOS_NotificationId nid_est = EOS_P2P_AddNotifyPeerConnectionEstablished(g_p2p, &ne, nullptr, on_established);
    printf("[relay] AddNotifyPeerConnectionEstablished -> %llu\n", (unsigned long long)nid_est);

    EOS_P2P_AddNotifyPeerConnectionInterruptedOptions ni = {};
    ni.ApiVersion = EOS_P2P_ADDNOTIFYPEERCONNECTIONINTERRUPTED_API_LATEST;
    ni.LocalUserId = g_local;
    EOS_NotificationId nid_int = EOS_P2P_AddNotifyPeerConnectionInterrupted(g_p2p, &ni, nullptr, on_interrupted);
    printf("[relay] AddNotifyPeerConnectionInterrupted -> %llu\n", (unsigned long long)nid_int);

    EOS_P2P_AddNotifyPeerConnectionClosedOptions nc = {};
    nc.ApiVersion = EOS_P2P_ADDNOTIFYPEERCONNECTIONCLOSED_API_LATEST;
    nc.LocalUserId = g_local;
    EOS_NotificationId nid_cls = EOS_P2P_AddNotifyPeerConnectionClosed(g_p2p, &nc, nullptr, on_closed);
    printf("[relay] AddNotifyPeerConnectionClosed -> %llu\n", (unsigned long long)nid_cls);

    printf("[relay] Listening on 'EOSSocket', bridging to UDP 127.0.0.1:%d (seconds: %s)\n",
           g_udp_port, seconds > 0 ? std::to_string(seconds).c_str() : "infinite");
    fflush(stdout);

    unsigned char buf[65536];
    time_t start_time = time(NULL);
    time_t last_stat = start_time;

    while (g_running && (seconds <= 0 || (time(NULL) - start_time < seconds))) {
        EOS_Platform_Tick(g_platform);
        refresh_step();

        // --- Step A: EOS -> UDP ---
        for (;;) {
            EOS_P2P_GetNextReceivedPacketSizeOptions gp = {};
            gp.ApiVersion = EOS_P2P_GETNEXTRECEIVEDPACKETSIZE_API_LATEST;
            gp.LocalUserId = g_local;
            uint32_t sz = 0;
            EOS_EResult res = EOS_P2P_GetNextReceivedPacketSize(g_p2p, &gp, &sz);
            if (res == EOS_EResult::EOS_InvalidAuth) {
                // The token ran out without a warning: refresh, and only restart if that keeps happening.
                if (g_refresh == REFRESH_IDLE) {
                    if (++g_invalid_auth > INVALID_AUTH_MAX) {
                        printf("[relay] EOS_InvalidAuth again after %d refreshes, exiting for a supervised restart\n",
                               INVALID_AUTH_MAX);
                        fflush(stdout);
                        exit(1);
                    }
                    printf("[relay] EOS_InvalidAuth, refreshing the login\n");
                    fflush(stdout);
                    g_refresh = REFRESH_WANTED;
                }
                break;
            }
            if (res != EOS_EResult::EOS_Success || sz == 0) {
                break;
            }
            if (sz > sizeof(buf)) sz = sizeof(buf);

            EOS_P2P_ReceivePacketOptions rp = {};
            rp.ApiVersion = EOS_P2P_RECEIVEPACKET_API_LATEST;
            rp.LocalUserId = g_local;
            rp.MaxDataSizeBytes = sizeof(buf);

            EOS_ProductUserId peer = nullptr;
            EOS_P2P_SocketId sid = {};
            uint8_t ch = 0;
            uint32_t written = 0;

            if (EOS_P2P_ReceivePacket(g_p2p, &rp, &peer, &sid, &ch, buf, &written) != EOS_EResult::EOS_Success) {
                break;
            }

            Peer* p = peer ? peer_for(peer) : nullptr;
            if (!p || p->fd < 0) continue;

            p->channel = ch;
            if (send(p->fd, (const char*)buf, written, 0) < 0) {
                perror("send to bridge UDP");
            }
            if (p->from_peer++ < 5 || p->from_peer % 500 == 0) {
                printf("[relay] Mobile %s (ch=%u) -> Bridge (len=%u, id=0x%02x)\n",
                       p->name, ch, written, buf[0]);
                fflush(stdout);
            }
        }

        // --- Step B: UDP -> EOS ---
        for (int i = 0; i < g_npeers; i++) {
            Peer* p = &g_peers[i];
            if (!p->active || p->fd < 0) continue;

            for (;;) {
                int n = (int)recv(p->fd, (char*)buf, sizeof(buf), 0);
                if (n <= 0) break;

                send_to_peer(p, buf, n);
                if (p->to_peer <= 5 || p->to_peer % 500 == 0) {
                    printf("[relay] Bridge -> Mobile %s (len=%d, id=0x%02x)\n",
                           p->name, n, buf[0]);
                    fflush(stdout);
                }
            }
        }

        // Stats logging every 60 seconds
        time_t now = time(NULL);
        if (now - last_stat >= 60) {
            last_stat = now;
            for (int i = 0; i < g_npeers; i++) {
                if (g_peers[i].active) {
                    printf("[relay] Peer %s status: %llu pkts in, %llu pkts out\n",
                           g_peers[i].name, g_peers[i].from_peer, g_peers[i].to_peer);
                    fflush(stdout);
                }
            }
        }

        usleep(2000); // 2ms tick interval = 500 Hz
    }

    printf("[relay] Shutting down gracefully...\n");
    for (int i = 0; i < g_npeers; i++) {
        if (g_peers[i].fd >= 0) close_socket(g_peers[i].fd);
    }

    EOS_Platform_Release(g_platform);
    EOS_Shutdown();
    printf("[relay] Done.\n");
    return 0;
}
