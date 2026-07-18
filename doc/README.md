# CARP for Linux

**Common Address Redundancy Protocol (CARP) - Linux Kernel Port**

Ported from FreeBSD 14.4-RELEASE (ip_carp.c) to Linux 6.12 (Debian 13.6).

## Overview

CARP allows multiple hosts on the same local network to share a set of
IPv4 and/or IPv6 addresses. Its primary purpose is to ensure that these
addresses are always available, providing host-level redundancy.

This is a **full kernel-level implementation** of CARP for Linux, maintaining
**wire-level compatibility** with FreeBSD and OpenBSD CARP implementations.

## Module Architecture

```
┌─────────────────────────────────────────────────────┐
│                    内核模块 (kmod/)                   │
│                                                       │
│  carp_netdev.c  ─ 网络栈集成                          │
│  ├─ 协议 112 注册 (IPv4 + IPv6)                      │
│  ├─ NF hook (源 MAC 替换)                             │
│  └─ 设备事件通知 (netdev notifier)                    │
│                                                       │
│  carp_input.c   ─ 收包处理                            │
│  ├─ HMAC-SHA1 认证                                    │
│  ├─ 状态机 (INIT→BACKUP→MASTER)                      │
│  └─ 环路检测                                          │
│                                                       │
│  carp_output.c  ─ 发包处理                            │
│  ├─ 广告构建 + 发送                                   │
│  ├─ 降级管理                                          │
│  └─ 源地址选择                                        │
│                                                       │
│  carp_netlink.c ─ 用户态接口                          │
│  ├─ Generic Netlink (配置)                            │
│  ├─ 多播组管理                                        │
│  └─ ARP/NDP/桥接 hook (EXPORT_SYMBOL)                │
│                                                       │
│  carp_main.c    ─ 模块生命周期                        │
│  ├─ 状态机 (set_state, sc_state)                     │
│  ├─ 接口生命周期 (alloc/destroy)                      │
│  ├─ 地址管理 (attach/detach)                          │
│  └─ /proc 接口                                       │
│                                                       │
│  路由/IP管理: 委托给用户态 (carpd daemon)             │
│  内核 → uevent → carpd → ip addr add/del              │
└─────────────────────────────────────────────────────┘
```

## Features

```
carp_linux/
├── kmod/              Kernel module sources
│   ├── carp_internal.h   Internal header (structs, macros, declarations)
│   ├── carp_main.c       Module init/exit, state machine, lifecycle
│   ├── carp_input.c      Packet reception, HMAC-SHA1, loop detection
│   ├── carp_output.c     Advertisement sending, source address selection
│   ├── carp_netlink.c    Netlink interface, multicast, ARP/NDP/bridge hooks
│   ├── carp_netdev.c     Network stack integration: NF hook, protocol 112, device events
│   └── Makefile          Kbuild Makefile
├── tools/             Userspace management
│   ├── carpd.h         Public header (includes include/carp.h)
│   ├── carpd.c         Main entry point (CLI parsing)
│   ├── carpd_netlink.c Netlink communication + VIP query
│   ├── carpd_cmd.c     CLI commands (add/del/set/status)
│   ├── carpd_daemon.c  Daemon mode (uevent + address mgmt)
│   └── Makefile
├── include/           Shared headers
│   └── carp.h            UAPI header (kernel ↔ userspace)
├── tests/             Test scripts
│   ├── carp_basic.sh     Integration test (ip netns)
│   └── Makefile
├── doc/
│   ├── README.md         This file
│   └── PORTABILITY.md    Portability analysis (FreeBSD ↔ Linux)
├── DKMS/
│   └── dkms.conf         DKMS configuration
├── .github/workflows/
│   └── build.yml         CI build pipeline
├── .github/workflows/
│   └── build.yml         CI build pipeline
└── Makefile               Top-level build
```

## Building

### Kernel Module

```bash
cd kmod
make
sudo insmod carp.ko
```

### Userspace Tool

```bash
cd tools
make
sudo make install
```

## Usage

### Loading the Module

```bash
# Load with default settings
sudo modprobe carp

# Load with custom settings
sudo insmod carp.ko carp_allow=1 carp_preempt=0 carp_dscp=56

# Module parameters:
#   carp_allow        - Accept incoming CARP packets (0/1, default: 1)
#   carp_preempt      - Preempt slower masters (0/1, default: 0)
#   carp_log          - Log level (0/1/2, default: 1)
#   carp_dscp         - DSCP for outgoing packets (0-63, default: 56)
#   carp_senderr_adj  - Send error demotion factor (default: 240)
#   carp_ifdown_adj   - Interface down demotion factor (default: 240)
```

### Using carpd

```bash
# Add a CARP VHID
sudo carpd add eth0 1

# Add with options
sudo carpd add eth0 1 --advbase 1 --advskew 0 --password mysecret

# Set state
sudo carpd set eth0 1 --state MASTER

# Check status
sudo carpd status
sudo carpd status eth0
sudo carpd status eth0 1

# Delete
sudo carpd del eth0 1

# Start daemon (monitors state changes, manages addresses)
sudo carpd daemon
```

### Monitoring

```bash
# View statistics
cat /proc/net/carp/stats

# View interfaces
cat /proc/net/carp/interfaces

# The carpd daemon automatically manages virtual IP addresses
# when CARP state changes (MASTER → add VIP, BACKUP/INIT → remove VIP)
sudo carpd daemon
```

## Features

### Perfectly Ported (Same Behavior as FreeBSD)
- CARP state machine (INIT → BACKUP → MASTER)
- HMAC-SHA1 authentication (kernel crypto API)
- Advertisement interval (advbase + advskew)
- Master-down detection (3× advbase timeout)
- Send error demotion (3 failures → demote, 3 successes → undemote)
- Interface down demotion
- Virtual MAC (00:00:5e:00:01:XX)
- Source MAC replacement on outgoing traffic (IPv4 + IPv6 NF hooks)
- Loop detection (VHID=0 self-packet detection)
- Route management delegated to userspace (carpd daemon) via uevent notification
- Gratuitous ARP/NA on MASTER transition
- Multicast group management (224.0.0.18 / ff02::12)
- ARP/NDP address matching hooks (EXPORT_SYMBOL)
- Bridge MAC matching (carp_forus)
- Netlink configuration interface + /proc/net/carp/ stats

### Ported With Different API (Same Behavior)
- Protocol 112 registration → inet_add_protocol (kernel handler)
- FreeBSD ioctl → Generic Netlink
- VNET → global list + RCU
- callout → timer_list
- taskqueue → workqueue (schedule_work)
- mbuf → sk_buff
- NET_EPOCH → RCU
- ifpromisc → dev_set_promiscuity
- ifa_ref → in_dev_hold
- timeval → timespec64 (timespec64_to_jiffies, timespec64_compare)
- if_output hook → NF_INET(6)_POST_ROUTING hook

## Compatibility

### Wire Compatibility

100% wire-compatible with FreeBSD/OpenBSD CARP:
- IP protocol 112
- Multicast: 224.0.0.18 (IPv4), ff02::12 (IPv6)
- CARP header: 36 bytes, identical layout
- Virtual MAC: 00:00:5e:00:01:XX
- HMAC-SHA1 authentication

### Cross-Platform Testing

```bash
# Linux side
sudo modprobe carp
sudo carpd add eth0 1 --advbase 1 --password sharedkey

# FreeBSD side
ifconfig eth0 vhid 1 advbase 1 pass sharedkey 192.168.1.100/24
```

## Source Files

### Kernel Module (`kmod/`)

| File | Lines | Purpose |
|------|-------|---------|
| `carp_internal.h` | 171 | Internal header: structs, macros, declarations |
| `carp_main.c` | 633 | Module init/exit, state machine, lifecycle |
| `carp_input.c` | 393 | HMAC-SHA1, packet reception, loop detection |
| `carp_output.c` | 484 | Advertisement sending, demotion, source address selection |
| `carp_netlink.c` | 388 | Netlink interface, multicast, ARP/NDP/bridge hooks |
| `carp_netdev.c` | 189 | Network stack integration: NF hook, protocol 112, device events |

### Userspace Tool (`tools/`)

| File | Lines | Purpose |
|------|-------|---------|
| `carpd.h` | 66 | Public header (includes include/carp.h) |
| `carpd.c` | 166 | Main entry point (CLI parsing, command dispatch) |
| `carpd_netlink.c` | 158 | Netlink communication + VIP query |
| `carpd_cmd.c` | 234 | CLI commands (add/del/set/status) |
| `carpd_daemon.c` | 144 | Daemon mode (uevent monitoring + address management) |

### Shared Header (`include/`)

| File | Lines | Purpose |
|------|-------|---------|
| `carp.h` | 93 | UAPI header: CARP protocol definitions (kernel ↔ userspace) |

## License

BSD-2-Clause (matching original FreeBSD CARP license)
