# CARP Linux Port

FreeBSD CARP (Common Address Redundancy Protocol) ported to Linux kernel module.

## Source Mapping (FreeBSD → Linux)

| FreeBSD file | Linux file | Changes |
|---|---|---|
| `sys/netinet/ip_carp.h` | `carp.h` | FreeBSD types → Linux types; `BYTE_ORDER` → `__LITTLE_ENDIAN_BITFIELD`; add `_Static_assert` |
| `sys/netinet/ip_carp.c` | `carp_main.c` | `mbuf` → `sk_buff`; `callout` → `timer_list`; `mtx/sx` → `spinlock`; `ifnet` → `net_device`; `VNET sysctl` → `module_param`; packet injection via `dev_queue_xmit` |
| `sys/netinet/ip_carp.c` (HMAC) | `carp_hmac.c` | FreeBSD `SHA1_CTX` → Linux `crypto_shash` API; same HMAC-SHA1 algorithm |
| `sbin/ifconfig/carp.c` | `carp_config.c` | Standalone userspace tool; uses same `SIOCSVH`/`SIOCGVH` ioctls |

## Architecture

The core CARP state machine (INIT → BACKUP → MASTER) is preserved exactly from FreeBSD:

1. **Advertisement timer** (`sc_ad_tmo`): MASTER sends periodic CARP advertisements
2. **Master down timer** (`sc_md_tmo`): BACKUP promotes to MASTER if no advertisement received within 3× advbase
3. **State transitions**: same logic as FreeBSD `carp_input_c` — including preempt and timeout detection

The CARP packet format (36-byte header with HMAC-SHA1) is identical on wire, ensuring interoperability with FreeBSD/OpenBSD CARP peers.

## Build

### Kernel module

Requires kernel headers installed:

```bash
# Install kernel headers (Debian/Ubuntu)
apt install linux-headers-$(uname -r)

# Install kernel headers (RHEL/CentOS)
yum install kernel-devel

# Build
make module
```

### Userspace tool

```bash
make userspace
# or just:
gcc -Wall -o carp_config carp_config.c
```

## Usage

### 1. Load the module

```bash
sudo insmod carp.ko
```

Module parameters:
- `carp_allow=1` — accept incoming CARP packets (default: 1)
- `carp_preempt=0` — enable preemption of slower masters (default: 0)
- `carp_log=1` — log level: 0=off, 1=info, 2=debug

### 2. Configure CARP on an interface

```bash
# On host A (MASTER, higher priority via lower advskew):
sudo ./carp_config -v 1 -b 1 -s 0 -k mysecret eth0

# On host B (BACKUP, lower priority):
sudo ./carp_config -v 1 -b 1 -s 100 -k mysecret eth0
```

### 3. Check status

```bash
sudo ./carp_config -g -v 1 eth0
```

### 4. Force state

```bash
sudo ./carp_config -v 1 -S MASTER eth0
```

## Key Differences from FreeBSD

| Feature | FreeBSD | This Linux Port |
|---|---|---|
| IPv6 support | Yes | Partial (header defined, input not registered) |
| Sysctl | Full sysctl tree | Module parameters only |
| Interface attachment | `ifconfig` integration | Standalone tool + IOCTL |
| Multicast join | Kernel `in_joingroup` | Relies on packet_type registration |
| Promiscuous mode | Automatic `ifpromisc` | Not implemented |
| Route management | `ifa_add_loopback_route` | Not implemented |
| Virtual net_device | No (uses parent ifnet) | Not needed (packet_type on parent) |

## License

BSD 2-Clause (same as FreeBSD CARP)
