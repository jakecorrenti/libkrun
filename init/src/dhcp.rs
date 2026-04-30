/// DHCP client for configuring an IPv4 network interface.
///
/// Ported from `init/dhcp.c`. Sends a DHCPDISCOVER with Rapid Commit,
/// handles a direct DHCPACK or falls back to the full OFFER→REQUEST→ACK
/// 4-way handshake, then configures the IP address, default route, DNS
/// servers, and MTU via netlink.
use anyhow::{Context, Result, bail};
use std::mem::{self, MaybeUninit};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use rustix::net::netdevice;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::sockopt::{self, Timeout};
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketAddrV4, SocketType,
    ipproto, sendto, recvfrom,
};
use rustix::process::getpid;

// ── DHCP constants ────────────────────────────────────────────────────────────

const DHCP_BUFFER_SIZE: usize = 576;
const DHCP_OPTIONS_SIZE: usize = 60;
const DHCP_MSG_OFFER: u8 = 2;
const DHCP_MSG_ACK: u8 = 5;
const BOOTREQUEST: u8 = 1;
const MAGIC_COOKIE: u32 = 0x6382_5363;
/// Byte offset of the `yiaddr` field in a DHCP packet (RFC 2131 §2).
const DHCP_YIADDR_OFFSET: usize = 16;

// ── DHCP packet (RFC 2131) ────────────────────────────────────────────────────

#[repr(C, packed)]
struct DhcpPacket {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: u32,
    yiaddr: u32,
    siaddr: u32,
    giaddr: u32,
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    magic: u32,
    options: [u8; DHCP_OPTIONS_SIZE],
}

impl DhcpPacket {
    fn new_zeroed() -> Self {
        // SAFETY: DhcpPacket is #[repr(C, packed)] with all fields being
        // plain integer types; a zero bit-pattern is valid for all of them.
        unsafe { MaybeUninit::<Self>::zeroed().assume_init() }
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: packed repr, all fields are plain integer types; no padding.
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!(*self).cast::<u8>(),
                mem::size_of::<Self>(),
            )
        }
    }
}

// ── Netlink structs not exposed by libc ──────────────────────────────────────
// `libc` exposes `nlmsghdr`, `nlmsgerr`, and `ifinfomsg`, but not
// `ifaddrmsg`, `rtmsg`, or `rtattr`.  Define them here from the kernel ABI.

#[repr(C)]
struct Ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[repr(C)]
struct Rtmsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[repr(C)]
struct Rtattr {
    rta_len: u16,
    rta_type: u16,
}

// ── Netlink macro equivalents ─────────────────────────────────────────────────
// NLMSG_ALIGNTO = 4
// NLMSG_ALIGN(len) = (len + 3) & !3
// NLMSG_HDRLEN = NLMSG_ALIGN(size_of::<nlmsghdr>())
// NLMSG_LENGTH(len) = len + NLMSG_HDRLEN
// RTA_ALIGNTO = 4
// RTA_ALIGN(len) = (len + 3) & !3
// RTA_LENGTH(len) = RTA_ALIGN(size_of::<rtattr>()) + len
// RTA_SPACE(len)  = RTA_ALIGN(RTA_LENGTH(len))

const fn align4(len: usize) -> usize {
    (len + 3) & !3
}
const NLMSG_HDRLEN: usize = align4(mem::size_of::<libc::nlmsghdr>());
const fn nlmsg_length(payload: usize) -> usize {
    payload + NLMSG_HDRLEN
}
const RTA_HDR: usize = align4(mem::size_of::<Rtattr>());
const fn rta_length(data_len: usize) -> usize {
    RTA_HDR + data_len
}
const fn rta_space(data_len: usize) -> usize {
    align4(rta_length(data_len))
}

// ── Netlink helpers ───────────────────────────────────────────────────────────

/// Appends an rtattr to the netlink message in `buf` and updates `nlmsg_len`.
fn add_rtattr(buf: &mut [u8], attr_type: u16, data: &[u8]) {
    let nlh = buf.as_mut_ptr() as *mut libc::nlmsghdr;
    let cur_len = unsafe { (*nlh).nlmsg_len } as usize;
    let aligned = align4(cur_len);
    let needed = aligned + rta_space(data.len());
    assert!(
        needed <= buf.len(),
        "add_rtattr: buffer too small (need {needed}, have {})",
        buf.len()
    );

    // SAFETY: bounds checked above; buf is aligned for nlmsghdr/Rtattr.
    unsafe {
        let rta = buf.as_mut_ptr().add(aligned) as *mut Rtattr;
        (*rta).rta_type = attr_type;
        (*rta).rta_len = rta_length(data.len()) as u16;
        std::ptr::copy_nonoverlapping(data.as_ptr(), (rta as *mut u8).add(RTA_HDR), data.len());
        (*nlh).nlmsg_len = needed as u32;
    }
}

/// Returns the `nlmsg_len` field from the header at the start of `buf`.
fn nlmsg_len(buf: &[u8]) -> usize {
    // SAFETY: buf is always a 4096-byte zeroed stack array initialised with a
    // valid nlmsghdr before this is called; NLMSG_HDRLEN fits within it.
    unsafe { (*(buf.as_ptr() as *const libc::nlmsghdr)).nlmsg_len as usize }
}

/// Sends a netlink message and waits for the kernel ACK.
fn nl_transaction(nl_sock: &rustix::fd::OwnedFd, buf: &mut [u8], msg_len: usize) -> Result<()> {
    let kernel_addr = SocketAddrNetlink::new(0, 0);
    sendto(nl_sock, &buf[..msg_len], SendFlags::empty(), &kernel_addr)
        .context("netlink sendto")?;

    let (recv_len, _, _) = recvfrom(nl_sock, &mut *buf, RecvFlags::empty())
        .context("netlink recvfrom")?;

    let min = nlmsg_length(mem::size_of::<libc::nlmsgerr>());
    if recv_len < min {
        bail!("netlink response too short");
    }
    let nlh = buf.as_ptr() as *const libc::nlmsghdr;
    if unsafe { (*nlh).nlmsg_type } != libc::NLMSG_ERROR as u16 {
        bail!("netlink: expected NLMSG_ERROR");
    }
    // SAFETY: bounds checked above; NLMSG_HDRLEN is the correct offset.
    let err_ptr = unsafe { buf.as_ptr().add(NLMSG_HDRLEN) } as *const libc::nlmsgerr;
    let code = unsafe { (*err_ptr).error };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(-code)).context("netlink kernel error");
    }
    Ok(())
}

// ── Netlink configuration helpers ─────────────────────────────────────────────

fn set_mtu(nl_sock: &rustix::fd::OwnedFd, iface_index: i32, mtu: u32) -> Result<()> {
    let mut buf = [0u8; 4096];
    let payload = mem::size_of::<libc::ifinfomsg>();

    // SAFETY: buf is zeroed and large enough; all pointers stay within it.
    unsafe {
        let nlh = buf.as_mut_ptr() as *mut libc::nlmsghdr;
        (*nlh).nlmsg_len = nlmsg_length(payload) as u32;
        (*nlh).nlmsg_type = libc::RTM_NEWLINK;
        (*nlh).nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
        (*nlh).nlmsg_seq = 1;
        (*nlh).nlmsg_pid = getpid().as_raw_nonzero().get() as u32;

        let ifi = buf.as_mut_ptr().add(NLMSG_HDRLEN) as *mut libc::ifinfomsg;
        (*ifi).ifi_family = libc::AF_UNSPEC as u8;
        (*ifi).ifi_type = libc::ARPHRD_ETHER;
        (*ifi).ifi_index = iface_index;
    }

    add_rtattr(&mut buf, libc::IFLA_MTU, &mtu.to_ne_bytes());
    let msg_len = nlmsg_len(&buf);
    nl_transaction(nl_sock, &mut buf, msg_len).context("set_mtu")
}

fn mod_addr4(
    nl_sock: &rustix::fd::OwnedFd,
    iface_index: i32,
    cmd: u16,
    addr: u32, // address in host byte order
    prefix_len: u8,
) -> Result<()> {
    let mut buf = [0u8; 4096];
    let payload = mem::size_of::<Ifaddrmsg>();

    // SAFETY: buf is zeroed and large enough; all pointers stay within it.
    unsafe {
        let nlh = buf.as_mut_ptr() as *mut libc::nlmsghdr;
        (*nlh).nlmsg_len = nlmsg_length(payload) as u32;
        (*nlh).nlmsg_type = cmd;
        (*nlh).nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16;
        (*nlh).nlmsg_seq = 1;
        (*nlh).nlmsg_pid = getpid().as_raw_nonzero().get() as u32;

        let ifa = buf.as_mut_ptr().add(NLMSG_HDRLEN) as *mut Ifaddrmsg;
        (*ifa).ifa_family = libc::AF_INET as u8;
        (*ifa).ifa_prefixlen = prefix_len;
        (*ifa).ifa_scope = libc::RT_SCOPE_UNIVERSE;
        (*ifa).ifa_index = iface_index as u32;
    }

    let addr_bytes = addr.to_be_bytes();
    add_rtattr(&mut buf, libc::IFA_LOCAL, &addr_bytes);
    add_rtattr(&mut buf, libc::IFA_ADDRESS, &addr_bytes);
    let msg_len = nlmsg_len(&buf);
    nl_transaction(nl_sock, &mut buf, msg_len).context("mod_addr4")
}

fn mod_route4(
    nl_sock: &rustix::fd::OwnedFd,
    iface_index: i32,
    cmd: u16,
    gw: u32, // gateway in host byte order
) -> Result<()> {
    let mut buf = [0u8; 4096];
    let payload = mem::size_of::<Rtmsg>();

    // SAFETY: buf is zeroed and large enough; all pointers stay within it.
    unsafe {
        let nlh = buf.as_mut_ptr() as *mut libc::nlmsghdr;
        (*nlh).nlmsg_len = nlmsg_length(payload) as u32;
        (*nlh).nlmsg_type = cmd;
        (*nlh).nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_CREATE | libc::NLM_F_ACK) as u16;
        (*nlh).nlmsg_seq = 1;
        (*nlh).nlmsg_pid = getpid().as_raw_nonzero().get() as u32;

        let rtm = buf.as_mut_ptr().add(NLMSG_HDRLEN) as *mut Rtmsg;
        (*rtm).rtm_family = libc::AF_INET as u8;
        (*rtm).rtm_table = libc::RT_TABLE_MAIN;
        (*rtm).rtm_protocol = libc::RTPROT_BOOT;
        (*rtm).rtm_scope = libc::RT_SCOPE_UNIVERSE;
        (*rtm).rtm_type = libc::RTN_UNICAST;
    }

    let dst_bytes = [0u8; 4]; // 0.0.0.0 — default route
    let gw_bytes = gw.to_be_bytes();
    let idx_bytes = iface_index.to_ne_bytes();
    add_rtattr(&mut buf, libc::RTA_OIF, &idx_bytes);
    add_rtattr(&mut buf, libc::RTA_DST, &dst_bytes);
    add_rtattr(&mut buf, libc::RTA_GATEWAY, &gw_bytes);
    let msg_len = nlmsg_len(&buf);
    nl_transaction(nl_sock, &mut buf, msg_len).context("mod_route4")
}

// ── DHCP option building ──────────────────────────────────────────────────────

/// Writes TLV-encoded DHCP options into a fixed-size byte buffer.
struct OptionsWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> OptionsWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Appends a type-length-value option.
    fn write(&mut self, code: u8, data: &[u8]) {
        let end = self.pos + 2 + data.len();
        assert!(end <= self.buf.len(), "OptionsWriter: buffer overflow");
        self.buf[self.pos] = code;
        self.buf[self.pos + 1] = data.len() as u8;
        self.buf[self.pos + 2..end].copy_from_slice(data);
        self.pos = end;
    }

    /// Appends a zero-length option (e.g. Rapid Commit, option 80).
    fn write_flag(&mut self, code: u8) {
        assert!(self.pos + 1 < self.buf.len(), "OptionsWriter: buffer overflow");
        self.buf[self.pos] = code;
        self.buf[self.pos + 1] = 0;
        self.pos += 2;
    }

    /// Appends the end-of-options sentinel (0xff).
    fn end(&mut self) {
        assert!(self.pos < self.buf.len(), "OptionsWriter: buffer overflow");
        self.buf[self.pos] = 0xff;
        self.pos += 1;
    }
}

// ── DHCP option parsing ───────────────────────────────────────────────────────

/// Iterator over the TLV options in a DHCP packet, starting after the
/// magic cookie (offset 240). Yields `(code, data)` pairs, skipping padding
/// bytes (code 0) and stopping at the end sentinel (code 255).
struct DhcpOptions<'a> {
    pkt: &'a [u8],
    pos: usize,
}

impl<'a> DhcpOptions<'a> {
    fn new(pkt: &'a [u8]) -> Self {
        Self { pkt, pos: 240 }
    }
}

impl<'a> Iterator for DhcpOptions<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos >= self.pkt.len() {
                return None;
            }
            let code = self.pkt[self.pos];
            match code {
                0xff => return None,
                0x00 => {
                    self.pos += 1;
                    continue;
                }
                _ => {}
            }
            let len_pos = self.pos + 1;
            if len_pos >= self.pkt.len() {
                return None;
            }
            let opt_len = self.pkt[len_pos] as usize;
            let data_start = self.pos + 2;
            let data_end = data_start + opt_len;
            if data_end > self.pkt.len() {
                return None;
            }
            self.pos = data_end;
            return Some((code, &self.pkt[data_start..data_end]));
        }
    }
}

fn dhcp_msg_type(pkt: &[u8]) -> Option<u8> {
    DhcpOptions::new(pkt)
        .find(|&(code, data)| code == 53 && !data.is_empty())
        .map(|(_, data)| data[0])
}

/// Parses a DHCPACK, writes DNS to `/etc/resolv.conf`, and applies the
/// IP address, default route, and MTU via netlink.
fn handle_dhcp_ack(nl_sock: &rustix::fd::OwnedFd, iface_index: i32, pkt: &[u8]) -> Result<()> {
    if pkt.len() < 241 {
        bail!("DHCPACK too short ({} bytes)", pkt.len());
    }

    // Read yiaddr from the wire (network byte order) and convert to host order.
    let yiaddr = u32::from_be_bytes(
        pkt[DHCP_YIADDR_OFFSET..DHCP_YIADDR_OFFSET + 4]
            .try_into()
            .expect("slice is exactly 4 bytes"),
    );
    if yiaddr == 0 {
        bail!("DHCPACK: yiaddr is 0.0.0.0");
    }

    // u32::from_be_bytes converts network byte order to host order, so these
    // hold host-order values (equivalent to ntohl in C).
    let mut netmask: u32 = 0;
    let mut router: u32 = 0;
    let mut mtu: u16 = 65520;
    let mut dns_lines = String::new();

    for (code, data) in DhcpOptions::new(pkt) {
        match (code, data.len()) {
            (1, n) if n >= 4 => {
                netmask = u32::from_be_bytes(data[..4].try_into().expect("slice is exactly 4 bytes"));
            }
            (3, n) if n >= 4 => {
                router = u32::from_be_bytes(data[..4].try_into().expect("slice is exactly 4 bytes"));
            }
            (6, n) if n >= 4 => {
                for chunk in data.chunks_exact(4) {
                    let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                    dns_lines.push_str(&format!("nameserver {ip}\n"));
                }
            }
            (26, n) if n >= 2 => {
                let v = u16::from_be_bytes(data[..2].try_into().expect("slice is exactly 2 bytes"));
                mtu = v.clamp(1280, 65520);
            }
            _ => {}
        }
    }

    if !dns_lines.is_empty()
        && let Err(e) = std::fs::write("/etc/resolv.conf", dns_lines.as_bytes())
    {
        eprintln!("Failed to write /etc/resolv.conf: {e}");
    }

    // netmask is in host order (from_be_bytes == ntohl); leading_ones() gives
    // the prefix length, matching count_leading_ones(ntohl(...)) in the C.
    let prefix_len = netmask.leading_ones() as u8;

    mod_addr4(
        nl_sock,
        iface_index,
        libc::RTM_NEWADDR,
        yiaddr,
        prefix_len,
    )?;
    mod_route4(nl_sock, iface_index, libc::RTM_NEWROUTE, router)?;
    set_mtu(nl_sock, iface_index, mtu.into())?;
    Ok(())
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Sends a DHCPDISCOVER with Rapid Commit, processes the response, and
/// configures the interface.  Returns `Ok(())` on success *or* when no
/// DHCP response arrives (the VM may be IPv6-only).
/// Mirrors `do_dhcp()` in `init/dhcp.c`.
pub fn do_dhcp(iface: &str) -> Result<()> {
    // Netlink socket for address / route / MTU configuration.
    // rustix maps None to protocol 0, which is NETLINK_ROUTE — the same
    // protocol the C code passes explicitly.
    let nl_sock = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, None)
        .context("creating netlink socket")?;

    let pid = getpid().as_raw_nonzero().get() as u32;
    rustix::net::bind(&nl_sock, &SocketAddrNetlink::new(pid, 0))
        .context("binding netlink socket")?;

    // UDP socket for DHCP discover / request / receive.
    let sock = rustix::net::socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        Some(ipproto::UDP),
    )
    .context("creating UDP socket")?;

    // Resolve the interface index using the UDP socket fd.
    let iface_index = netdevice::name_to_index(&sock, iface)
        .with_context(|| format!("failed to find index for network interface '{iface}'"))?
        as i32;

    sockopt::set_socket_broadcast(&sock, true).context("setting SO_BROADCAST")?;

    // SO_BINDTODEVICE has no typed rustix wrapper; use libc directly.
    let iface_cstr =
        std::ffi::CString::new(iface).expect("interface name must not contain null bytes");
    let iface_len = iface_cstr.as_bytes_with_nul().len();
    if unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_cstr.as_ptr() as *const libc::c_void,
            iface_len as libc::socklen_t,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("setting SO_BINDTODEVICE");
    }

    let bind_addr = SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 68);
    rustix::net::bind(&sock, &bind_addr).context("binding UDP socket to port 68")?;

    // Read MAC address via SIOCGIFHWADDR (no rustix equivalent).
    let mut mac_ifr: libc::ifreq = unsafe { mem::zeroed() };
    // SAFETY: ifr_name is [c_char; IFNAMSIZ]; we write at most IFNAMSIZ-1
    // bytes and the array was zeroed above, so the name is always null-terminated.
    {
        let name_bytes = iface.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        let name_dst = unsafe {
            std::slice::from_raw_parts_mut(mac_ifr.ifr_name.as_mut_ptr() as *mut u8, copy_len)
        };
        name_dst.copy_from_slice(&name_bytes[..copy_len]);
    }
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR as _, &mut mac_ifr) } < 0 {
        return Err(std::io::Error::last_os_error()).context("SIOCGIFHWADDR");
    }

    // Build DHCPDISCOVER.
    let mut request = DhcpPacket::new_zeroed();
    request.op = BOOTREQUEST;
    request.htype = 1;
    request.hlen = 6;
    request.xid = pid.to_be();
    request.flags = 0x8000u16.to_be();
    request.magic = MAGIC_COOKIE.to_be();
    // sa_data is [c_char; 14]; the first 6 bytes are the MAC address.
    // SAFETY: c_char and u8 have the same size and alignment; reinterpreting
    // the bit pattern of a MAC address byte is always valid.
    let mac_bytes: [u8; 6] = unsafe {
        *(mac_ifr.ifr_ifru.ifru_hwaddr.sa_data[..6].as_ptr() as *const [u8; 6])
    };
    request.chaddr[..6].copy_from_slice(&mac_bytes);
    // Option 53: DISCOVER (1) | Option 80: Rapid Commit | Option 255: End
    let mut opts = OptionsWriter::new(&mut request.options);
    opts.write(53, &[1]); // DHCP Message Type = DISCOVER
    opts.write_flag(80); // Rapid Commit
    opts.end();

    let dest_addr = SocketAddrV4::new(std::net::Ipv4Addr::BROADCAST, 67);

    sendto(&sock, request.as_bytes(), SendFlags::empty(), &dest_addr)
        .context("sending DHCPDISCOVER")?;

    // 100 ms receive timeout — keeps IPv6-only VMs fast.
    sockopt::set_socket_timeout(&sock, Timeout::Recv, Some(Duration::from_millis(100)))
        .context("setting SO_RCVTIMEO")?;

    let mut response = [0u8; DHCP_BUFFER_SIZE];
    // recvfrom with &mut [u8] returns (filled_len, pre_trunc_len, addr).
    let (recv_len, _, from_any) = match recvfrom(&sock, response.as_mut_slice(), RecvFlags::empty()) {
        Err(rustix::io::Errno::AGAIN) | Err(rustix::io::Errno::TIMEDOUT) => {
            // No response — not an error; VM may be IPv6-only.
            return Ok(());
        }
        Err(e) => return Err(e).context("recvfrom DHCP response"),
        Ok(t) => t,
    };
    if recv_len == 0 {
        return Ok(());
    }

    // Extract sender IPv4 address for the 4-way handshake path.
    let from_addr_v4: Option<SocketAddrV4> = from_any
        .and_then(|a| SocketAddrV4::try_from(a).ok());

    match dhcp_msg_type(&response[..recv_len]) {
        Some(DHCP_MSG_ACK) => {
            handle_dhcp_ack(&nl_sock, iface_index, &response[..recv_len])?;
        }
        Some(DHCP_MSG_OFFER) => {
            // 4-way handshake: send DHCPREQUEST then wait for DHCPACK.
            // Read offered IP from wire (network byte order) into host order.
            let offered_addr = u32::from_be_bytes(
                response[DHCP_YIADDR_OFFSET..DHCP_YIADDR_OFFSET + 4]
                    .try_into()
                    .expect("slice is exactly 4 bytes"),
            );
            // Server ID option value: 4 bytes of the server's IPv4 address.
            let server_id_bytes: [u8; 4] = from_addr_v4
                .map(|a| a.ip().octets())
                .unwrap_or([0u8; 4]);

            request.options = [0u8; DHCP_OPTIONS_SIZE];
            let mut opts = OptionsWriter::new(&mut request.options);
            opts.write(53, &[3]); // DHCP Message Type = REQUEST
            opts.write(50, &offered_addr.to_be_bytes()); // Requested IP
            opts.write(54, &server_id_bytes); // Server Identifier
            opts.end();

            sendto(&sock, request.as_bytes(), SendFlags::empty(), &dest_addr)
                .context("sending DHCPREQUEST")?;

            let mut ack_buf = [0u8; DHCP_BUFFER_SIZE];
            let (ack_filled, _, _) =
                recvfrom(&sock, ack_buf.as_mut_slice(), RecvFlags::empty())
                    .context("no DHCPACK received")?;
            if ack_filled == 0 {
                bail!("no DHCPACK received");
            }

            let msg_type = dhcp_msg_type(&ack_buf[..ack_filled]);
            if msg_type != Some(DHCP_MSG_ACK) {
                bail!("expected DHCPACK but got message type {msg_type:?}");
            }

            handle_dhcp_ack(&nl_sock, iface_index, &ack_buf[..ack_filled])?;
        }
        None => bail!("DHCP response has no message type (option 53 missing)"),
        Some(t) => bail!("unexpected DHCP message type {t}"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── align4 / nlmsg_length / rta_space ─────────────────────────────────────

    #[test]
    fn align4_already_aligned() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(8), 8);
    }

    #[test]
    fn align4_rounds_up() {
        assert_eq!(align4(1), 4);
        assert_eq!(align4(2), 4);
        assert_eq!(align4(3), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(7), 8);
    }

    #[test]
    fn nlmsg_length_adds_header() {
        // NLMSG_HDRLEN is align4(size_of::<nlmsghdr>()) = 16 on all platforms.
        assert_eq!(nlmsg_length(0), NLMSG_HDRLEN);
        assert_eq!(nlmsg_length(8), NLMSG_HDRLEN + 8);
    }

    #[test]
    fn rta_space_is_aligned() {
        // rta_space must always be a multiple of 4.
        for len in 0..=32usize {
            let s = rta_space(len);
            assert_eq!(s % 4, 0, "rta_space({len}) = {s} is not 4-byte aligned");
        }
    }

    #[test]
    fn rta_space_grows_with_data() {
        assert!(rta_space(0) <= rta_space(4));
        assert!(rta_space(4) <= rta_space(8));
    }

    // ── OptionsWriter ─────────────────────────────────────────────────────────

    #[test]
    fn options_writer_tlv() {
        let mut buf = [0u8; 16];
        let mut w = OptionsWriter::new(&mut buf);
        w.write(53, &[1]); // DHCP Message Type = DISCOVER
        w.end();
        // byte 0: code=53, byte 1: len=1, byte 2: value=1, byte 3: end=0xff
        assert_eq!(buf[0], 53);
        assert_eq!(buf[1], 1);
        assert_eq!(buf[2], 1);
        assert_eq!(buf[3], 0xff);
    }

    #[test]
    fn options_writer_flag() {
        let mut buf = [0u8; 8];
        let mut w = OptionsWriter::new(&mut buf);
        w.write_flag(80); // Rapid Commit
        w.end();
        // byte 0: code=80, byte 1: len=0, byte 2: end=0xff
        assert_eq!(buf[0], 80);
        assert_eq!(buf[1], 0);
        assert_eq!(buf[2], 0xff);
    }

    #[test]
    fn options_writer_multiple_options() {
        let mut buf = [0u8; 32];
        let mut w = OptionsWriter::new(&mut buf);
        w.write(53, &[3]);       // type = REQUEST
        w.write(50, &[192, 168, 1, 10]); // Requested IP
        w.end();
        assert_eq!(buf[0], 53);  // code
        assert_eq!(buf[1], 1);   // len
        assert_eq!(buf[2], 3);   // REQUEST
        assert_eq!(buf[3], 50);  // next code
        assert_eq!(buf[4], 4);   // len
        assert_eq!(&buf[5..9], &[192, 168, 1, 10]);
        assert_eq!(buf[9], 0xff); // end
    }

    // ── DhcpOptions iterator ──────────────────────────────────────────────────

    /// Build a minimal DHCP packet with the given raw options payload placed
    /// at offset 240 (right after the 4-byte magic cookie).
    fn make_dhcp_pkt(options_payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 240 + options_payload.len()];
        pkt[240..].copy_from_slice(options_payload);
        pkt
    }

    #[test]
    fn dhcp_options_parses_single_option() {
        // code=53, len=1, value=5 (ACK), end=0xff
        let pkt = make_dhcp_pkt(&[53, 1, 5, 0xff]);
        let opts: Vec<(u8, &[u8])> = DhcpOptions::new(&pkt).collect();
        assert_eq!(opts, vec![(53u8, [5u8].as_ref())]);
    }

    #[test]
    fn dhcp_options_stops_at_end_sentinel() {
        let pkt = make_dhcp_pkt(&[53, 1, 2, 0xff, 1, 1, 1]);
        let opts: Vec<_> = DhcpOptions::new(&pkt).collect();
        assert_eq!(opts.len(), 1);
    }

    #[test]
    fn dhcp_options_skips_padding_byte() {
        // 0x00 is a padding byte and must be skipped.
        let pkt = make_dhcp_pkt(&[0x00, 0x00, 53, 1, 5, 0xff]);
        let opts: Vec<_> = DhcpOptions::new(&pkt).collect();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].0, 53);
    }

    #[test]
    fn dhcp_options_multiple_options() {
        // subnet mask (1), router (3), end
        let pkt = make_dhcp_pkt(&[
            1, 4, 255, 255, 255, 0,   // subnet mask
            3, 4, 192, 168, 1, 1,     // router
            0xff,
        ]);
        let opts: Vec<_> = DhcpOptions::new(&pkt).collect();
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].0, 1);
        assert_eq!(opts[1].0, 3);
    }

    #[test]
    fn dhcp_options_empty_payload_yields_nothing() {
        let pkt = make_dhcp_pkt(&[0xff]);
        let opts: Vec<_> = DhcpOptions::new(&pkt).collect();
        assert!(opts.is_empty());
    }

    #[test]
    fn dhcp_options_truncated_length_stops_safely() {
        // len=10 but only 2 bytes follow before end of buffer.
        let pkt = make_dhcp_pkt(&[53, 10, 1, 2]);
        let opts: Vec<_> = DhcpOptions::new(&pkt).collect();
        assert!(opts.is_empty());
    }

    // ── dhcp_msg_type ─────────────────────────────────────────────────────────

    #[test]
    fn msg_type_discover() {
        let pkt = make_dhcp_pkt(&[53, 1, 1, 0xff]);
        assert_eq!(dhcp_msg_type(&pkt), Some(1));
    }

    #[test]
    fn msg_type_offer() {
        let pkt = make_dhcp_pkt(&[53, 1, DHCP_MSG_OFFER, 0xff]);
        assert_eq!(dhcp_msg_type(&pkt), Some(DHCP_MSG_OFFER));
    }

    #[test]
    fn msg_type_ack() {
        let pkt = make_dhcp_pkt(&[53, 1, DHCP_MSG_ACK, 0xff]);
        assert_eq!(dhcp_msg_type(&pkt), Some(DHCP_MSG_ACK));
    }

    #[test]
    fn msg_type_missing_returns_none() {
        // Only a subnet mask option, no option 53.
        let pkt = make_dhcp_pkt(&[1, 4, 255, 255, 255, 0, 0xff]);
        assert_eq!(dhcp_msg_type(&pkt), None);
    }

    #[test]
    fn msg_type_option53_empty_data_skipped() {
        // Option 53 with zero-length data must be ignored (data slice is empty).
        let pkt = make_dhcp_pkt(&[53, 0, 0xff]);
        assert_eq!(dhcp_msg_type(&pkt), None);
    }

    // ── handle_dhcp_ack parsing (prefix length calculation) ───────────────────

    #[test]
    fn prefix_length_from_netmask_24() {
        let netmask = u32::from_be_bytes([255, 255, 255, 0]);
        assert_eq!(netmask.leading_ones(), 24);
    }

    #[test]
    fn prefix_length_from_netmask_16() {
        let netmask = u32::from_be_bytes([255, 255, 0, 0]);
        assert_eq!(netmask.leading_ones(), 16);
    }

    #[test]
    fn prefix_length_from_netmask_32() {
        let netmask = u32::from_be_bytes([255, 255, 255, 255]);
        assert_eq!(netmask.leading_ones(), 32);
    }

    #[test]
    fn prefix_length_from_netmask_0() {
        let netmask = u32::from_be_bytes([0, 0, 0, 0]);
        assert_eq!(netmask.leading_ones(), 0);
    }

    // ── MTU clamping (mirrors handle_dhcp_ack logic) ──────────────────────────

    #[test]
    fn mtu_clamp_below_minimum() {
        let raw: u16 = 500;
        let mtu = raw.clamp(1280, 65520);
        assert_eq!(mtu, 1280);
    }

    #[test]
    fn mtu_clamp_above_maximum() {
        let raw: u16 = 65535;
        let mtu = raw.clamp(1280, 65520);
        assert_eq!(mtu, 65520);
    }

    #[test]
    fn mtu_clamp_within_range() {
        let raw: u16 = 9000;
        let mtu = raw.clamp(1280, 65520);
        assert_eq!(mtu, 9000);
    }

    // ── DHCP packet byte order / yiaddr extraction ────────────────────────────

    #[test]
    fn yiaddr_extracted_correctly_from_packet() {
        // Build a minimal packet with yiaddr = 192.168.100.42 at offset 16.
        let mut pkt = vec![0u8; 241];
        pkt[DHCP_YIADDR_OFFSET..DHCP_YIADDR_OFFSET + 4].copy_from_slice(&[192, 168, 100, 42]);
        let yiaddr = u32::from_be_bytes(
            pkt[DHCP_YIADDR_OFFSET..DHCP_YIADDR_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        let addr = std::net::Ipv4Addr::from(yiaddr);
        assert_eq!(addr, std::net::Ipv4Addr::new(192, 168, 100, 42));
    }

    // ── DhcpPacket construction ───────────────────────────────────────────────

    #[test]
    fn dhcp_packet_new_zeroed_is_all_zeros() {
        let pkt = DhcpPacket::new_zeroed();
        let bytes = pkt.as_bytes();
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn dhcp_packet_as_bytes_has_correct_size() {
        let pkt = DhcpPacket::new_zeroed();
        let bytes = pkt.as_bytes();
        // RFC 2131: fixed header (236 bytes) + magic cookie (4) + options (DHCP_OPTIONS_SIZE).
        assert_eq!(bytes.len(), mem::size_of::<DhcpPacket>());
        assert!(bytes.len() >= 240);
    }
}

