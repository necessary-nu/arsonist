//! Host networking: a tap and a /30 per slot, NAT out of the host, and a
//! firewall keeping guests off each other and off the host.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer};

use crate::cmd::Cmd;
use crate::info;

/// Every slot's tap is this plus the slot index; the firewall matches on it.
pub const TAP_PREFIX: &str = "arsonist";
const NFT_TABLE: &str = "arsonist";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    base: u32,
    prefix: u8,
}

impl FromStr for Subnet {
    type Err = anyhow::Error;

    fn from_str(cidr: &str) -> Result<Subnet> {
        let (ip, bits) = cidr
            .split_once('/')
            .with_context(|| format!("{cidr:?} is not a CIDR like 172.30.0.0/16"))?;
        let ip: Ipv4Addr = ip.parse().with_context(|| format!("{cidr:?}"))?;
        let prefix: u8 = bits.parse().with_context(|| format!("{cidr:?}"))?;
        if !(8..=30).contains(&prefix) {
            bail!("{cidr}: the prefix must be /8 to /30");
        }
        let base = u32::from(ip);
        if base & !(u32::MAX << (32 - prefix)) != 0 {
            bail!("{cidr} is not aligned to its prefix");
        }
        Ok(Subnet { base, prefix })
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.base), self.prefix)
    }
}

impl<'de> Deserialize<'de> for Subnet {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse()
            .map_err(|e: anyhow::Error| serde::de::Error::custom(format!("{e:#}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAddress {
    pub tap: String,
    pub host_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub guest_mac: String,
}

impl Subnet {
    /// Slot `index` gets the `index`th /30: host side .1, guest .2.
    /// Point-to-point links keep the guests off each other's segment.
    pub fn slot(&self, index: u32) -> Result<SlotAddress> {
        let size = 1u64 << (32 - self.prefix);
        let block = u64::from(self.base) + u64::from(index) * 4;
        if block + 4 > u64::from(self.base) + size {
            bail!(
                "{self} has room for {} slots, not {}",
                size / 4,
                u64::from(index) + 1
            );
        }
        let guest = Ipv4Addr::from(block as u32 + 2);
        let [a, b, c, d] = guest.octets();
        Ok(SlotAddress {
            tap: format!("{TAP_PREFIX}{index}"),
            host_ip: Ipv4Addr::from(block as u32 + 1),
            guest_ip: guest,
            netmask: Ipv4Addr::new(255, 255, 255, 252),
            guest_mac: format!("06:00:{a:02x}:{b:02x}:{c:02x}:{d:02x}"),
        })
    }
}

/// Guests reach the internet through the uplink alone, masqueraded: not
/// each other, not the host, and not other networks the host is on, such as
/// a tailnet it would otherwise let them into as itself. Nothing reaches a
/// guest but replies. Replaced whole every time, so it never accumulates.
pub fn nft_ruleset(subnet: Subnet, uplink: &str) -> String {
    format!(
        r#"table ip {NFT_TABLE}
delete table ip {NFT_TABLE}
table ip {NFT_TABLE} {{
  chain forward {{
    type filter hook forward priority filter; policy accept;
    iifname "{TAP_PREFIX}*" oifname != "{uplink}" drop
    oifname "{TAP_PREFIX}*" iifname != "{uplink}" drop
    oifname "{TAP_PREFIX}*" ct state established,related accept
    oifname "{TAP_PREFIX}*" drop
  }}
  chain input {{
    type filter hook input priority filter; policy accept;
    iifname "{TAP_PREFIX}*" ct state established,related accept
    iifname "{TAP_PREFIX}*" drop
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {subnet} oifname "{uplink}" masquerade
  }}
}}
"#
    )
}

/// The interface of the default IPv4 route, from `ip -4 route show default`.
fn default_route_interface(routes: &str) -> Option<&str> {
    routes.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        words.next().filter(|w| *w == "default")?;
        words.skip_while(|w| *w != "dev").nth(1)
    })
}

pub fn uplink(configured: Option<&str>) -> Result<String> {
    if let Some(uplink) = configured {
        return Ok(uplink.to_string());
    }
    let routes = Cmd::new("ip")
        .args(["-4", "route", "show", "default"])
        .run()?
        .stdout;
    default_route_interface(&routes)
        .map(String::from)
        .context("no default IPv4 route to send the guests out of; set network.uplink")
}

/// Docker on the same host sets the iptables FORWARD policy to DROP, which
/// overrides an accept in any other table. DOCKER-USER is where Docker lets
/// other forwarding in.
fn docker_user_rules() -> [Vec<String>; 2] {
    let tap = format!("{TAP_PREFIX}+");
    [
        vec!["-i".into(), tap.clone(), "-j".into(), "ACCEPT".into()],
        [
            "-o",
            &tap,
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ]
        .map(String::from)
        .to_vec(),
    ]
}

fn has_docker_user_chain() -> bool {
    Cmd::new("iptables")
        .args(["-n", "-L", "DOCKER-USER"])
        .succeeds()
}

pub fn network_up(subnet: Subnet, configured_uplink: Option<&str>) -> Result<()> {
    let uplink = uplink(configured_uplink)?;
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n").context("enabling IPv4 forwarding")?;
    Cmd::new("nft")
        .args(["-f", "-"])
        .stdin(nft_ruleset(subnet, &uplink))
        .run()?;
    if has_docker_user_chain() {
        for rule in docker_user_rules() {
            if !Cmd::new("iptables")
                .args(["-C", "DOCKER-USER"])
                .args(&rule)
                .succeeds()
            {
                Cmd::new("iptables")
                    .args(["-I", "DOCKER-USER"])
                    .args(&rule)
                    .run()?;
            }
        }
        info!("let microVM traffic through Docker's DOCKER-USER chain");
    }
    info!("host networking is up for {subnet}, out through {uplink}");
    Ok(())
}

pub fn network_down() -> Result<()> {
    Cmd::new("nft")
        .args(["delete", "table", "ip", NFT_TABLE])
        .ok_codes(&[1])
        .run()?;
    if has_docker_user_chain() {
        for rule in docker_user_rules() {
            while Cmd::new("iptables")
                .args(["-C", "DOCKER-USER"])
                .args(&rule)
                .succeeds()
            {
                Cmd::new("iptables")
                    .args(["-D", "DOCKER-USER"])
                    .args(&rule)
                    .run()?;
            }
        }
    }
    Ok(())
}

/// Recreate the slot's tap, owned by its jail uid so Firecracker can open it.
pub fn tap_up(addr: &SlotAddress, uid: u32) -> Result<()> {
    tap_down(addr)?;
    Cmd::new("ip")
        .args(["tuntap", "add", "dev", &addr.tap, "mode", "tap", "user"])
        .arg(uid.to_string())
        .run()?;
    Cmd::new("ip")
        .args([
            "addr",
            "add",
            &format!("{}/30", addr.host_ip),
            "dev",
            &addr.tap,
        ])
        .run()?;
    Cmd::new("ip")
        .args(["link", "set", &addr.tap, "up"])
        .run()?;
    Ok(())
}

pub fn tap_down(addr: &SlotAddress) -> Result<()> {
    if Cmd::new("ip").args(["link", "show", &addr.tap]).succeeds() {
        Cmd::new("ip").args(["link", "del", &addr.tap]).run()?;
    }
    Ok(())
}

/// The first two IPv4 nameservers in a resolv.conf that a guest can reach
/// through the uplink: not loopback (the host's own stub resolver), and not
/// shared address space (100.64.0.0/10, where Tailscale's MagicDNS lives).
fn upstream_nameservers(resolv_conf: &str) -> Vec<Ipv4Addr> {
    resolv_conf
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            match (words.next(), words.next()) {
                (Some("nameserver"), Some(ip)) => ip.parse::<Ipv4Addr>().ok(),
                _ => None,
            }
        })
        .filter(|ip| !ip.is_loopback() && !ip.is_link_local() && !is_shared(*ip))
        .take(2)
        .collect()
}

fn is_shared(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 100 && (64..128).contains(&b)
}

/// The host's upstream resolvers, which the guests reach through the NAT.
pub fn host_resolvers() -> Result<Vec<Ipv4Addr>> {
    for file in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        if let Ok(text) = std::fs::read_to_string(file) {
            let servers = upstream_nameservers(&text);
            if !servers.is_empty() {
                return Ok(servers);
            }
        }
    }
    bail!("the host has no nameserver a guest could reach through the uplink; set network.dns")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_slot_gets_its_own_slash_30() {
        let subnet: Subnet = "172.30.0.0/16".parse().unwrap();
        assert_eq!(
            subnet.slot(0).unwrap(),
            SlotAddress {
                tap: "arsonist0".into(),
                host_ip: "172.30.0.1".parse().unwrap(),
                guest_ip: "172.30.0.2".parse().unwrap(),
                netmask: "255.255.255.252".parse().unwrap(),
                guest_mac: "06:00:ac:1e:00:02".into(),
            }
        );
        let far = subnet.slot(100).unwrap();
        assert_eq!(far.host_ip.to_string(), "172.30.1.145");
        assert_eq!(far.guest_ip.to_string(), "172.30.1.146");
        assert_eq!(far.tap, "arsonist100");
    }

    #[test]
    fn subnets_must_fit_and_align() {
        let small: Subnet = "10.9.0.0/29".parse().unwrap();
        assert!(small.slot(1).is_ok());
        assert!(format!("{:#}", small.slot(2).unwrap_err()).contains("room for 2 slots"));
        assert!("10.9.0.1/24".parse::<Subnet>().is_err());
        assert!("10.9.0.0/31".parse::<Subnet>().is_err());
    }

    #[test]
    fn taps_fit_in_an_interface_name() {
        let subnet: Subnet = "10.0.0.0/8".parse().unwrap();
        let last = subnet.slot((1 << 22) - 1).unwrap();
        assert!(last.tap.len() <= 15, "{}", last.tap);
    }

    #[test]
    fn guests_only_go_out_through_the_uplink() {
        let rules = nft_ruleset("172.30.0.0/16".parse().unwrap(), "vmbr0");
        assert!(rules.starts_with("table ip arsonist\ndelete table ip arsonist\n"));
        assert!(rules.contains(r#"iifname "arsonist*" oifname != "vmbr0" drop"#));
        assert!(rules.contains(r#"oifname "arsonist*" iifname != "vmbr0" drop"#));
        assert!(rules.contains(r#"ip saddr 172.30.0.0/16 oifname "vmbr0" masquerade"#));
    }

    #[test]
    fn the_uplink_is_the_default_routes_interface() {
        let routes = "default via 144.76.103.129 dev vmbr0 proto kernel onlink \n";
        assert_eq!(default_route_interface(routes), Some("vmbr0"));
        assert_eq!(default_route_interface("10.0.0.0/8 dev eth1\n"), None);
    }

    #[test]
    fn resolvers_guests_cannot_reach_are_skipped() {
        let conf = "nameserver 127.0.0.53\nnameserver 100.100.100.100\nnameserver 192.168.1.1\n# x\nnameserver ::1\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n";
        assert_eq!(
            upstream_nameservers(conf),
            [
                "192.168.1.1".parse::<Ipv4Addr>().unwrap(),
                "1.1.1.1".parse().unwrap()
            ]
        );
    }
}
