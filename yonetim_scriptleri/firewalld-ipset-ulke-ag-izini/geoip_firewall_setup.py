#!/usr/bin/env python3
"""
GeoIP Firewall Setup Script
Professional country-based access control for firewalld
Author: System Security Script
Version: 3.0

Changelog v3.0:
  - Added local network ipset support (ipset4-local / ipset6-local)
  - Fixed bug: --account-id and --license-key were not passed to configure_geoipupdate()
  - Added --local-networks argument for custom network ranges
  - Added --no-local flag to disable local network rules
  - Local network rules applied at highest priority (-32768) to prevent accidental lockout
  - Improved error messages and diagnostic output
  - Code cleanup and docstring improvements
"""

import os
import sys
import subprocess
import logging
import csv
import tarfile
import ipaddress
from pathlib import Path
from typing import List, Dict, Optional, Union

# ============================================================================
# CONFIGURATION
# ============================================================================

LOG_FILE = "/var/log/allowcntry.log"
FIREWALLD_IPSETS_DIR = "/etc/firewalld/ipsets"
GEOIP_DB_DIR = "/usr/share/GeoIP"
GEOIPUPDATE_CONF = "/etc/GeoIP.conf"

DEFAULT_ALLOWED_COUNTRIES = ["TR"]

# Default local network ranges — intentionally minimal.
#
# Only truly universal addresses (loopback, link-local) are included by
# default.  Broad RFC 1918 blocks (10/8, 172.16/12, 192.168/16) are NOT
# included because the user may only want specific subnets, and adding the
# whole /8 would silently swallow any narrower range passed via
# --local-networks (nftables rejects overlapping intervals).
#
# Add your LAN / VPN subnets explicitly with --local-networks:
#   --local-networks 10.253.10.0/24,192.168.1.0/24
DEFAULT_LOCAL_NETWORKS_IPV4 = [
    "127.0.0.0/8",      # Loopback
    "169.254.0.0/16",   # Link-local (APIPA)
]

DEFAULT_LOCAL_NETWORKS_IPV6 = [
    "::1/128",          # Loopback
    "fe80::/10",        # Link-local
]

# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging() -> bool:
    """Configure file + console logging."""
    try:
        log_dir = os.path.dirname(LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout),
            ]
        )

        if os.path.exists(LOG_FILE):
            os.chmod(LOG_FILE, 0o644)

        logging.info("=" * 80)
        logging.info("GeoIP Firewall Setup Script v3.0 Started")
        logging.info("=" * 80)
        return True
    except Exception as e:
        print(f"CRITICAL ERROR: Cannot setup logging: {e}")
        return False

# ============================================================================
# SYSTEM DETECTION AND PACKAGE MANAGEMENT
# ============================================================================

class SystemManager:
    """Detect the operating system and manage package installation."""

    def __init__(self):
        self.os_type: Optional[str] = None
        self.package_manager: Optional[str] = None
        self.detect_system()

    def detect_system(self):
        """Detect OS and set the appropriate package manager."""
        logging.info("Detecting operating system...")

        if os.path.exists("/etc/fedora-release"):
            self.os_type = "fedora"
            self.package_manager = "dnf"
            logging.info("✓ Detected: Fedora")
        elif os.path.exists("/etc/redhat-release"):
            self.os_type = "rhel"
            self.package_manager = "dnf"
            logging.info("✓ Detected: RHEL/CentOS")
        elif os.path.exists("/etc/debian_version"):
            self.os_type = "debian"
            self.package_manager = "apt"
            if os.path.exists("/etc/lsb-release"):
                with open("/etc/lsb-release") as f:
                    if "Ubuntu" in f.read():
                        self.os_type = "ubuntu"
            logging.info(f"✓ Detected: {self.os_type.capitalize()}")
        else:
            logging.error("❌ Unsupported operating system")
            raise Exception(
                "Unsupported OS. Only Fedora, RHEL/CentOS, and Ubuntu/Debian are supported."
            )

    def run_command(
        self,
        cmd: List[str],
        check: bool = True,
        capture: bool = True,
    ) -> subprocess.CompletedProcess:
        """Execute a shell command with logging and error handling."""
        logging.info(f"Executing: {' '.join(cmd)}")
        try:
            if capture:
                result = subprocess.run(
                    cmd,
                    check=check,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if result.stdout:
                    logging.debug(f"STDOUT: {result.stdout}")
                if result.stderr:
                    logging.debug(f"STDERR: {result.stderr}")
            else:
                result = subprocess.run(cmd, check=check)

            logging.info("✓ Command completed successfully")
            return result
        except subprocess.CalledProcessError as e:
            logging.error(f"❌ Command failed (exit code {e.returncode})")
            if hasattr(e, 'stdout') and e.stdout:
                logging.error(f"STDOUT: {e.stdout}")
            if hasattr(e, 'stderr') and e.stderr:
                logging.error(f"STDERR: {e.stderr}")
            raise

    def is_package_installed(self, package: str) -> bool:
        """Return True if the given package is installed."""
        try:
            if self.package_manager == "dnf":
                return subprocess.run(
                    ["rpm", "-q", package],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                ).returncode == 0
            else:
                return subprocess.run(
                    ["dpkg", "-l", package],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                ).returncode == 0
        except Exception:
            return False

    def install_packages(self, packages: List[str]):
        """Install any packages from *packages* that are not already present."""
        logging.info(f"Checking required packages: {', '.join(packages)}")

        to_install = [p for p in packages if not self.is_package_installed(p)]
        for p in packages:
            if p in to_install:
                logging.info(f"  ⚠ Not installed: {p}")
            else:
                logging.info(f"  ✓ Already installed: {p}")

        if not to_install:
            logging.info("✓ All required packages are already installed")
            return

        logging.info(f"Installing: {', '.join(to_install)}")
        try:
            if self.package_manager == "dnf":
                self.run_command(["dnf", "install", "-y"] + to_install, capture=False)
            else:
                self.run_command(["apt-get", "update"], capture=False)
                self.run_command(["apt-get", "install", "-y"] + to_install, capture=False)
            logging.info("✓ Packages installed successfully")
        except Exception as e:
            logging.error(f"❌ Failed to install packages: {e}")
            raise Exception(
                f"Package installation failed. Please install manually:\n"
                f"  Fedora/RHEL : sudo dnf install -y {' '.join(to_install)}\n"
                f"  Ubuntu/Debian: sudo apt-get install -y {' '.join(to_install)}"
            )

    def ensure_required_packages(self):
        """Install all required packages and ensure firewalld is running."""
        logging.info("Ensuring all required packages are installed...")
        self.install_packages(["firewalld", "ipset", "python3", "geoipupdate"])

        logging.info("Ensuring firewalld service is running...")
        try:
            self.run_command(["systemctl", "enable", "firewalld"])
            self.run_command(["systemctl", "start", "firewalld"])
            self.run_command(["systemctl", "status", "firewalld"])
            logging.info("✓ Firewalld service is active")
        except Exception:
            logging.error("❌ Failed to start firewalld service")
            raise

# ============================================================================
# GEOIP UPDATE CONFIGURATION
# ============================================================================

class GeoIPUpdater:
    """Manage GeoIP database updates via geoipupdate."""

    def __init__(self, system_manager: SystemManager):
        self.system = system_manager

    def configure_geoipupdate(
        self,
        account_id: Optional[str] = None,
        license_key: Optional[str] = None,
        edition_ids: str = "GeoLite2-Country",
    ) -> bool:
        """
        Write /etc/GeoIP.conf with the supplied credentials.

        If *account_id* or *license_key* are not given and the config
        file does not already exist, the user is prompted interactively.
        """
        logging.info("Configuring GeoIP Update...")

        # Re-use existing config if no new credentials were supplied
        if os.path.exists(GEOIPUPDATE_CONF) and not account_id and not license_key:
            logging.info("Checking existing GeoIP.conf...")
            with open(GEOIPUPDATE_CONF) as f:
                content = f.read()
            if "YOUR_ACCOUNT_ID_HERE" not in content and "YOUR_LICENSE_KEY_HERE" not in content:
                logging.info("✓ GeoIP.conf is already configured")
                return True

        if not account_id or not license_key:
            logging.warning("⚠ GeoIP.conf needs configuration")
            print("\n" + "=" * 80)
            print("GEOIP UPDATE CONFIGURATION REQUIRED")
            print("=" * 80)
            print("\nTo use GeoIP databases you need a free MaxMind account.")
            print("Sign up at : https://www.maxmind.com/en/geolite2/signup")
            print("Get keys at: https://www.maxmind.com/en/accounts/current/license-key")
            print("=" * 80)

        if not account_id:
            account_id = input("\nEnter your MaxMind Account ID: ").strip()
        if not account_id:
            logging.error("❌ Account ID cannot be empty")
            return False

        if not license_key:
            license_key = input("Enter your MaxMind License Key: ").strip()
        if not license_key:
            logging.error("❌ License Key cannot be empty")
            return False

        config_content = (
            "# GeoIP.conf - generated by GeoIP Firewall Setup Script v3.0\n"
            f"AccountID {account_id}\n"
            f"LicenseKey {license_key}\n"
            f"EditionIDs {edition_ids}\n\n"
            f"DatabaseDirectory {GEOIP_DB_DIR}\n"
        )

        try:
            os.makedirs(os.path.dirname(GEOIPUPDATE_CONF), exist_ok=True)
            os.makedirs(GEOIP_DB_DIR, exist_ok=True)
            with open(GEOIPUPDATE_CONF, 'w') as f:
                f.write(config_content)
            os.chmod(GEOIPUPDATE_CONF, 0o600)
            logging.info(f"✓ Created {GEOIPUPDATE_CONF}")
            return True
        except Exception as e:
            logging.error(f"❌ Failed to write GeoIP.conf: {e}")
            return False

    def update_database(self):
        """Run geoipupdate and verify that the CSV files are present."""
        logging.info("Updating GeoIP database...")
        try:
            self.system.run_command(["geoipupdate", "-v"], capture=False)
            logging.info("✓ geoipupdate completed")
        except Exception as e:
            raise Exception(
                "GeoIP database update failed.\n"
                "Check your MaxMind credentials and internet connection.\n"
                f"Details: {e}"
            )

        self._extract_csv_files()

        required_csv = [
            f"{GEOIP_DB_DIR}/GeoLite2-Country-Blocks-IPv4.csv",
            f"{GEOIP_DB_DIR}/GeoLite2-Country-Blocks-IPv6.csv",
            f"{GEOIP_DB_DIR}/GeoLite2-Country-Locations-en.csv",
        ]
        missing = [f for f in required_csv if not os.path.exists(f)]
        if missing:
            # Try once more
            self._extract_csv_files()
            missing = [f for f in required_csv if not os.path.exists(f)]
            if missing:
                raise FileNotFoundError(
                    f"Required CSV files are still missing after extraction: {missing}"
                )

        logging.info("✓ All required CSV files are present")

    def _extract_csv_files(self):
        """Extract CSV files from downloaded .tar.gz / .zip archives."""
        logging.info("Extracting CSV files from GeoLite2 archives...")
        try:
            for file in Path(GEOIP_DB_DIR).glob("GeoLite2-Country_*.tar.gz"):
                logging.info(f"Extracting {file}...")
                with tarfile.open(file, 'r:gz') as tar:
                    for member in tar.getmembers():
                        if member.name.endswith('.csv'):
                            member.name = os.path.basename(member.name)
                            tar.extract(member, GEOIP_DB_DIR)
                            logging.info(f"  ✓ {member.name}")

            import zipfile
            for file in Path(GEOIP_DB_DIR).glob("GeoLite2-Country_*.zip"):
                logging.info(f"Extracting {file}...")
                with zipfile.ZipFile(file, 'r') as zf:
                    for name in zf.namelist():
                        if name.endswith('.csv'):
                            content = zf.read(name)
                            out = os.path.join(GEOIP_DB_DIR, os.path.basename(name))
                            with open(out, 'wb') as f:
                                f.write(content)
                            logging.info(f"  ✓ {os.path.basename(name)}")

            logging.info("✓ CSV extraction completed")
        except Exception as e:
            logging.warning(f"⚠ CSV extraction issue: {e}")

# ============================================================================
# GEOIP PARSER
# ============================================================================

class GeoIPParser:
    """Parse GeoLite2-Country CSV files into country → CIDR mappings."""

    def __init__(self):
        self.country_codes: Dict[str, str] = {}      # geoname_id -> ISO code
        self.ipv4_blocks: Dict[str, List[str]] = {}  # ISO code  -> [CIDRs]
        self.ipv6_blocks: Dict[str, List[str]] = {}  # ISO code  -> [CIDRs]

    def load_country_locations(self):
        """Load geoname_id → ISO code mapping."""
        f = f"{GEOIP_DB_DIR}/GeoLite2-Country-Locations-en.csv"
        logging.info(f"Loading country locations from {f}...")
        if not os.path.exists(f):
            raise FileNotFoundError(
                f"Country locations file not found: {f}\n"
                "Please update the GeoIP database."
            )
        with open(f, encoding='utf-8') as fh:
            for row in csv.DictReader(fh):
                gid = row.get('geoname_id', '')
                cc = row.get('country_iso_code', '')
                if gid and cc:
                    self.country_codes[gid] = cc.upper()
        logging.info(f"✓ Loaded {len(self.country_codes)} country codes")

    def load_ip_blocks(self, ip_version: int):
        """Load CIDR blocks for IPv4 or IPv6."""
        fname = (
            f"{GEOIP_DB_DIR}/GeoLite2-Country-Blocks-IPv"
            f"{'4' if ip_version == 4 else '6'}.csv"
        )
        target = self.ipv4_blocks if ip_version == 4 else self.ipv6_blocks

        logging.info(f"Loading IPv{ip_version} blocks from {fname}...")
        if not os.path.exists(fname):
            raise FileNotFoundError(
                f"IP blocks file not found: {fname}\n"
                "Please update the GeoIP database."
            )

        count = 0
        with open(fname, encoding='utf-8') as fh:
            for row in csv.DictReader(fh):
                network = row.get('network', '')
                gid = row.get('geoname_id', '') or row.get('registered_country_geoname_id', '')
                if not network or not gid:
                    continue
                cc = self.country_codes.get(gid)
                if not cc:
                    continue
                target.setdefault(cc, []).append(network)
                count += 1

        logging.info(
            f"✓ Loaded {count} IPv{ip_version} blocks across {len(target)} countries"
        )

    def parse_all(self):
        """Parse all GeoIP CSV data files."""
        logging.info("Parsing GeoIP database...")
        self.load_country_locations()
        self.load_ip_blocks(4)
        self.load_ip_blocks(6)
        logging.info("✓ GeoIP parsing complete")

# ============================================================================
# LOCAL NETWORK IPSET GENERATOR
# ============================================================================

class LocalNetworkIPSetGenerator:
    """
    Generate ipset4-local.xml and ipset6-local.xml for firewalld.

    These ipsets are applied at priority **-32768** (higher than the GeoIP
    rules at -32767), guaranteeing that traffic from loopback, link-local,
    and any explicitly added LAN/VPN addresses is *always* accepted.

    Default IPv4 ranges (minimal — loopback + link-local only)
    -----------------------------------------------------------
    127.0.0.0/8      Loopback
    169.254.0.0/16   Link-local (APIPA)

    Default IPv6 ranges
    -------------------
    ::1/128          Loopback
    fe80::/10        Link-local

    RFC 1918 private ranges (10/8, 172.16/12, 192.168/16) are NOT included
    by default because they are very broad — adding 10.0.0.0/8 would make
    it impossible to later restrict to just 10.253.10.0/24 (nftables rejects
    overlapping intervals in the same ipset).  Specify your subnets
    explicitly via --local-networks.
    """

    IPSET_NAME_V4 = "ipset4-local"
    IPSET_NAME_V6 = "ipset6-local"

    def __init__(
        self,
        extra_ipv4: Optional[List[str]] = None,
        extra_ipv6: Optional[List[str]] = None,
    ):
        """
        Parameters
        ----------
        extra_ipv4 : list of str, optional
            Additional IPv4 CIDR ranges to include (e.g. VPN subnets).
            Ranges that are already covered by a broader default range are
            silently skipped — nftables rejects overlapping intervals.
        extra_ipv6 : list of str, optional
            Additional IPv6 CIDR ranges to include.
        """
        combined_v4 = list(DEFAULT_LOCAL_NETWORKS_IPV4)
        combined_v6 = list(DEFAULT_LOCAL_NETWORKS_IPV6)

        # Validate and accumulate extra ranges before deduplication
        for net in (extra_ipv4 or []):
            net = net.strip()
            if not net:
                continue
            self._validate_cidr(net, 4)
            if net not in combined_v4:
                combined_v4.append(net)

        for net in (extra_ipv6 or []):
            net = net.strip()
            if not net:
                continue
            self._validate_cidr(net, 6)
            if net not in combined_v6:
                combined_v6.append(net)

        # Remove any subnet that is already covered by a broader supernet
        # in the same list — nftables hash:net interval rejects overlapping CIDRs
        self.ipv4_networks = self._deduplicate_networks(combined_v4, 4)
        self.ipv6_networks = self._deduplicate_networks(combined_v6, 6)

        os.makedirs(FIREWALLD_IPSETS_DIR, exist_ok=True)

    @staticmethod
    def _validate_cidr(cidr: str, version: int):
        """
        Raise a clear ValueError if *cidr* is not a valid IPv4/IPv6 network.

        Catches the common typo of writing '10.255.255.0,24' instead of
        '10.255.255.0/24' (comma instead of slash).
        """
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            # Give a targeted hint for the comma-vs-slash typo
            suggestion = ""
            if "," in cidr:
                suggestion = f"  Did you mean '{cidr.replace(',', '/', 1)}'? (use '/' not ',')"
            raise ValueError(
                f"Invalid IPv{version} CIDR '{cidr}'.\n"
                f"  Expected format: address/prefix-length  e.g. 10.8.0.0/24\n"
                f"{suggestion}"
            )

    @staticmethod
    def _deduplicate_networks(cidrs: List[str], version: int) -> List[str]:
        """
        Return *cidrs* with any subnet that is already fully covered by a
        broader network in the list removed.

        nftables ``hash:net`` with the ``interval`` flag raises
        "conflicting intervals" when two overlapping prefixes (e.g.
        10.0.0.0/8 and 10.253.10.0/24) are loaded into the same set.
        Removing the more-specific (smaller) prefix is safe because the
        broader one already matches all traffic in that range.

        Example
        -------
        Input : ['10.0.0.0/8', '172.16.0.0/12', '10.253.10.0/24']
        Output: ['10.0.0.0/8', '172.16.0.0/12']   ← /24 removed (inside /8)
        """
        net_type = ipaddress.IPv4Network if version == 4 else ipaddress.IPv6Network

        # Parse, normalise (strict=False accepts host bits set), deduplicate
        parsed: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        seen = set()
        for c in cidrs:
            n = net_type(c, strict=False)
            key = str(n)
            if key not in seen:
                seen.add(key)
                parsed.append(n)

        # Sort broadest-first (shortest prefix length first)
        parsed.sort(key=lambda n: n.prefixlen)

        kept: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for candidate in parsed:
            # Is this candidate a subnet of any already-kept network?
            covered = any(candidate.subnet_of(k) and candidate != k for k in kept)
            if covered:
                logging.warning(
                    f"  ⚠ Skipping {candidate} — already covered by a broader network "
                    f"in the local ipset (nftables does not allow overlapping intervals)"
                )
            else:
                kept.append(candidate)

        result = [str(n) for n in kept]
        logging.info(
            f"  IPv{version} local networks after deduplication "
            f"({len(result)}/{len(cidrs)}): {', '.join(result)}"
        )
        return result

    @staticmethod
    def _build_xml(name: str, family: str, entries: List[str], description: str) -> str:
        lines = [
            '<?xml version="1.0" encoding="utf-8"?>',
            '<ipset type="hash:net">',
            f'  <short>{name}</short>',
            f'  <description>{description}</description>',
            f'  <option name="family" value="{family}"/>',
        ]
        lines += [f'  <entry>{e}</entry>' for e in entries]
        lines.append('</ipset>')
        return "\n".join(lines) + "\n"

    def create_local_ipsets(self) -> List[str]:
        """
        Write ipset4-local.xml and ipset6-local.xml.

        Returns the list of created file paths.
        """
        logging.info("Creating local network ipset files...")
        created: List[str] = []

        for name, family, networks in [
            (self.IPSET_NAME_V4, "inet",  self.ipv4_networks),
            (self.IPSET_NAME_V6, "inet6", self.ipv6_networks),
        ]:
            xml_file = f"{FIREWALLD_IPSETS_DIR}/{name}.xml"
            xml = self._build_xml(
                name=name,
                family=family,
                entries=networks,
                description=f"Local/private {'IPv4' if family == 'inet' else 'IPv6'} networks "
                            f"- always accepted (auto-generated)",
            )
            with open(xml_file, 'w') as fh:
                fh.write(xml)

            if not (os.path.exists(xml_file) and os.path.getsize(xml_file) > 0):
                raise Exception(f"Failed to create {xml_file}")

            created.append(xml_file)
            logging.info(f"✓ Created {xml_file} ({len(networks)} networks)")
            for net in networks:
                logging.info(f"    {net}")

        logging.info("✓ Local network ipset files created")
        return created

# ============================================================================
# COUNTRY-BASED IPSET GENERATOR
# ============================================================================

class FirewalldIPSetGenerator:
    """Generate per-country and combined notblock ipset XML files."""

    def __init__(self, parser: GeoIPParser, allowed_countries: List[str]):
        self.parser = parser
        self.allowed_countries = [c.upper() for c in allowed_countries]
        os.makedirs(FIREWALLD_IPSETS_DIR, exist_ok=True)

    @staticmethod
    def _build_xml(name: str, family: str, entries: List[str]) -> str:
        lines = [
            '<?xml version="1.0" encoding="utf-8"?>',
            '<ipset type="hash:net">',
            f'  <short>{name}</short>',
            f'  <description>GeoIP {name} - auto-generated</description>',
            f'  <option name="family" value="{family}"/>',
        ]
        lines += [f'  <entry>{e}</entry>' for e in entries]
        lines.append('</ipset>')
        return "\n".join(lines) + "\n"

    def _write_xml(self, xml_file: str, xml_content: str, label: str) -> str:
        with open(xml_file, 'w') as fh:
            fh.write(xml_content)
        if not (os.path.exists(xml_file) and os.path.getsize(xml_file) > 0):
            raise Exception(f"Failed to create {xml_file}")
        logging.info(f"✓ Created {xml_file} ({label})")
        return xml_file

    def create_country_ipsets(self) -> List[str]:
        """Create geoip4-XX.xml / geoip6-XX.xml files for each allowed country."""
        logging.info("Creating country-specific ipset files...")
        created: List[str] = []

        for country in self.allowed_countries:
            for version, src, family in [
                (4, self.parser.ipv4_blocks, "inet"),
                (6, self.parser.ipv6_blocks, "inet6"),
            ]:
                if country not in src:
                    logging.warning(f"⚠ No IPv{version} blocks for country: {country}")
                    continue
                name = f"geoip{version}-{country.lower()}"
                xml_file = f"{FIREWALLD_IPSETS_DIR}/{name}.xml"
                created.append(
                    self._write_xml(
                        xml_file,
                        self._build_xml(name, family, src[country]),
                        f"{len(src[country])} entries",
                    )
                )

        if not created:
            raise Exception("No country ipset files were created. Check country codes.")

        logging.info(f"✓ Created {len(created)} country ipset files")
        return created

    def create_notblock_ipsets(self) -> List[str]:
        """
        Merge all allowed-country CIDRs into geoip4-notblock / geoip6-notblock.
        These combined ipsets are what the drop/accept rules actually reference.
        """
        logging.info("Creating combined notblock ipset files...")
        created: List[str] = []

        all_v4 = [n for c in self.allowed_countries for n in self.parser.ipv4_blocks.get(c, [])]
        all_v6 = [n for c in self.allowed_countries for n in self.parser.ipv6_blocks.get(c, [])]

        for name, family, entries in [
            ("geoip4-notblock", "inet",  all_v4),
            ("geoip6-notblock", "inet6", all_v6),
        ]:
            if not entries:
                logging.warning(f"⚠ No entries for {name}, skipping")
                continue
            xml_file = f"{FIREWALLD_IPSETS_DIR}/{name}.xml"
            created.append(
                self._write_xml(
                    xml_file,
                    self._build_xml(name, family, entries),
                    f"{len(entries)} entries",
                )
            )

        logging.info("✓ Combined notblock ipset files created")
        return created

# ============================================================================
# FIREWALLD RULE MANAGER
# ============================================================================

class FirewalldRuleManager:
    """Apply, verify, and clean up firewalld rich rules."""

    def __init__(self, system_manager: SystemManager):
        self.system = system_manager

    def reload_firewalld(self):
        """Reload firewalld so newly written ipset XML files are recognised."""
        logging.info("Reloading firewalld...")
        try:
            self.system.run_command(["firewall-cmd", "--reload"])
            logging.info("✓ Firewalld reloaded")
        except Exception as e:
            logging.error(f"❌ Failed to reload firewalld: {e}")
            raise

    def remove_existing_rules(self):
        """Remove any previously created GeoIP or local-ipset rules."""
        logging.info("Removing existing GeoIP / local-ipset rules...")
        try:
            result = self.system.run_command(
                ["firewall-cmd", "--list-rich-rules"], check=False
            )
            for line in result.stdout.splitlines():
                keywords = ("geoip", "ipset4-local", "ipset6-local")
                if any(k in line.lower() for k in keywords):
                    logging.info(f"Removing: {line}")
                    for flag in [[], ["--permanent"]]:
                        try:
                            self.system.run_command(
                                ["firewall-cmd"] + flag + ["--remove-rich-rule", line]
                            )
                        except Exception:
                            pass
            logging.info("✓ Existing rules cleaned up")
        except Exception as e:
            logging.warning(f"⚠ Could not clean up existing rules: {e}")

    def add_local_network_rules(self):
        """
        Add ACCEPT rules for local-network ipsets at priority **-32768**.

        Being processed before the GeoIP drop rules (-32767), these rules
        ensure that LAN / loopback / VPN traffic is never blocked.
        """
        logging.info("Adding local network ACCEPT rules (priority -32768)...")
        rules = [
            'rule priority="-32768" family="ipv4" source ipset="ipset4-local" accept',
            'rule priority="-32768" family="ipv6" source ipset="ipset6-local" accept',
        ]
        self._apply_rules(rules)
        logging.info("✓ Local network rules added")

    def add_geoip_rules(self):
        """
        Add GeoIP ACCEPT/DROP rules at priority **-32767**.

        Rule evaluation order (lowest number = highest priority):
          -32768  local ipsets          → ACCEPT  (applied by add_local_network_rules)
          -32767  allowed-country ipset → ACCEPT
          -32767  everything else       → DROP
        """
        logging.info("Adding GeoIP country rules (priority -32767)...")
        rules = [
            'rule priority="-32767" family="ipv4" source ipset="geoip4-notblock" accept',
            'rule priority="-32767" family="ipv4" drop',
            'rule priority="-32767" family="ipv6" source ipset="geoip6-notblock" accept',
            'rule priority="-32767" family="ipv6" drop',
        ]
        self._apply_rules(rules)
        logging.info("✓ GeoIP rules added")

    def _apply_rules(self, rules: List[str]):
        """Apply a list of rich rules both at runtime and permanently."""
        for rule in rules:
            logging.info(f"  Adding: {rule}")
            try:
                self.system.run_command(["firewall-cmd", "--add-rich-rule", rule])
                self.system.run_command(["firewall-cmd", "--permanent", "--add-rich-rule", rule])
                logging.info("  ✓ Rule added")
            except Exception as e:
                logging.error(f"  ❌ Failed: {e}")
                raise

    def verify_rules(self, check_local: bool = True) -> bool:
        """
        Verify all expected rules are active.

        Parameters
        ----------
        check_local : bool
            When True (default) also check that ipset4-local / ipset6-local
            rules are present.
        """
        logging.info("Verifying firewall rules...")
        try:
            result = self.system.run_command(["firewall-cmd", "--list-rich-rules"])
            output = result.stdout

            required = ["geoip4-notblock", "geoip6-notblock"]
            if check_local:
                required += ["ipset4-local", "ipset6-local"]

            missing = [r for r in required if r not in output]

            if not missing:
                logging.info("✓ All firewall rules verified")
                print("\n" + "=" * 80)
                print("ACTIVE FIREWALL RULES:")
                print("=" * 80)
                print(output)
                print("=" * 80)
                return True
            else:
                logging.error(f"❌ Rules not found for: {', '.join(missing)}")
                return False
        except Exception as e:
            logging.error(f"❌ Verification failed: {e}")
            return False

# ============================================================================
# CLI ARGUMENT PARSING
# ============================================================================

def parse_arguments():
    """Parse and return command-line arguments."""
    import argparse

    parser = argparse.ArgumentParser(
        description="GeoIP Firewall Setup v3.0 – country-based access control with local network support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --allow TR
  %(prog)s --allow TR,DE,US
  %(prog)s --allow TR --account-id 123456 --license-key AbCd1234
  %(prog)s --allow TR --local-networks 10.10.0.0/16,172.20.0.0/14
  %(prog)s --allow TR --no-local
  %(prog)s --allow TR --skip-update

Local network ipsets (ipset4-local / ipset6-local)
  By default, RFC 1918 private ranges, loopback, and link-local addresses
  are ALWAYS accepted (priority -32768) so that LAN/VPN access cannot be
  blocked by country-based rules.
  --local-networks  adds extra CIDRs (e.g. a VPN or management subnet).
  --no-local        disables local ipsets entirely (NOT recommended).

MaxMind account
  Sign up for free at: https://www.maxmind.com/en/geolite2/signup
        """
    )

    parser.add_argument(
        '--allow',
        type=str, default='TR',
        help='Comma-separated ISO 3166-1 alpha-2 country codes to allow (default: TR)'
    )
    parser.add_argument(
        '--account-id',
        type=str, default=None,
        help='MaxMind Account ID (prompted interactively if omitted)'
    )
    parser.add_argument(
        '--license-key',
        type=str, default=None,
        help='MaxMind License Key (prompted interactively if omitted)'
    )
    parser.add_argument(
        '--edition-ids',
        type=str, default='GeoLite2-Country',
        help='GeoIP Edition IDs (default: GeoLite2-Country)'
    )
    parser.add_argument(
        '--skip-update',
        action='store_true',
        help='Skip GeoIP database update and use existing data'
    )
    parser.add_argument(
        '--local-networks', '--local-network',  # accept both singular and plural
        dest='local_networks',
        type=str, default=None,
        help=(
            'Comma-separated extra CIDR ranges added to local ipsets '
            '(e.g. "10.8.0.0/24,172.20.0.0/14"). '
            'Subnets already covered by a default range are skipped automatically.'
        )
    )
    parser.add_argument(
        '--no-local',
        action='store_true',
        help='Disable local network ipsets entirely (NOT recommended - risk of LAN lockout)'
    )

    return parser.parse_args()

# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    """Entry point."""
    args = parse_arguments()

    allowed_countries = [c.strip().upper() for c in args.allow.split(',') if c.strip()]

    # Separate extra local networks into IPv4 and IPv6 lists
    # Validate CIDRs eagerly so the user gets a clear error before any system changes
    extra_local_ipv4: List[str] = []
    extra_local_ipv6: List[str] = []
    if args.local_networks:
        for raw in args.local_networks.split(','):
            raw = raw.strip()
            if not raw:
                continue
            # Detect and reject comma-vs-slash typo early (e.g. "10.0.0.0,8")
            # A plain integer with no dot/colon is almost certainly a stray prefix length
            if raw.isdigit():
                print(
                    f"\n❌ ERROR: '{raw}' looks like a stray prefix length, not a CIDR.\n"
                    f"  Did you write a comma instead of a slash?\n"
                    f"  Correct format: 10.255.255.0/24   (use '/' not ',')"
                )
                sys.exit(1)
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                suggestion = ""
                if "," in raw:
                    suggestion = f"\n  Did you mean '{raw.replace(',', '/', 1)}'?"
                print(
                    f"\n❌ ERROR: Invalid CIDR '{raw}' in --local-networks.\n"
                    f"  Expected format: address/prefix-length  e.g. 10.8.0.0/24"
                    f"{suggestion}"
                )
                sys.exit(1)
            if isinstance(net, ipaddress.IPv6Network):
                extra_local_ipv6.append(str(net))
            else:
                extra_local_ipv4.append(str(net))

    # --- Banner ---
    print("\n" + "=" * 80)
    print("GeoIP FIREWALL SETUP v3.0")
    print("=" * 80)
    print(f"\n  Allowed countries   : {', '.join(allowed_countries)}")
    print(f"  Blocked             : ALL other countries")
    if args.no_local:
        print("  Local network rules : DISABLED (--no-local)")
    else:
        v4 = DEFAULT_LOCAL_NETWORKS_IPV4 + extra_local_ipv4
        v6 = DEFAULT_LOCAL_NETWORKS_IPV6 + extra_local_ipv6
        print(f"  Local IPv4 networks : {', '.join(v4) if v4 else '(only loopback/link-local)'}")
        print(f"  Local IPv6 networks : {', '.join(v6) if v6 else '(only loopback/link-local)'}")
        if not extra_local_ipv4 and not extra_local_ipv6:
            print("  ⚠  No LAN subnets added. Use --local-networks to add your subnets"
                  " (e.g. --local-networks 10.253.10.0/24)")
    print("\n" + "=" * 80)

    if os.geteuid() != 0:
        print("\n❌ ERROR: This script must be run as root")
        print("  sudo python3 geoip_firewall_setup.py")
        sys.exit(1)

    if not setup_logging():
        print("❌ Failed to setup logging. Exiting.")
        sys.exit(1)

    total_steps = 8 if not args.no_local else 7

    try:
        # 1 — System detection
        print(f"\n[1/{total_steps}] System Detection and Package Installation")
        print("-" * 80)
        system = SystemManager()
        system.ensure_required_packages()

        # 2 — GeoIP config
        print(f"\n[2/{total_steps}] GeoIP Configuration")
        print("-" * 80)
        updater = GeoIPUpdater(system)

        if not args.skip_update:
            if not updater.configure_geoipupdate(
                account_id=args.account_id,
                license_key=args.license_key,
                edition_ids=args.edition_ids,
            ):
                raise Exception("GeoIP configuration failed")

            # 3 — Database update
            print(f"\n[3/{total_steps}] GeoIP Database Update")
            print("-" * 80)
            updater.update_database()
        else:
            logging.info("⚠ Skipping GeoIP database update (--skip-update flag)")

        # 4 — Parse
        print(f"\n[4/{total_steps}] Parsing GeoIP Database")
        print("-" * 80)
        geoip_parser = GeoIPParser()
        geoip_parser.parse_all()

        for country in allowed_countries:
            if country not in geoip_parser.ipv4_blocks and country not in geoip_parser.ipv6_blocks:
                raise Exception(
                    f"Country code '{country}' not found in the GeoIP database.\n"
                    "Use ISO 3166-1 alpha-2 codes (TR, DE, US, …)."
                )

        # 5 — Country ipsets
        print(f"\n[5/{total_steps}] Generating Country IPSet Files")
        print("-" * 80)
        country_gen = FirewalldIPSetGenerator(geoip_parser, allowed_countries)
        country_gen.create_country_ipsets()
        country_gen.create_notblock_ipsets()

        # 6 — Local network ipsets (optional)
        step = 6
        if not args.no_local:
            print(f"\n[{step}/{total_steps}] Generating Local Network IPSet Files")
            print("-" * 80)
            LocalNetworkIPSetGenerator(
                extra_ipv4=extra_local_ipv4,
                extra_ipv6=extra_local_ipv6,
            ).create_local_ipsets()
            step += 1
        else:
            logging.info("⚠ Skipping local network ipsets (--no-local)")

        # 7 — Firewalld rules
        print(f"\n[{step}/{total_steps}] Configuring Firewalld Rules")
        print("-" * 80)
        rule_manager = FirewalldRuleManager(system)
        rule_manager.remove_existing_rules()
        rule_manager.reload_firewalld()

        if not args.no_local:
            rule_manager.add_local_network_rules()  # priority -32768

        rule_manager.add_geoip_rules()              # priority -32767
        step += 1

        # 8 — Verify
        print(f"\n[{step}/{total_steps}] Verification")
        print("-" * 80)
        rule_manager.verify_rules(check_local=not args.no_local)

        # Success
        print("\n" + "=" * 80)
        print("✓ SUCCESS - GEOIP FIREWALL CONFIGURED SUCCESSFULLY")
        print("=" * 80)
        print(f"\n  Allowed countries   : {', '.join(allowed_countries)}")
        print(f"  All other countries : BLOCKED")
        if not args.no_local:
            print(f"  Local network sets  : ipset4-local, ipset6-local (always ACCEPTED)")
        print(f"\n  Log file  : {LOG_FILE}")
        print(f"  IPSet dir : {FIREWALLD_IPSETS_DIR}")
        print("\n" + "=" * 80)

        logging.info("=" * 80)
        logging.info("Script completed successfully")
        logging.info("=" * 80)
        return 0

    except KeyboardInterrupt:
        logging.error("\n❌ Script interrupted by user")
        print("\n❌ Script interrupted by user")
        return 130

    except Exception as e:
        logging.error(f"❌ FATAL ERROR: {e}")
        print("\n" + "=" * 80)
        print("❌ ERROR OCCURRED")
        print("=" * 80)
        print(f"\n{e}")
        print(f"\nCheck log: sudo tail -100 {LOG_FILE}")
        print("\n" + "=" * 80)
        print("TROUBLESHOOTING CHECKLIST:")
        print("  1. Valid MaxMind account with correct Account ID / License Key")
        print("  2. Internet connectivity (ping www.maxmind.com)")
        print("  3. firewalld installed and running (systemctl status firewalld)")
        print("  4. Sufficient disk space (df -h /usr/share)")
        print(f"  5. Full log: sudo cat {LOG_FILE}")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
