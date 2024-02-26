#!/usr/bin/env python3

"""Load bind9 zone files into a PanOS firewall as address and address group objects"""

# SPDX-FileCopyrightText: 2024 Joe Pitt
#
# SPDX-License-Identifier: GPL-3.0-only

from configparser import ConfigParser, NoOptionError
from ipaddress import ip_address
from os.path import isfile
from re import compile, IGNORECASE
from typing import List

try:
    from dns.rdataclass import INTERNET
    from dns.rdatatype import A as a_id, AAAA as aaaa_id
    from dns.rdtypes.IN.A import A
    from dns.rdtypes.IN.AAAA import AAAA
    from dns.zone import from_file, NoNS, NoSOA
except ImportError:
    raise ImportError("Failed to load zone processor")

try:
    from panos.errors import PanObjectMissing
    from panos.firewall import Firewall
    from panos.objects import AddressGroup, AddressObject
except ImportError:
    raise ImportError("Failed to load PanOS module")

from log import CreateLogger

__author__ = "Joe Pitt"
__copyright__ = "Copyright 2024, Joe Pitt"
__email__ = "Joe.Pitt@joepitt.co.uk"
__license__ = "GPL-3.0-only"
__maintainer__ = "Joe Pitt"
__status__ = "Production"
__version__ = "1.0.0"


def host_description(comment: str | None) -> str:
    """Parse the PanOS description out of a bind9 comment

    Args:
        comment (str | None): The comment associated with the record, or None

    Raises:
        ValueError: If no description is found or there is no comment

    Returns:
        str: The description to use
    """

    rex = compile(r"panos_desc=(?P<desc>([A-Za-z0-9]+)|(\"[A-Za-z0-9 ]+\"))")
    try:
        return rex.search(comment)[0].replace("panos_desc=", "").replace('"', "")
    except (KeyError, TypeError):
        raise ValueError("No PanOS description found")


def host_tag(comment: str | None) -> str:
    """Parse the PanOS tag out of a bind9 comment

    Args:
        comment (str | None): The comment associated with the record, or None

    Raises:
        ValueError: If no tag is found or there is no comment

    Returns:
        str: The tag to use
    """

    rex = compile(r"panos_tag=(?P<tag>([A-Za-z0-9]+)|(\"[A-Za-z0-9 ]+\"))")
    try:
        return rex.search(comment)[0].replace("panos_tag=", "").replace('"', "")
    except (KeyError, TypeError):
        raise ValueError("No PanOS tag found")


def is_fqdn(hostname: str) -> bool:
    """Check if the given string is a valid Fully Qualified Domain Name

    Based on: https://codereview.stackexchange.com/a/235478 by Samwise
    License: CC BY-SA 4.0

    Args:
        hostname (str): The string to test

    Returns:
        bool: If the string was a valid FQDN
    """

    if not 1 < len(hostname) < 253:
        return False

    # Remove trailing dot
    if hostname[-1] == ".":
        hostname = hostname[0:-1]

    #  Split hostname into list of DNS labels
    labels = hostname.split(".")

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn = compile(r"^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$", IGNORECASE)

    # Check that all labels match that pattern.
    return all(fqdn.match(label) for label in labels)


def new_panos_fqdn(
    hostname: str,
    tag: str,
    description: str | None = None,
) -> AddressObject:
    """Generate a Fully Qualified Domain Name (FQDN) PanOS address object.

    Args:
        hostname (str): The host the object is for.
        tag (str): The tag to apply to the object.
        description (str | None, optional): A description to add to the object. Defaults to None.

    Raises:
        ValueError: If the data provided is invalid.

    Returns:
        AddressObject: The generated PanOS address object.
    """

    if not is_fqdn(hostname):
        raise ValueError("Hostname is invalid")

    return AddressObject(
        description=description,
        name="{}-fqdn".format(hostname),
        tag=[tag],
        type="fqdn",
        value=hostname.lower(),
    )


def new_panos_ipv4_address(
    hostname: str,
    tag: str,
    ipv4_address: str,
    description: str | None = None,
    sequence_id: int = 1,
) -> AddressObject:
    """Generate an IPv4 PanOS address object.

    Args:
        hostname (str): The host the object is for.
        tag (str): The tag to apply to the object.
        ipv4_address (str): The IPv4 address pointing to the host.
        description (str | None, optional): A description to add to the object. Defaults to None.
        sequence_id (int, optional): A unique ID for hosts with multiple IPv4 addresses. Defaults to 1.

    Raises:
        ValueError: If the data provided is invalid.

    Returns:
        AddressObject: The generated PanOS address object.
    """

    if not is_fqdn(hostname):
        raise ValueError("Hostname is invalid")

    try:
        address = ip_address(ipv4_address)
        if address.version == 4:
            if sequence_id == 1:
                return AddressObject(
                    description=description,
                    name="{}-v4".format(hostname),
                    tag=[tag],
                    type="ip-netmask",
                    value="{}/32".format(address.compressed),
                )
            else:
                return AddressObject(
                    description=description,
                    name="{}-v4_{}".format(hostname, sequence_id),
                    tag=[tag],
                    type="ip-netmask",
                    value="{}/32".format(address.compressed),
                )
        else:
            raise ValueError("Bad IP Family")
    except ValueError:
        raise ValueError("IPv4 address is invalid")


def new_panos_ipv6_address(
    hostname: str,
    tag: str,
    ipv6_address: str,
    description: str | None = None,
    sequence_id: int = 1,
) -> AddressObject:
    """Generate an IPv6 PanOS address object.

    Args:
        hostname (str): The host the object is for.
        tag (str): The tag to apply to the object.
        ipv6_address (str): The IPv6 address pointing to the host.
        description (str | None, optional): A description to add to the object. Defaults to None.
        sequence_id (int, optional): A unique ID for hosts with multiple IPv6 addresses. Defaults to 1.

    Raises:
        ValueError: If the data provided is invalid.

    Returns:
        AddressObject: The generated PanOS address object.
    """

    if not is_fqdn(hostname):
        raise ValueError("Hostname is invalid")

    try:
        address = ip_address(ipv6_address)
        if address.version == 6:
            if sequence_id == 1:
                return AddressObject(
                    description=description,
                    name="{}-v6".format(hostname),
                    tag=[tag],
                    type="ip-netmask",
                    value="{}/128".format(address.compressed),
                )
            else:
                return AddressObject(
                    description=description,
                    name="{}-v6_{}".format(hostname, sequence_id),
                    tag=[tag],
                    type="ip-netmask",
                    value="{}/128".format(address.compressed),
                )
        else:
            raise ValueError("Bad IP Family")
    except ValueError:
        raise ValueError("IPv6 address is invalid")


def new_panos_group(
    hostname: str,
    tag: str,
    description: str | None = None,
    ipv4_addresses: List[str] | None = None,
    ipv6_addresses: List[str] | None = None,
) -> tuple[AddressGroup, List[AddressObject]]:
    """Generate the PanOS objects for the given host.

    Args:
        hostname (str): The host the objects will be for.
        tag (str): The tag to apply to the hosts objects.
        description (str | None, optional): A description to add to the objects. Defaults to None.
        ipv4_addresses (List[str] | None, optional): The IPv4 addresses associated with the host. Defaults to None.
        ipv6_addresses (List[str] | None, optional): The IPv6 addresses associated with the host. Defaults to None.

    Raises:
        ValueError: If object generation fails.

    Returns:
        tuple[AddressGroup, List[AddressObject]]: An address group and list of address objects for the host.
    """

    objects = []
    object_names = []

    fqdn_object = new_panos_fqdn(hostname, tag, description)
    object_names.append(fqdn_object.name)
    objects.append(fqdn_object)
    if ipv4_addresses is not None:
        i = 1
        for ipv4_address in ipv4_addresses:
            ipv4_object = new_panos_ipv4_address(
                hostname, tag, ipv4_address, description, i
            )
            object_names.append(ipv4_object.name)
            objects.append(ipv4_object)
            i = i + 1
    if ipv6_addresses is not None:
        i = 1
        for ipv6_address in ipv6_addresses:
            ipv6_object = new_panos_ipv6_address(
                hostname, tag, ipv6_address, description, i
            )
            object_names.append(ipv6_object.name)
            objects.append(ipv6_object)
            i = i + 1

    return (
        AddressGroup(
            description=description,
            dynamic_value=None,
            name=hostname,
            static_value=object_names,
            tag=[tag],
        ),
        objects,
    )


config = ConfigParser()
config.read("bind9_to_panos.conf")
log = CreateLogger(
    "bind9_to_panos",
    LogDirectory=config.get("DEFAULT", "log_to_dir", fallback="/var/log/"),
    Debug=config.getboolean("DEFAULT", "debug", fallback=False),
    Stderr=config.getboolean("DEFAULT", "log_to_screen", fallback=True),
)

log.debug(
    "Connecting to Palo Alto firewall {}".format(config.get("DEFAULT", "hostname"))
)
firewall = Firewall(
    config.get("DEFAULT", "hostname"),
    api_username=config.get("DEFAULT", "username", fallback="admin"),
    api_password=config.get("DEFAULT", "password"),
    vsys=config.get("DEFAULT", "vsys", fallback="vsys1"),
)

firewall.refresh_system_info()
log.info(
    "Connected to {} a {} (Serial: {}) running PanOS v{}".format(
        firewall.hostname, firewall.platform, firewall.serial, firewall.version
    )
)

# TODO Implement lock checking - see https://github.com/PaloAltoNetworks/pan-os-python/issues/495

# throws exception
# if firewall.check_commit_locks() or firewall.check_config_locks():
#     print("lock in place - will not continue")
#     exit()

# doesn't detect locks
# if firewall.commit_locked or firewall.config_locked:
#    print("lock in place - will not continue")
#    exit()

if firewall.pending_changes():
    log.warning("Pending changes on device - will not continue")
    exit()

for zoneName in config.sections():
    try:
        zoneFile = config.get(zoneName, "file")
    except NoOptionError:
        log.error("[{}] Cannot load zone no file specified".format(zoneName))
        continue

    if not isfile(zoneFile):
        log.error(
            "[{}] Cannot load zone from file {}, it does not exist".format(
                zoneName, zoneFile
            )
        )

    log.debug("[{}] Loading from {}".format(zoneName, zoneFile))
    try:
        zone = from_file(zoneFile)
        log.info("[{}] Processing zone".format(zoneName))
    except KeyError:
        log.error("[{}] Cannot load - No $ORIGIN directive".format(zoneName))
        continue
    except NoNS:
        log.error("[{}] Cannot load - No NS resource record".format(zoneName))
        continue
    except NoSOA:
        log.error("[{}] Cannot load - No SOA resource record".format(zoneName))
        continue

    for hostname in zone.nodes:
        host = zone.get_node(hostname)
        tag = config.get("DEFAULT", "tag")
        description = None
        hostname = "{}.{}".format(hostname, zone.origin)[:-1].replace("@.", "")
        log.debug("[{}] Processing {}".format(zoneName, hostname))
        a_records = host.get_rdataset(INTERNET, a_id)
        aaaa_records = host.get_rdataset(INTERNET, aaaa_id)
        if a_records is None and aaaa_records is None:
            log.debug(
                "[{}] {} has no A or AAAA records, skipping it".format(
                    zoneName, hostname
                )
            )
        else:
            ipv4_addresses = None
            if a_records is not None:
                ipv4_addresses = []
                a_record: A
                for a_record in a_records.items:
                    try:
                        description = host_description(a_record.rdcomment)
                    except ValueError:
                        pass
                    try:
                        tag = host_tag(a_record.rdcomment)
                    except ValueError:
                        pass

                    ipv4_addresses.append(a_record.address)

            ipv6_addresses = None
            if aaaa_records is not None:
                ipv6_addresses = []
                aaaa_record: AAAA
                for aaaa_record in aaaa_records.items:
                    try:
                        description = host_description(aaaa_record.rdcomment)
                    except ValueError:
                        pass
                    try:
                        tag = host_tag(aaaa_record.rdcomment)
                    except ValueError:
                        pass

                    ipv6_addresses.append(aaaa_record.address)

            log.debug("[{}] Generating PanOS objects for {}".format(zoneName, hostname))
            try:
                address_group, address_objects = new_panos_group(
                    hostname, tag, description, ipv4_addresses, ipv6_addresses
                )
            except ValueError as e:
                log.error(
                    "[{}] Failed to generate PanOS objects for {}: {}".format(
                        zoneName, hostname, e
                    )
                )

            for address_object in address_objects:
                search_object = AddressObject(name=address_object.name)
                firewall.add(search_object)
                try:
                    search_object.refresh()
                except PanObjectMissing:
                    log.debug("[{}] {} is new".format(zoneName, address_object.name))
                    firewall.add(address_object)
                    address_object.apply()
                else:
                    if (
                        address_object.description == search_object.description
                        and address_object.name == search_object.name
                        and address_object.tag == search_object.tag
                        and address_object.type == search_object.type
                        and address_object.value == search_object.value
                    ):
                        log.debug(
                            "[{}] {} has not changed".format(
                                zoneName, address_object.name
                            )
                        )
                    else:
                        log.debug(
                            "[{}] {} has changed, updating".format(
                                zoneName, address_object.name
                            )
                        )
                        firewall.add(address_object)
                        address_object.apply()

            search_group = AddressGroup(name=address_group.name)
            firewall.add(search_group)
            try:
                search_group.refresh()
            except PanObjectMissing:
                log.debug("[{}] {} is new".format(zoneName, address_group.name))
                firewall.add(address_group)
                address_group.apply()
            else:
                if (
                    address_group.description == search_group.description
                    and address_group.dynamic_value == search_group.dynamic_value
                    and address_group.name == search_group.name
                    and sorted(address_group.static_value)
                    == sorted(search_group.static_value)
                    and address_group.tag == search_group.tag
                ):
                    log.debug(
                        "[{}] {} has not changed".format(zoneName, address_group.name)
                    )
                else:
                    log.debug(
                        "[{}] {} has changed, updating".format(
                            zoneName, address_group.name
                        )
                    )
                    firewall.add(address_group)
                    address_group.apply()

log.debug("Checking if changes need to be committed")
if firewall.pending_changes():
    log.info("Changes made, committing...")
    commit_result = firewall.commit_policy_and_objects(True)
    if commit_result["success"]:
        log.info("Committed successfully")
        if len(commit_result["messages"]) > 0:
            for message in commit_result["messages"]:
                if message not in [
                    "Partial changes to commit: changes to configuration by all administrators",
                    "Changes to policy and objects configuration",
                    "Configuration committed successfully",
                ]:
                    log.warning(message)
    else:
        log.critical("Committed failed")
        if len(commit_result["messages"]) > 0:
            for message in commit_result["messages"]:
                log.error("Error: {}".format(message))
else:
    log.info("Address objects and groups are already up to date")
