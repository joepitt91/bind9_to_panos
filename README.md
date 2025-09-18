<!--
SPDX-FileCopyrightText: 2024 Joe Pitt

SPDX-License-Identifier: GPL-3.0-only
-->
# Bind9 to PAN-OS

Load bind9 zone files into a PAN-OS firewall as address and address group objects.

Creates `{hostname}-fqdn`, `{hostname}-v4`, `{hostname}-v6` (and `{hostname}-v4_{n}` /
`{hostname}-v6_{n}` for hosts with multiple IPv4 and / or IPv6 addresses) address objects and a
`{hostname}` address group per host in the zone file.

Parses inline comments for a tag (`panos_tag=`) and descriptions (`panos_desc=`), these can appear
anywhere in the comments. Values with spaces are supported but must be quoted. Tags must already
exist on the PAN-OS device.

For example:

```
example         IN  A   10.10.10.10 ; some comment panos_tag=trust panos_Desc="box that does things"
```

**NOTE:** Updates to IPs, `panos_tag`, or `panos_desc` will be propagated to the PAN-OS device on
next run, however, renamed or deleted hosts will **not** be removed from PAN-OS, this must be done
manually.

## Requirements

* Python 3.9 to 3.12 on Linux, macOS, or Windows,
* PIP Module `dnspython`, and
* PIP Module `pan-os-python`.

## Setup

1. Copy the project to the bind server, or another host with access to the zone files.
2. Create a virtual environment: `python3 -m venv venv ; source venv/bin/activate`.
3. Install the dependencies: `pip3 install -r ./requirements.txt`.
4. Create a configuration file: `cp example.conf bind9_to_panos.conf`.
5. Restrict access to the configuration file: `chmod 600 bind9_to_panos.conf`.
6. Edit the `DEFAULT` section of `bind9_to_panos.conf` to point to your firewall.
7. Edit the `example.tld` section of `bind9_to_panos.conf` to point to the zone file.
8. (Optional) Add additional sections for other zone files.
9. Run the script: `python3 bind9_to_panos.py`.
10. (Optional) Add a cron job to run the script periodically:
    1. Disable printing to screen by setting `log_to_screen` to `False` in `bind9_to_panos.conf`.
    2. Open the crontab for the desired users: `sudo crontab -u <username> -e`. 
        * Use a low privilege user that can read the zone files, avoid `root` and `named`.
    3. Add the cron job to the file on the desired schedule (04:00 daily in this example):
        `0 4 * * * /path/to/venv/bin/python3 /path/to/bind9_to_panos.py`.
