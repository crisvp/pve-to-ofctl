### pve-to-ofctl.py: Set OpenFlow flows based on Proxmox VM configuration.

```
2018-02-02 -- Cris van Pelt <cris@melkfl.es>
```

## About

This script is a quick hack. It will monitor (via inotify) your PVE
VM configuration directory and regenerate the entire OpenFlow config
any time anything changes. Far from optimal, but fine for a small number
of VMs and/or few changes.

With the current configuration it is suitable for joining a group of VMs
and fully segregating their traffic and preventing MAC/IP spoofing.

Broadcast traffic is still possible but only between from the configured
router to all hosts, or from a host to only the router.

If you get an error about version negotiation failing run:

```
$ /usr/bin/ovs-ofctl set bridge vmbr0 \
  protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14,OpenFlow15
```

Some basic assumptions I made:
    * We're only using virtio interfaces.
    * PVE will always name its interfaces on the host side tap<vm id>i<net id>.
    * There is only a single router on the network.
    * VMs will never need to talk to one another via this bridge.

## Installation

    * Clone this thing
    * Don't read the README
    * cp pve-to-ofctl.py /usr/local/bin/
    * cp pve-to-ofctl.py /lib/systemd/system/
    * systemctl daemon-reload
    * systemctl enable pve-to-ofctl
    * systemctl start pve-to-ofctl

## Development

Robustness how do:
    * All the error checking. Basically right now the process will just crash.

Feature extension how do:
    * Fancy getopt parameters

Optimize how do:
    * Store the flow configuration in memory.
    * Call generate\_flows() only for the modified object.
