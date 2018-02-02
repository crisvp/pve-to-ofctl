#!/usr/bin/env python3

""" pve-to-ofctl.py: Set OpenFlow flows based on Proxmox VM configuration.

    2018-02-02 -- Cris van Pelt <cris@melkfl.es>
"""

import os
import sys
import re
import io
import time
import logging
import subprocess
import pyinotify

# Configuration goes here because getopt is hard.
BRIDGE = 'vmbr0'
ROUTER_MAC = '1E:C1:83:00:D3:49'
LOGLEVEL = logging.DEBUG
DELAY = 20 # Sleep for this amount of seconds when a change is detected

# You probably don't need to fiddle with this.
PVE_CONF = '/etc/pve/qemu-server'
PVE_RUN = '/var/run/qemu-server'
OFCTL_LIST = '/usr/bin/ovs-ofctl dump-ports-desc'
OFCTL_SET = ['/usr/bin/ovs-ofctl', '--bundle', 'replace-flows']

#table=0,priority=101 in_port={ofport} dl_src={mac} actions=normal
#table=0,priority=100 in_port={ofport} actions=drop

FLOWS = """
## Begin VMID {vmid} net{interface}
table=0,priority=100 in_port={router_ofport} dl_src={router_mac} dl_dst={mac} actions=normal
table=0,priority=100 in_port={router_ofport} dl_src={router_mac} dl_dst=00:01:00:00:00:00/00:01:00:00:00:00 actions=normal
table=0,priority=100 in_port={router_ofport} dl_src={router_mac} dl_dst=33:33:00:00:00:00/33:33:00:00:00:00 actions=normal
table=0,priority=50 in_port={ofport} dl_src={mac} dl_dst={router_mac} actions=normal
table=0,priority=50 in_port={ofport} dl_src={mac} dl_dst=ff:ff:ff:ff:ff:ff actions=output:{router_ofport}
table=0,priority=50 in_port={ofport} dl_src={mac} dl_dst=01:00:00:00:00:00/01:00:00:00:00:00 actions=output:{router_ofport}
table=0,priority=50 in_port={ofport} dl_src={mac} dl_dst=33:33:00:00:00:00/33:33:00:00:00:00 actions=output:{router_ofport}
table=0,priority=0 actions=drop
"""

logger = logging.getLogger(__name__)


def generate_flows(interface, router):
    interface.update({'router_{}'.format(k): v for k, v in router.items()})
    try:
        flows = FLOWS.format(**interface)
    except KeyError:
        return None

    return flows


def all_flows(path):
    config = os.listdir(path)
    interfaces = {}
    snoozed = False

    for c in config:
        m = re.match('(.*)\.conf$', c)
        if not m:
            continue

        if not snoozed:
            time.sleep(DELAY)
            snoozed = True

        vmid = m.group(1)
        interfaces[vmid] = {'vmid': vmid}

        with open(os.path.join(path, c), 'r') as f:
            for line in f.readlines():
                m = re.match('^net([0-9]+): virtio=([0-9A-F:]+).*bridge={}'.format(BRIDGE), line)
                if m:
                    interfaces[vmid]['mac'] = m.group(2).lower()
                    interfaces[vmid]['netid'] = m.group(1)

    vsctl = subprocess.check_output('{} {}'.format(OFCTL_LIST, BRIDGE), shell=True).decode('utf-8')
    logger.debug('vsctl: %s', vsctl)

    lines = vsctl.split('\n')
    for i, line in enumerate(lines):
        m = re.match('^\s*([0-9]+)\(tap([0-9]+)i([0-9]+)\):\s+addr:([a-f0-9:]+)$', line)
        if m:
            ofport = m.group(1)
            vmid = m.group(2)
            interface = m.group(3)
            bridge_mac = m.group(4)

            if vmid not in interfaces:
                interfaces[vmid] = {}

            interfaces[vmid]['interface'] = interface
            interfaces[vmid]['ofport'] = ofport
            logger.debug('Found interface: %s', interfaces[vmid])

    flows = []
    for k, v in interfaces.items():
        f = generate_flows(v, find_by_mac(interfaces, ROUTER_MAC))
        if f:
            flows.append(f)

    return '\n'.join(flows)


def configure_flows(flows):
    logger.debug(flows)

    with io.StringIO(flows) as f:
        p = subprocess.Popen(OFCTL_SET + [BRIDGE, '-'], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = p.communicate(bytes(f.read(), 'utf-8'))
        rc = p.wait()
        logger.debug('ofctl: rc: %d, stdout: %s, stderr: %s', rc, out.decode('utf-8'), err.decode('utf-8'))
        if rc > 0:
            logger.error('ofctl returned a non-zero exitcode: %d', rc)
        if err:
            logger.warn('ofctl: %s', err)

    return rc


def find_by_mac(interfaces, mac):
    for k, v in interfaces.items():
        if 'mac' in v and v['mac'].lower() == mac.lower():
            return v

    return None


class NotifyHandler(pyinotify.ProcessEvent):
    def process_IN_CLOSE_WRITE(self, event):
        self.process(event)

    def process_IN_DELETE(self, event):
        self.process(event)

    def process(self, event):
        if not re.match('^[0-9]+\.(conf|pid)$', event.name):
            return

        flows = all_flows(event.path)
        logger.info('{} modified or deleted. regenerated flows'.format(event.name))

        configure_flows(flows)


if __name__ == '__main__':
    sh = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    sh.setFormatter(formatter)
    logger.setLevel(LOGLEVEL)
    logger.addHandler(sh)

    flows = all_flows(PVE_CONF)
    configure_flows(flows)

    wm = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(wm, NotifyHandler())
    wm.add_watch(PVE_CONF, pyinotify.IN_CLOSE_WRITE | pyinotify.IN_DELETE, rec=True, auto_add=True)
    wm.add_watch(PVE_RUN, pyinotify.IN_CLOSE_WRITE | pyinotify.IN_DELETE, rec=True, auto_add=True)
    notifier.loop()
