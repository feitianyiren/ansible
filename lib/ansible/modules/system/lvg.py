#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013, Alexander Bulimov <lazywolf0@gmail.com>
# based on lvol module by Jeroen Hoekx <jeroen.hoekx@dsquare.be>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
author: "Alexander Bulimov (@abulimov)"
module: lvg
short_description: Configure LVM volume groups
description:
  - This module creates, removes or resizes volume groups.
version_added: "1.1"
options:
  vg:
    description:
    - The name of the volume group.
    required: true
  pvs:
    description:
    - List of comma-separated devices to use as physical devices in this volume group. Required when creating or resizing volume group.
    - The module will take care of running pvcreate if needed.
    required: false
  pesize:
    description:
    - The size of the physical extent in megabytes. Must be a power of 2.
    default: 4
    required: false
  vg_options:
    description:
    - Additional options to pass to C(vgcreate) when creating the volume group.
    default: null
    required: false
    version_added: "1.6"
  state:
    choices: [ "present", "absent" ]
    default: present
    description:
    - Control if the volume group exists.
    required: false
  force:
    choices: [ "yes", "no" ]
    default: "no"
    description:
    - If yes, allows to remove volume group with logical volumes.
    required: false
notes:
  - module does not modify PE size for already present volume group
'''

EXAMPLES = '''
# Create a volume group on top of /dev/sda1 with physical extent size = 32MB.
- lvg:
    vg: vg.services
    pvs: /dev/sda1
    pesize: 32

# Create or resize a volume group on top of /dev/sdb1 and /dev/sdc5.
# If, for example, we already have VG vg.services on top of /dev/sdb1,
# this VG will be extended by /dev/sdc5.  Or if vg.services was created on
# top of /dev/sda5, we first extend it with /dev/sdb1 and /dev/sdc5,
# and then reduce by /dev/sda5.
- lvg:
    vg: vg.services
    pvs: /dev/sdb1,/dev/sdc5

# Remove a volume group with name vg.services.
- lvg:
    vg: vg.services
    state: absent
'''
import os

from ansible.module_utils.basic import AnsibleModule


def parse_vgs(data):
    vgs = []
    for line in data.splitlines():
        parts = line.strip().split(';')
        vgs.append({
            'name': parts[0],
            'pv_count': int(parts[1]),
            'lv_count': int(parts[2]),
        })
    return vgs

def find_mapper_device_name(module, dm_device):
    dmsetup_cmd = module.get_bin_path('dmsetup', True)
    mapper_prefix = '/dev/mapper/'
    rc, dm_name, err = module.run_command("%s info -C --noheadings -o name %s" % (dmsetup_cmd, dm_device))
    if rc != 0:
        module.fail_json(msg="Failed executing dmsetup command.", rc=rc, err=err)
    mapper_device = mapper_prefix + dm_name.rstrip()
    return mapper_device

def parse_pvs(module, data):
    pvs = []
    dm_prefix = '/dev/dm-'
    for line in data.splitlines():
        parts = line.strip().split(';')
        if parts[0].startswith(dm_prefix):
            parts[0] = find_mapper_device_name(module, parts[0])
        pvs.append({
            'name': parts[0],
            'vg_name': parts[1],
        })
    return pvs

def main():
    module = AnsibleModule(
        argument_spec = dict(
            vg=dict(required=True),
            pvs=dict(type='list'),
            pesize=dict(type='int', default=4),
            vg_options=dict(default=''),
            state=dict(choices=["absent", "present"], default='present'),
            force=dict(type='bool', default='no'),
        ),
        supports_check_mode=True,
    )

    vg = module.params['vg']
    state = module.params['state']
    force = module.boolean(module.params['force'])
    pesize = module.params['pesize']
    vgoptions = module.params['vg_options'].split()

    dev_list = []
    if module.params['pvs']:
        dev_list = module.params['pvs']
    elif state == 'present':
        module.fail_json(msg="No physical volumes given.")

    # LVM always uses real paths not symlinks so replace symlinks with actual path
    for idx, dev in enumerate(dev_list):
        dev_list[idx] = os.path.realpath(dev)

    if state=='present':
        ### check given devices
        for test_dev in dev_list:
            if not os.path.exists(test_dev):
                module.fail_json(msg="Device %s not found."%test_dev)

        ### get pv list
        pvs_cmd = module.get_bin_path('pvs', True)
        rc,current_pvs,err = module.run_command("%s --noheadings -o pv_name,vg_name --separator ';'" % pvs_cmd)
        if rc != 0:
            module.fail_json(msg="Failed executing pvs command.",rc=rc, err=err)

        ### check pv for devices
        pvs = parse_pvs(module, current_pvs)
        used_pvs = [ pv for pv in pvs if pv['name'] in dev_list and pv['vg_name'] and pv['vg_name'] != vg ]
        if used_pvs:
            module.fail_json(msg="Device %s is already in %s volume group."%(used_pvs[0]['name'],used_pvs[0]['vg_name']))

    vgs_cmd = module.get_bin_path('vgs', True)
    rc,current_vgs,err = module.run_command("%s --noheadings -o vg_name,pv_count,lv_count --separator ';'" % vgs_cmd)

    if rc != 0:
        module.fail_json(msg="Failed executing vgs command.",rc=rc, err=err)

    changed = False

    vgs = parse_vgs(current_vgs)

    for test_vg in vgs:
        if test_vg['name'] == vg:
            this_vg = test_vg
            break
    else:
        this_vg = None

    if this_vg is None:
        if state == 'present':
            ### create VG
            if module.check_mode:
                changed = True
            else:
                ### create PV
                pvcreate_cmd = module.get_bin_path('pvcreate', True)
                for current_dev in dev_list:
                    rc,_,err = module.run_command("%s -f %s" % (pvcreate_cmd,current_dev))
                    if rc == 0:
                        changed = True
                    else:
                        module.fail_json(msg="Creating physical volume '%s' failed" % current_dev, rc=rc, err=err)
                vgcreate_cmd = module.get_bin_path('vgcreate')
                rc,_,err = module.run_command([vgcreate_cmd] + vgoptions + ['-s', str(pesize), vg] + dev_list)
                if rc == 0:
                    changed = True
                else:
                    module.fail_json(msg="Creating volume group '%s' failed"%vg, rc=rc, err=err)
    else:
        if state == 'absent':
            if module.check_mode:
                module.exit_json(changed=True)
            else:
                if this_vg['lv_count'] == 0 or force:
                    ### remove VG
                    vgremove_cmd = module.get_bin_path('vgremove', True)
                    rc,_,err = module.run_command("%s --force %s" % (vgremove_cmd, vg))
                    if rc == 0:
                        module.exit_json(changed=True)
                    else:
                        module.fail_json(msg="Failed to remove volume group %s"%(vg),rc=rc, err=err)
                else:
                    module.fail_json(msg="Refuse to remove non-empty volume group %s without force=yes"%(vg))

        ### resize VG
        current_devs = [ os.path.realpath(pv['name']) for pv in pvs if pv['vg_name'] == vg ]
        devs_to_remove = list(set(current_devs) - set(dev_list))
        devs_to_add = list(set(dev_list) - set(current_devs))

        if devs_to_add or devs_to_remove:
            if module.check_mode:
                changed = True
            else:
                if devs_to_add:
                    devs_to_add_string = ' '.join(devs_to_add)
                    ### create PV
                    pvcreate_cmd = module.get_bin_path('pvcreate', True)
                    for current_dev in devs_to_add:
                        rc,_,err = module.run_command("%s -f %s" % (pvcreate_cmd, current_dev))
                        if rc == 0:
                            changed = True
                        else:
                            module.fail_json(msg="Creating physical volume '%s' failed"%current_dev, rc=rc, err=err)
                    ### add PV to our VG
                    vgextend_cmd = module.get_bin_path('vgextend', True)
                    rc,_,err = module.run_command("%s %s %s" % (vgextend_cmd, vg, devs_to_add_string))
                    if rc == 0:
                        changed = True
                    else:
                        module.fail_json(msg="Unable to extend %s by %s."%(vg, devs_to_add_string),rc=rc,err=err)

                ### remove some PV from our VG
                if devs_to_remove:
                    devs_to_remove_string = ' '.join(devs_to_remove)
                    vgreduce_cmd = module.get_bin_path('vgreduce', True)
                    rc,_,err = module.run_command("%s --force %s %s" % (vgreduce_cmd, vg, devs_to_remove_string))
                    if rc == 0:
                        changed = True
                    else:
                        module.fail_json(msg="Unable to reduce %s by %s."%(vg, devs_to_remove_string),rc=rc,err=err)

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
