#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, VMware, Inc.
# Author(s): Yasen Simeonov <simeonovy@vmware.com>
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.


ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}
  
DOCUMENTATION = '''
---
module: vmware_deploy_ova
short_description: Deploy OVA with different properties
description:
    - Encodes different properties to OVF
    - Deploys to vCenter
author: "Yasen Simeonov <simeonovy@vmware.com>"
version_added: "2.4"
notes:
    - Tested on vSphere 6.0 and 6.5
requirements:
    - "python >= 2.7"
    - PyVmomi
options:
    check_mode:
        if run in check_mode it will list all additional OVF properties that can be included in parameters section
    datacenter: 
        description:
            - Name of the Datacenter in vSphere where the OVA will be deployed
        required: True
    datastore: 
        description:
            - Name of the Datastore in vSphere where the OVA will be deployed
        required: True
    portgroup: 
        description:
            - Name of the portgroup in vSphere where the OVA VM will be attached to
        required: True
    cluster: 
        description:
            - Name of the Cluster in vSphere where the OVA will be deployed
        required: True
    vmname: 
        description:
            - Name of the VM in vSphere
        required: True
    hostname: 
        description:
            - vCenter ip address or hostname
        required: True
    username:
        description:
            - vCenter username
        required: True 
    password: 
        description:
            - vCenter password
        required: True
    properties:
        description:
            - Multiple additional properties specified in OVF. Run in check mode with -vvv to see all possible properties.
        required: False
    path_to_ova: 
        description:
            - Path to the folder where the OVA is located
        required: True
    ova_file: 
        description:
            - Name of the OVA file
        required: True

extends_documentation_fragment: vmware.documentation
'''

EXAMPLES = '''
- name: Show additional OVF properties
  vmware_deploy_ova:
    datacenter: "{{ deployDataCenterName }}"
    datastore: "{{ deployMgmtDatastoreName}}"
    portgroup: "{{ deployMgmtPortGroup }}"
    cluster: "{{ deployCluster }}"
    vmname: "{{ deployVmName }}"
    hostname: "{{ deployVcIPAddress }}"
    username: "admin"
    password: 'SuperSecretPassword'
    path_to_ova: '/user/OVAs'
    ova_file: 'myFile.ova'
    check_mode: yes
    
- name: deploy OVA
  vmware_deploy_ova:
    datacenter: "{{ deployDataCenterName }}"
    datastore: "{{ deployMgmtDatastoreName}}"
    portgroup: "{{ deployMgmtPortGroup }}"
    cluster: "{{ deployCluster }}"
    vmname: "{{ deployVmName }}"
    hostname: "{{ deployVcIPAddress }}"
    username: "{{ deployVcUser }}"
    password: "{{ deployVcPassword }}"
    properties:
      vsm_isSSHEnabled: True
      vsm_isCEIPEnabled: False
      vsm_hostname: "myVMfromOva"
      vsm_dns1_0: "10.29.12.201"
      vsm_ntp_0: "10.29.12.201"
      vsm_domain_0: "yasen.local"
      vsm_gateway_0: "10.29.121.1"
      vsm_ip_0: "10.29.121.2"
      vsm_netmask_0: "255.255.255.252"
      vsm_cli_passwd_0: "SecretPass!"
      vsm_cli_en_passwd_0: "SecretPass"
    path_to_ova: "{{ OvaPath }}"
    ova_file: "{{ myOva }}"
'''
__author__ = 'yasensim'

import os, tarfile, requests, ssl, sys, time
from threading import Timer
from six.moves.urllib.request import Request, urlopen
from xml.dom import minidom
try:
    from pyVmomi import vim, vmodl
    from pyVim import connect
    HAS_PYVMOMI = True
except ImportError:
    HAS_PYVMOMI = False


class OvfHandler(object):
    def __init__(self, ovafile):
        self.handle = self._create_file_handle(ovafile)
        self.tarfile = tarfile.open(fileobj=self.handle)
        ovffilename = list(filter(lambda x: x.endswith(".ovf"),
                                  self.tarfile.getnames()))[0]
        ovffile = self.tarfile.extractfile(ovffilename)
        self.descriptor = ovffile.read().decode()

    def _create_file_handle(self, entry):
        if os.path.exists(entry):
            return FileHandle(entry)
        else:
            return WebHandle(entry)

    def get_descriptor(self):
        return self.descriptor
    def get_spec(self):
        return self.spec

    def set_spec(self, spec):
        self.spec = spec

    def get_disk(self, fileItem, lease):
        ovffilename = list(filter(lambda x: x == fileItem.path,
                                  self.tarfile.getnames()))[0]
        return self.tarfile.extractfile(ovffilename)

    def get_device_url(self, fileItem, lease):
        for deviceUrl in lease.info.deviceUrl:
            if deviceUrl.importKey == fileItem.deviceId:
                return deviceUrl
        raise Exception("Failed to find deviceUrl for file %s" % fileItem.path)

    def upload_disks(self, lease, host):
        self.lease = lease
        try:
            self.start_timer()
            for fileItem in self.spec.fileItem:
                self.upload_disk(fileItem, lease, host)
            lease.Complete()
            return "success"
        except vmodl.MethodFault as e:
            lease.Abort(e)
        except Exception as e:
            lease.Abort(vmodl.fault.SystemError(reason=str(e)))
            raise
        return "success"

    def upload_disk(self, fileItem, lease, host):
        ovffile = self.get_disk(fileItem, lease)
        if ovffile is None:
            return
        deviceUrl = self.get_device_url(fileItem, lease)
        url = deviceUrl.url.replace('*', host)
        headers = {'Content-length': get_tarfile_size(ovffile)}
        if hasattr(ssl, '_create_unverified_context'):
            sslContext = ssl._create_unverified_context()
        else:
            sslContext = None
        req = Request(url, ovffile, headers)
        urlopen(req)

    def start_timer(self):
        Timer(5, self.timer).start()

    def timer(self):
        try:
            prog = self.handle.progress()
            self.lease.Progress(prog)
            if self.lease.state not in [vim.HttpNfcLease.State.done,
                                        vim.HttpNfcLease.State.error]:
                self.start_timer()
            sys.stderr.write("Progress: %d%%\r" % prog)
        except:  
            pass


class FileHandle(object):
    def __init__(self, filename):
        self.filename = filename
        self.fh = open(filename, 'rb')

        self.st_size = os.stat(filename).st_size
        self.offset = 0

    def __del__(self):
        self.fh.close()

    def tell(self):
        return self.fh.tell()

    def seek(self, offset, whence=0):
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            self.offset = self.st_size - offset

        return self.fh.seek(offset, whence)

    def seekable(self):
        return True

    def read(self, amount):
        self.offset += amount
        result = self.fh.read(amount)
        return result

    def progress(self):
        return int(100.0 * self.offset / self.st_size)


class WebHandle(object):
    def __init__(self, url):
        self.url = url
        r = urlopen(url)
        if r.code != 200:
            raise FileNotFoundError(url)
        self.headers = self._headers_to_dict(r)
        if 'accept-ranges' not in self.headers:
            raise Exception("Site does not accept ranges")
        self.st_size = int(self.headers['content-length'])
        self.offset = 0

    def _headers_to_dict(self, r):
        result = {}
        if hasattr(r, 'getheaders'):
            for n, v in r.getheaders():
                result[n.lower()] = v.strip()
        else:
            for line in r.info().headers:
                if line.find(':') != -1:
                    n, v = line.split(': ', 1)
                    result[n.lower()] = v.strip()
        return result

    def tell(self):
        return self.offset

    def seek(self, offset, whence=0):
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            self.offset = self.st_size - offset
        return self.offset

    def seekable(self):
        return True

    def read(self, amount):
        start = self.offset
        end = self.offset + amount - 1
        req = Request(self.url,
                      headers={'Range': 'bytes=%d-%d' % (start, end)})
        r = urlopen(req)
        self.offset += amount
        result = r.read(amount)
        r.close()
        return result

    def progress(self):
        return int(100.0 * self.offset / self.st_size)


def get_obj(content, vimtype, name):
    obj = None
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for view in container.view:
        if view.name == name:
            obj = view
            break
    return obj

def get_obj_in_list(obj_name, obj_list):
    for o in obj_list:
        if o.name == obj_name:
            return o
    print ("Unable to find object by the name of %s in list:\n%s" %
           (o.name, map(lambda o: o.name, obj_list)))
    exit(1)


def get_objects(content, module): 
    datacenter_list = content.rootFolder.childEntity
    if module.params['datacenter']:
	datacenter_obj = find_datacenter_by_name(content, module.params['datacenter'])
    datastore_list = datacenter_obj.datastoreFolder.childEntity
    if module.params['datastore']:
	datastore_obj = find_datastore_by_name(content, module.params['datastore'])
    else:
        print "No datastores found in DC (%s)." % datacenter_obj.name
    cluster_list = datacenter_obj.hostFolder.childEntity
    if module.params['cluster']:
	cluster_obj = find_cluster_by_name(content, module.params['cluster'])
    elif len(cluster_list) > 0:
        cluster_obj = cluster_list[0]
    else:
        print "No clusters found in DC (%s)." % datacenter_obj.name
    resource_pool_obj = cluster_obj.resourcePool

    return {"datacenter": datacenter_obj,
            "datastore": datastore_obj,
            "resource pool": resource_pool_obj}

def genOvf(ovfkey, ovfvalue, ovfd):
    xmldoc = minidom.parseString(ovfd)
    itemlist = xmldoc.getElementsByTagName('Property')
    check=0
    for s in itemlist:
        if s.attributes['ovf:key'].value == ovfkey:
            s.setAttribute("ovf:value", ovfvalue)
            check=1
    if check==0:
        print "There is NO property {} in the OVF, possible properties are {}".format(ovfkey, getPropertyMap(ovfd))          
    pretty_xml_as_string = xmldoc.toprettyxml()
#    xmlContent = pretty_xml_as_string.encode('ascii', 'ignore')
    return pretty_xml_as_string


def changeNIC(module, content):
    net_moreff = get_obj(content, [vim.Network], module.params['portgroup'])
    vm = get_obj(content, [vim.VirtualMachine], module.params['vmname'])
    print "Net {} VM {}".format(str(net_moreff), str(vm))
    if net_moreff is None:
        invoke_and_track(vm.PowerOn, None)
        sleep(150)
    device_change = []
    for device in vm.config.hardware.device:
        if isinstance(device, vim.vm.device.VirtualEthernetCard):
    	    nicspec = vim.vm.device.VirtualDeviceSpec()
            nicspec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
            nicspec.device = device
            nicspec.device.wakeOnLanEnabled = True
	    if net_moreff is not None:
                nicspec.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
                nicspec.device.backing.network = get_obj(content, [vim.Network], module.params['portgroup'])
                nicspec.device.backing.deviceName = module.params['portgroup']
		nicspec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
		nicspec.device.connectable.startConnected = True
		nicspec.device.connectable.allowGuestControl = True
		device_change.append(nicspec)
	    else:
		network = get_obj(content,[vim.dvs.DistributedVirtualPortgroup], module.params['portgroup'])
    		dvs_port_connection = vim.dvs.PortConnection()
    		dvs_port_connection.portgroupKey = network.key
    		dvs_port_connection.switchUuid = network.config.distributedVirtualSwitch.uuid
    		nicspec.device.backing = vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo()
    		nicspec.device.backing.port = dvs_port_connection
		nicspec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
		nicspec.device.connectable.startConnected = True
		nicspec.device.connectable.allowGuestControl = True
		device_change.append(nicspec)
	    break
    config_spec = vim.vm.ConfigSpec(deviceChange=device_change)
    task = vm.ReconfigVM_Task(config_spec)
    wait_for_task(task)
    invoke_and_track(vm.PowerOn, None)
    return 0

def invoke_and_track(func, *args, **kw):
    try :
        func(*args, **kw)
    except:
        raise

def get_tarfile_size(tarfile):
    if hasattr(tarfile, 'size'):
        return tarfile.size
    size = tarfile.seek(0, 2)
    tarfile.seek(0, 0)
    return size

def upload_ova(module, content):
    ova_path = module.params['path_to_ova'] + "/" + module.params['ova_file']
    ovf_handler = OvfHandler(ova_path)
    ovfManager = content.ovfManager
    objs = get_objects(content, module)
    spec_params = vim.OvfManager.CreateImportSpecParams()
    spec_params.entityName = module.params['vmname']
    ovf_descriptor = ovf_handler.get_descriptor()
    if module.params['properties']:
        for key, value in module.params['properties'].iteritems():
            ovf_descriptor = genOvf(str(key), str(value), ovf_descriptor)
    import_spec = ovfManager.CreateImportSpec(ovf_descriptor,
                                           objs["resource pool"],
                                           objs["datastore"],
                                           spec_params)
    if len(import_spec.error):
        print("The following errors will prevent import of this OVA:")
    for error in import_spec.error:
        print("%s" % error)
        return 1
    ovf_handler.set_spec(import_spec)
    lease = objs["resource pool"].ImportVApp(import_spec.importSpec, objs["datacenter"].vmFolder)
    while lease.state == vim.HttpNfcLease.State.initializing:
        print("Waiting for lease to be ready...")
        time.sleep(1)
    if lease.state == vim.HttpNfcLease.State.error:
        print("Lease error: %s" % lease.error)
        return 1
    if lease.state == vim.HttpNfcLease.State.done:
        return "success"
    print("Starting deploy...")
    ovf_handler.upload_disks(lease, module.params['hostname'])
    print "Start Changing NIC"
    changeNIC(module, content)
    return "success"

def getPropertyMap(module):
    ova_path = module.params['path_to_ova'] + "/" + module.params['ova_file']
    ovf_handler = OvfHandler(ova_path)
    ovf_descriptor = ovf_handler.get_descriptor()
    dom = minidom.parseString(ovf_descriptor)
    section = dom.getElementsByTagName("ProductSection")[0]
    propertyMap = {}
    for property in section.getElementsByTagName("Property"):
	key   = property.getAttribute("ovf:key")
	value = property.getAttribute("ovf:value")
	propertyMap[key] = value
    dom.unlink()
    return str(propertyMap)

def main():

    module = AnsibleModule(
        argument_spec=dict(
            datacenter=dict(required=True, type='str'),
            datastore=dict(required=True, type='str'),
            portgroup=dict(required=True, type='str'),
            cluster=dict(required=True, type='str'),
            vmname=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
            path_to_ova=dict(required=True, type='str'),
            ova_file=dict(required=True, type='str'),
            disk_mode=dict(default='thin'),
            username=dict(required=True, type='str'),
            password=dict(required=True, type='str', no_log=True),
	    validate_certs=dict(type='str'),
	    properties=dict(required=False, type='dict', no_log=True)
        ),
        supports_check_mode=True
    )

    reload(sys)
    sys.setdefaultencoding('utf8')
    requests.packages.urllib3.disable_warnings()
    if not HAS_PYVMOMI:
	module.fail_json(msg='pyvmomi is required for this module')

    if module.check_mode:
        props = getPropertyMap(module)
        module.exit_json(changed=True, msg="OVF Properties that can be used: {}".format(props))


    content = connect_to_api(module)
    nsx_manager_vm = get_obj(content, [vim.VirtualMachine], module.params['vmname'])
    if nsx_manager_vm:
        module.exit_json(changed=False, result='A VM with the name {} is already present!'.format(module.params['vmname']))

    upload_ova(module, content)
    module.exit_json(changed=True, result="OVA deployed successfully !")

from ansible.module_utils.basic import *
from ansible.module_utils.vmware import *

if __name__ == "__main__":
    exit(main())

