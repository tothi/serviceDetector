#!/usr/bin/env python3
#
# serviceDetector.py: Detect whether a service is installed (blindly) and/or running (if exposing named pipes) on a remote machine without using local admin privileges.
#
# This script implements two types of detections:
#
# 1.) detect whether a service is installed or not on a remote machine
#     using [MS-LSAT] LsarLookupNames (~advapi32.dll:LsaLoopupNames)
#
# 2.) detect whether a process (with a named pipe connected) is running or not
#     on a remote machine by enumerating the named pipes
#
# NOTE: none of the above requires privileged account!
#
# EXAMPLE USE CASES:
#
#   - enumerate WebClient service (see conf/webclient.json)
#   - enumerate AV/EDRs (see conf/edr.json)
#   - enumerate Impacket PsExec (see conf/psexec.json)
#
# ACKNOWLEDMENTS:
#
# detection #1 was inspired by the Antivirusscanner module of PingCastle by Vincent Le Toux (@mysmartlogon)
# detection #2 was inspired by a Twitter post by Lee Christensen (@tifkin_) using this for WebClient service
#

from __future__ import division
from __future__ import print_function

from impacket.dcerpc.v5 import lsat, lsad
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, RPC_UNICODE_STRING
from impacket.dcerpc.v5 import transport, epm

from impacket.smbconnection import SMBConnection

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target

import sys
import argparse
import logging
import json
import pathlib

class COLORS:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    PURPLE = '\033[95m'

class LsaLookupNames():
    timeout = None
    authn_level = None
    protocol = None
    transfer_syntax = None
    machine_account = False

    iface_uuid = lsat.MSRPC_UUID_LSAT
    authn = True

    lmhash = ""
    nthash = ""

    def __init__(self, domain="", username="", password="", remoteName="", k=False, kdcHost="", lmhash="", nthash=""):
        self.domain = domain
        self.username = username
        self.password = password
        self.remoteName = remoteName
        self.string_binding = r"ncacn_np:{}[\PIPE\lsarpc]".format(remoteName)
        self.doKerberos = k
        self.lmhash = lmhash
        self.nthash = nthash
        self.dcHost = kdcHost

    def connect(self, string_binding=None, iface_uuid=None):
        """Obtains a RPC Transport and a DCE interface according to the bindings and
        transfer syntax specified.

        :return: tuple of DCE/RPC and RPC Transport objects
        :rtype: (DCERPC_v5, DCERPCTransport)
        """
        string_binding = string_binding or self.string_binding
        if not string_binding:
            raise NotImplemented("String binding must be defined")

        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        # Set timeout if defined
        if self.timeout:
            rpc_transport.set_connect_timeout(self.timeout)

        # Authenticate if specified
        if self.authn and hasattr(rpc_transport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

        if self.doKerberos:
            rpc_transport.set_kerberos(self.doKerberos, kdcHost=self.dcHost)

        # Gets the DCE RPC object
        dce = rpc_transport.get_dce_rpc()

        # Set the authentication level
        if self.authn_level:
            dce.set_auth_level(self.authn_level)

        # Connect
        dce.connect()

        # Bind if specified
        iface_uuid = iface_uuid or self.iface_uuid
        if iface_uuid and self.transfer_syntax:
            dce.bind(iface_uuid, transfer_syntax=self.transfer_syntax)
        elif iface_uuid:
            dce.bind(iface_uuid)

        return dce, rpc_transport


    def open_policy(self, dce):
        request = lsad.LsarOpenPolicy2()
        request['SystemName'] = NULL
        request['ObjectAttributes']['RootDirectory'] = NULL
        request['ObjectAttributes']['ObjectName'] = NULL
        request['ObjectAttributes']['SecurityDescriptor'] = NULL
        request['ObjectAttributes']['SecurityQualityOfService'] = NULL
        request['DesiredAccess'] = MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES
        resp = dce.request(request)
        return resp['PolicyHandle']


    def LsarLookupNames(self, policyHandle, service):
        request = lsat.LsarLookupNames()
        request['PolicyHandle'] = policyHandle
        request['Count'] = 1
        name1 = RPC_UNICODE_STRING()
        name1['Data'] = 'NT Service\{}'.format(service)
        request['Names'].append(name1)
        request['TranslatedSids']['Sids'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        resp = dce.request(request)
        return resp


def dump_results(results, remoteName, success):
    out1 = "On host {}{}{} found".format(COLORS.BOLD, remoteName, COLORS.ENDC)
    for item in results:
        out = out1
        if 'services' in results[item]:
            out += " {}{}{} {}INSTALLED{}".format(COLORS.GREEN, item, COLORS.ENDC, COLORS.YELLOW, COLORS.ENDC)
            if 'pipes' in results[item]:
                out += " and it seems to be {}RUNNING{}".format(COLORS.RED, COLORS.ENDC)
            else:
                for product in conf['products']:
                    if (item == product['name']) and (len(product['pipes']) == 0):
                        out += " (NamedPipe for this service was not provided in config)"
        elif 'pipes' in results[item]:
            out += " {}{}{} {}RUNNING{}".format(COLORS.GREEN, item, COLORS.ENDC, COLORS.RED, COLORS.ENDC)
        print(out)
    if (len(results) < 1) and (success > 1):
        out = out1 + " {}NOTHING!{}".format(COLORS.PURPLE, COLORS.ENDC)
        print(out)

# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    parser = argparse.ArgumentParser(add_help = True,
                                     description = "Detect whether a service is installed (blindly) and/or running (if exposing named pipes) on a remote machine without using local admin privileges. ")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-conf', metavar='JSON config', action='store', help='JSON config defining '
                                            'services and named pipes (default: conf/edr.json)')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if options.conf is None:
        conffile = "conf/edr.json"
    else:
        conffile = options.conf

    with open(conffile, 'r') as f:
        conf = json.load(f)

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.target_ip is None:
        options.target_ip = remoteName

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    success = 0
    results = {}
    logging.debug("Detecting installed services on {} using LsarLookupNames()...".format(remoteName))
    try:
        lsa = LsaLookupNames(domain, username, password, remoteName, options.k, options.dc_ip, lmhash, nthash)
        dce, rpctransport = lsa.connect()
        policyHandle = lsa.open_policy(dce)

        for i, product in enumerate(conf['products']):
            for service in product['services']:
                try:
                    lsa.LsarLookupNames(policyHandle, service['name'])
                    logging.debug("Detected {}installed{} service on {}: {}{}{} ({})".format(COLORS.YELLOW, COLORS.ENDC, remoteName, COLORS.GREEN, product['name'], COLORS.ENDC, service['description']))
                    if product['name'] not in results:
                        results[product['name']] = {"services": []}
                    results[product['name']]['services'].append(service)
                except:
                    pass
        success += 1
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)

    logging.debug("Detecting running processes on {} by enumerating pipes...".format(remoteName))
    try:
        smbClient = SMBConnection(remoteName, remoteName)
        if options.k:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip)
        else:
            smbClient.login(username, password, domain, lmhash, nthash)
        for f in smbClient.listPath('IPC$', '\\*'):
            fl = f.get_longname()
            for i, product in enumerate(conf['products']):
                for pipe in product['pipes']:
                   if pathlib.PurePath(fl).match(pipe['name']):
                        logging.debug("{}{}{} {}running{} claim found on {} by existing pipe {} (likely processes: {})".format(COLORS.GREEN, product['name'], COLORS.ENDC, COLORS.YELLOW, COLORS.ENDC, remoteName, fl, pipe['processes']))
                        if product['name'] not in results:
                            results[product['name']] = {}
                        if "pipes" not in results[product['name']]:
                            results[product['name']]['pipes'] = []
                        results[product['name']]['pipes'].append(pipe)
        success += 1
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)

    # print(json.dumps(results, indent=2))
    dump_results(results, remoteName, success)

