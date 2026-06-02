#aci-protocol-builder
#!/usr/bin/python

import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.pol
import cobra.model.fabric
import cobra.model.infra
import cobra.model.rtctrl
import cobra.model.cdp
import cobra.model.lldp
import cobra.model.lacp
import cobra.model.stp
import cobra.model.mcp
import cobra.model.phys
import cobra.model.aaa
import cobra.model.fv
import cobra.model.fvns
import cobra.model.ip
import cobra.model.l3ext
import cobra.model.dhcp
import cobra.model.vns
import cobra.model.nd
import cobra.model.vz
import cobra.model.tag
import cobra.model.bfd
import cobra.model.eigrp
import cobra.model.ospf
import cobra.model.bgp
import cobra.model.pim

from datetime import datetime
from ping3 import ping, verbose_ping
from aci_model import *
import argparse
import getpass
import requests
import sys
import os.path
import re
import time

VERSION = '0.01'
NODEPROFILE = 0
PROFILENAME = 0
ATTRIBUTE = 1
LINE = 1
RESULT = 0

comment = r'^#.*'
newline = r'^\n'
verbose = False

_RE_MULTI_SEMICOLON = re.compile(r';{2,}')
_RE_MAC_ADDRESS     = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
_RE_ILLEGAL_CHAR    = re.compile(r'([!@#$%^&*()<>?\'"{[}\]|\\`~]+)')
_RE_EMPTY_LLADDR    = re.compile(r';llAddr:::')
_RE_EMPTY_MAC       = re.compile(r';mac:::')
_RE_URL_FORMAT      = re.compile(r'^\s*https://.*')

profiles = {}

profiles['tenant'] = []

profiles['domain'] = []
profiles['aaep'] = []
profiles['vlanPool'] = []
profiles['vlanPoolRange'] = []

profiles['application-profile'] = []
profiles['security'] = []
profiles['epg'] = []
profiles['bridge-domain'] = []
profiles['vrf'] = []
profiles['protocolPolicy'] = []

#stores bridge-domain links to l3out
profiles['bridgeDomainLink'] = []

profiles['l3out'] = []
profiles['l3OutProtocol'] = []
profiles['nodeProfile'] = []
profiles['intProfile'] = []
profiles['intProtocol'] = []
profiles['routeMap'] = []
profiles['staticRoute'] = []
profiles['networks'] = []
profiles['subnets'] = []
profiles['BGPPeer'] = []
profiles['l3OutRouteMap'] = []
profiles['routeMapMatch'] = []
profiles['routeMapRules'] = []

profiles['subnet'] = []
profiles['dhcpRelayLabel'] = []
profiles['dhcpOptionPolicy'] = []
profiles['dhcpOption'] = []

profiles['ndProxySubnet'] = []

profiles['switch'] = []
profiles['switchPolicy'] = []
profiles['switchProfile'] = []
profiles['interface'] = []
profiles['global'] = []

#removes whitespace and newlines surrounding string
def clean_input(string):
    tempString = string
    tempString = tempString.strip().replace('\n', '')
    return tempString

def is_valid_file(file):
    valid = None
    if os.path.isfile(file):
        valid = True
    return valid

def parse_args():
    parser = argparse.ArgumentParser(description='Configure an ACI APIC instance based off a provided input build file.')
    parser.add_argument('--in_file', required=True, help='Input file for APIC configuration.')
    parser.add_argument('--url', required=False, help='URL to the APIC instance')
    parser.add_argument('--user', required=False, help='Username for APIC access')
    parser.add_argument('--validate', action='store_true', required=False, help='Verifies if build file is valid and outlines located errors')
    parser.add_argument('--verbose', required=False, action='store_true', help='Verbose logging output.')
    args = parser.parse_args()

    valid_file = is_valid_file(str(args.in_file))
    print()
    if not valid_file:
        print('ERROR: Unable to find input file:', args.in_file)
        print('Exiting program.')
        sys.exit(1)

    if not args.validate:
        if not args.user:
            print('STATUS: Using default user account admin for profile push.')
            args.user = 'admin'
        if not args.url:
            print('ERROR: --url is required when not running in --validate mode.')
            sys.exit(1)
        if re.match(_RE_URL_FORMAT, args.url):
            print('STATUS: Valid URL found:', args.url)
        else:
            args.url = 'https://' + args.url
            print('STATUS: Appending protocol prefix to provided APIC host:', args.url)

    return args


def buildfile_check_clean(line, line_count):
    line_check = [True, line.rstrip('\n')]

    # Strip empty special-case fields before duplicate-delimiter cleaning.
    # These use '::' as an empty-value sentinel and contain literal ':::'
    # which would trigger false-positive duplicate-colon hits if left in place.
    # They are reattached after cleaning so downstream parsing still sees them.
    removed_holder = []
    for pat, placeholder in [(_RE_EMPTY_MAC, ';mac:::'), (_RE_EMPTY_LLADDR, ';llAddr:::')]:
        if re.search(pat, line_check[LINE]):
            removed_holder.append(placeholder)
            line_check[LINE] = re.sub(pat, '', line_check[LINE])

    # Collapse all runs of duplicate semicolons in one pass
    if re.search(_RE_MULTI_SEMICOLON, line_check[LINE]):
        print('Stripping duplicate semicolons from line {}\n{}'.format(line_count, line_check[LINE]))
        line_check[LINE] = re.sub(_RE_MULTI_SEMICOLON, ';', line_check[LINE])

    # Reattach the stripped special-case fields
    for item in removed_holder:
        line_check[LINE] = line_check[LINE].rstrip(';') + item

    # Strip trailing semicolons
    if line_check[LINE].endswith(';'):
        line_check[LINE] = line_check[LINE].rstrip(';')
        print('Stripping trailing semicolon from line {}'.format(line_count))

    # Validate each field
    for curr_string in line_check[LINE].split(';'):
        # Split on first colon only — values may contain colons (MAC dash-notation,
        # IPv6 llAddr, etc.) and should not be further fragmented here
        tup = curr_string.split(':', 1)
        if len(tup) < 2:
            continue
        attribute, value = tup[0], tup[1]

        if attribute in ('descr', 'llAddr'):
            continue

        if attribute == 'mac':
            if not re.match(_RE_MAC_ADDRESS, value) and value != '::':
                print('ERROR: Invalid MAC address {} on line {}.\n{}'.format(value, line_count, line_check[LINE]))
                line_check[RESULT] = False
                break
        else:
            char_check = re.search(_RE_ILLEGAL_CHAR, value)
            if char_check:
                print('ERROR: Illegal chars {} on line {}.\n{}'.format(char_check.groups(), line_count, line_check[LINE]))
                line_check[RESULT] = False
                break
            char_check = re.search(_RE_ILLEGAL_CHAR, attribute)
            if char_check:
                print('ERROR: Illegal chars {} on line {}.\n{}'.format(char_check.groups(), line_count, line_check[LINE]))
                line_check[RESULT] = False
                break

    return line_check

def main():
    #start application timer
    start=datetime.now()

    #outer catch block in the event of script kill
    try:
        #parse arguments
        args = parse_args()
        
        #check for output verbosity
        global verbose
        if args.verbose:
            print("STATUS: Verbose output enabled.")
            verbose = True

        #print header to console
        print("\n\n*************************************************************************************")
        print("********************************* Cisco ACI Builder *********************************")
        print("***************************** Version: {}              ****************************".format(VERSION))
        print("*************************************************************************************")

        print("Administrators should always run this tool against a test environment prior to any") 
        print("production environment push.\n")
        print("*** The following features are not supported at this stage ***")
        print("\t- Overlay Multicast")
        print("\t- VLXAN and VSAN type pools")
        print("\t- Service chaining policies")
        print("\t- Fibre channel policies")
        print("\t- NetFlow policies")
        print("\t- Security/Monitoring/Troubleshoot tenant policies")
        print("\t- QoS policies")
        print()

        #turn off certificate related errors
        requests.packages.urllib3.disable_warnings()

        #preload credentials
        url = args.url
        login = args.user
        buildFile = args.in_file
        testCreds = False
        validate_build = False
        if args.validate:
            validate_build = True
        else:
            #check that server is reachable prior to profile push
            print('STATUS: Checking server reachability...', end='')
            host = url.split('://')[1]
            response = ping(host, timeout=3, unit='ms')
            if response:
                print("success!\nSTATUS: Server response time:",round(response, 2),"ms")
                print()
            else:
                #try a second time
                print("failed.\n Attempting a second time...", end='')
                response = ping(host, timeout=3, unit='ms')
                if response:
                    print("success!\nSTATUS: Server response time:",round(response, 2),"ms")
                    print()
                else:
                    print("ERROR: Server unreachable.")
                    print("Exiting script.")
                    sys.exit(1)

            #obtain server password
            password = getpass.getpass(prompt='Enter APIC password: ', stream=None) 
            print()
            #password = 'N0rd1cL3gacy)!'
            #password = 'did@t@123'

        #read loadfile
        file = open(buildFile, "r")
        line_count = 1
        build_errors = False
        
        #verbose output
        if verbose:
            print('STATUS: Parsing buildfile.')
        
        for line in file:
            #only run through build file and perform base checks
            if validate_build:
                is_comment = re.match(comment, line)
                is_newline = re.match(newline, line)
                #skip if newline or comment is present
                if is_comment or is_newline:
                    line_count += 1
                    continue
                else:
                    line_check = buildfile_check_clean(line, line_count)
                    if not line_check[RESULT]:
                        build_errors = True

            #push build file out to defined APIC
            else:
                is_comment = re.match(comment, line)
                is_newline = re.match(newline, line)
                #skip if newline or comment is present
                if is_comment or is_newline:
                    line_count += 1
                    continue
                else:
                    line_check = buildfile_check_clean(line, line_count)
                    curr_line = line_check[LINE]
                    result = line_check[RESULT]
                    if result:        
                        temp_list = curr_line.split(";")
                        category = ""
                        subCategory = ""
                        tempDict = {}
                        
                        #extract attributes for the current line and sort in dictionaries
                        for attribute in temp_list:
                            tup = attribute.split(":")
                            if tup[0] == 'category':
                                category = tup[1].rstrip().replace("\n", '')
                            if tup[0] == 'subCategory':
                                subCategory = tup[1].rstrip().replace("\n", '')
                            else:
                                tempDict[tup[0]] = tup[1].rstrip().replace("\n", '')
                                tempDict['category'] = category
                                tempDict['subCategory'] = subCategory
                        if category == 'tenant':
                            if subCategory == 'application-profile':
                                profiles['application-profile'].append(tempDict)
                            if subCategory == 'tenant':
                                profiles['tenant'].append(tempDict)
                            if subCategory == 'aaep':
                                profiles['aaep'].append(tempDict)
                        if category == 'global':
                            if subCategory == 'physicalDomain':
                                profiles['domain'].append(tempDict)
                            if subCategory == 'routedDomain':
                                profiles['domain'].append(tempDict)
                        if category == 'network':
                            if subCategory == 'epg':
                                profiles['epg'].append(tempDict)
                            if subCategory == 'bridge-domain':
                                profiles['bridge-domain'].append(tempDict)
                            if subCategory == 'dhcpRelayLabel':
                                profiles['dhcpRelayLabel'].append(tempDict)
                            if subCategory == 'ndProxySubnet':
                                profiles['ndProxySubnet'].append(tempDict)
                            if subCategory == 'subnet':
                                profiles['subnet'].append(tempDict)
                            if subCategory == 'vrf':           
                                profiles['vrf'].append(tempDict)
                            if subCategory == 'protocolPolicy':
                                profiles['protocolPolicy'].append(tempDict)
                            if subCategory == 'l3out':
                                profiles['l3out'].append(tempDict)
                            if subCategory == 'nodeProfile':
                                profiles['nodeProfile'].append(tempDict)
                            if subCategory == 'l3OutProtocol':
                                profiles['l3OutProtocol'].append(tempDict)
                            if subCategory == 'intProfile':
                                profiles['intProfile'].append(tempDict)
                            if subCategory == 'intProtocol':
                                profiles['intProtocol'].append(tempDict)
                            if subCategory == 'bridgeDomainLink':
                                profiles['bridgeDomainLink'].append(tempDict)
                            if subCategory == 'routeMap':
                                profiles['routeMap'].append(tempDict)
                            if subCategory == 'staticRoute':
                                profiles['staticRoute'].append(tempDict)
                            if subCategory == 'networks':
                                profiles['networks'].append(tempDict)
                            if subCategory == 'subnets':
                                profiles['subnets'].append(tempDict)
                            if subCategory == 'l3OutRouteMap':
                                profiles['l3OutRouteMap'].append(tempDict)
                            if subCategory == 'routeMapMatch':
                                profiles['routeMapMatch'].append(tempDict)
                            if subCategory == 'routeMapRules':
                                profiles['routeMapRules'].append(tempDict)
                            if subCategory == 'BGPPeer':
                                profiles['BGPPeer'].append(tempDict)
                        if category == 'security':
                            if subCategory == 'contract':
                                profiles['security'].append(tempDict)
                            if subCategory == 'subject':
                                profiles['security'].append(tempDict)
                            if subCategory == 'filter':
                                profiles['security'].append(tempDict)
                            if subCategory == 'filterEntry':
                                profiles['security'].append(tempDict)                
                        if category == 'global':
                            if subCategory == 'vlanPool':
                                profiles['vlanPool'].append(tempDict)
                            if subCategory == 'vlanPoolRange':
                                profiles['vlanPoolRange'].append(tempDict)
                        if category == 'switch':
                            if subCategory == 'leaf':
                                profiles['switchProfile'].append(tempDict)
                            if subCategory == 'spine':
                                profiles['switchProfile'].append(tempDict)
                        if category == 'switchPolicy':
                            if subCategory == 'leafPolicyGroup':
                                profiles['switchPolicy'].append(tempDict)
                            if subCategory == 'spinePolicyGroup':
                                profiles['switchPolicy'].append(tempDict)
                            if subCategory == 'vpcProtectionGroup':
                                profiles['switchPolicy'].append(tempDict)
                        if category == 'interface':
                            profiles['interface'].append(tempDict)
                    else:
                        print('ERROR: Problem detected in buildfile. Please repair the located errors and run the application again.')
                        print('Exiting program.')
                        sys.exit(1)
            #increase file line counter
            line_count += 1

        if validate_build:
            if build_errors:
                #validation failure
                print('ERROR: Build file validation failed. Please fix displayed errors before deployment.')
                print('Exiting application.')
                sys.exit(0)
            else:
                #validation success
                print('STATUS: Build file validation success.')
                print('Exiting application.')
                sys.exit(0)
        try:
            #verbose output
            if verbose:
                print('STATUS: Attempting to login to APIC',url)

            #login to always-on APIC for testing
            auth = cobra.mit.session.LoginSession(url, login, password)
            session = cobra.mit.access.MoDirectory(auth)
            session.login()     
        except requests.HTTPError as err:
            print('ERROR: Unable to connect to the specified server')
            print('\t', err)
            print('Exiting program.')
            exit(1)
        except ConnectionError as err:
            print('ERROR: Unable to connect to the specified server')
            print('\t', err)
            print('Exiting program.')
            exit(1)

        #verbose output
        if verbose:
            print('STATUS: Compiling temporary COBRA storage objects.')

        #define top-level object via Cobra framework
        polUni = cobra.model.pol.Uni('')
        infraInfra = cobra.model.infra.Infra(polUni)
        infraFuncP = cobra.model.infra.FuncP(infraInfra)
        fabricInst = cobra.model.fabric.Inst(polUni)
        fabricProtPol = cobra.model.fabric.ProtPol(fabricInst)

        #temporary dicts so we can reference Cobra objects again after creation
        #tenant related object storage
        temp_tenant = {}
        temp_bridge_domain = {}
        temp_app_profile = {}
        temp_epg = {}
        temp_dhcpOption = {}
        tempVlanPool = {}
        tempAAEP = {}
        tempDomain = {}
        
        #Security related object storage
        tempContract = {}
        tempFilter = {}
        tempSubject = {}
        tempLeafProfile = {}
        
        #L3Out related object storage
        tempL3Out = {}
        tempNodeProfile = {}
        tempNodeAttribute = {}
        tempNetworks = {}
        tempRouteMapContext = {}

        try:
            #begin load of fabric objects
            #load vlan pools
            if verbose:
                count = len(tempVlanPool.keys())
                if count > 0:
                    print('STATUS: Found x{} VLAN pools. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: VLAN pools have not been defined within the build file.')
            for profile in profiles['vlanPool']:
                fvnsVlanInstP = cobra.model.fvns.VlanInstP(infraInfra, allocMode=profile['allocMode'], descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                tempVlanPool[profile['name']] = fvnsVlanInstP
                
            #associate vlan pool ranges to parent pool
            if verbose:
                if count > 0:
                    print('STATUS: Associating VLAN ranges to parent pool object.')                
            for profile in profiles['vlanPoolRange']:
                if profile['vlanPool'] in tempVlanPool:
                    fvnsVlanInstP = tempVlanPool[profile['vlanPool']]
                else:
                    fvnsVlanInstP = cobra.model.fvns.VlanInstP(infraInfra, name=profile['name'])
                    tempVlanPool[profile['vlanPool']] = fvnsVlanInstP
                fvnsEncapBlk = cobra.model.fvns.EncapBlk(fvnsVlanInstP, allocMode=profile['allocMode'], descr=profile['descr'], from_='vlan-'+profile['startVlan'], name=profile['name'], nameAlias=profile['nameAlias'], to='vlan-' + profile['endVlan'])

            #load aaep
            if verbose:
                count = len(tempAAEP.keys())
                if count > 0:
                    print('STATUS: Found x{} AAEPs. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: NO AAEPs have been defined within the build file.')
            for profile in profiles['aaep']:
                infraAttEntityP = cobra.model.infra.AttEntityP(infraInfra, name=profile['name'], nameAlias=profile['nameAlias'], descr=profile['descr'])
                tempAAEP[profile['name']] = infraAttEntityP

            #load domains
            if verbose:
                count = len(tempDomain.keys())
                if count > 0:
                    print('STATUS: Found x{} domains. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: No domains have been defined within the build file.')
            for profile in profiles['domain']:
                if profile['subCategory'] == 'physicalDomain':
                    physDomP = cobra.model.phys.DomP(polUni, name=profile['name'], nameAlias=profile['nameAlias'])
                    infraRsVlanNs = cobra.model.infra.RsVlanNs(physDomP, tDn='uni/infra/vlanns-['+profile['poolName']+']-'+profile['poolType'])
                    if profile['securityDomain']:
                        aaaDomainRef = cobra.model.aaa.DomainRef(physDomP, name=profile['securityDomain'])
                    tempDomain[profile['name']] = physDomP
                if profile['subCategory'] == 'routedDomain':
                    l3extDomP = cobra.model.l3ext.DomP(polUni, name=profile['name'], nameAlias=profile['nameAlias'], descr=profile['descr'])
                    tempDomain[profile['name']] = l3extDomP
                    infraRsVlanNs = cobra.model.infra.RsVlanNs(l3extDomP, tDn='uni/infra/vlanns-['+profile['poolName']+']-'+profile['poolType'])
                    if profile['securityDomain']:
                        aaaDomainRef = cobra.model.aaa.DomainRef(l3extDomP, name=profile['securityDomain'])

            #begin load of tenant objects in required sequence
            #load tenant objects
            if verbose:
                count = len(temp_tenant.keys())
                if count > 0:
                    print('STATUS: Found x{} tenants. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: Tenants have not been defined within the build file.')
            for profile in profiles['tenant']:
                fvTenant = cobra.model.fv.Tenant(polUni, descr=profile['descr'], name=profile['name'])
                temp_tenant[profile['name']] = fvTenant

            #load application objects
            if verbose:
                count = len(temp_tenant.keys())
                if count > 0:
                    print('STATUS: Found x{} application-profiles. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: Application profiles have not been defined within the build file.')
            for profile in profiles['application-profile']:
                #if not available in temporary storage create new object and add
                if profile['tenant'] in temp_tenant:
                    fvTenant = temp_tenant[profile['tenant']]
                else:
                    fvTenant = cobra.model.fv.Tenant(polUni, profile['tenant'])
                    temp_tenant[profile['tenant']] = fvTenant
                fvAp = cobra.model.fv.Ap(fvTenant, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'], prio='unspecified')
                temp_app_profile[profile['name']] = fvAp

           #CLEAN UP REPEATED LOOPING IN THE BELOW - Transform outer dictionary into tuple for initial search
           #load security objects
            for profile in profiles['security']:
                #if not available in temporary storage create new object and add
                if profile['subCategory'] == 'contract':
                    if profile['tenant'] in temp_tenant:
                        fvTenant = temp_tenant[profile['tenant']]
                    else:
                        fvTenant = cobra.model.fv.Tenant(polUni, profile['tenant'])
                        temp_tenant[profile['tenant']] = fvTenant
                    vzBrCP = cobra.model.vz.BrCP(fvTenant, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'], prio=profile['prio'], targetDscp=profile['targetDscp'], scope=profile['scope'])
                    tempContract[profile['name']] = vzBrCP

            for profile in profiles['security']:
                if profile['subCategory'] == 'subject':
                    #if not available in temporary storage create new object and add
                    if profile['contract'] in tempContract:
                        vzBrCP = tempContract[profile['contract']]
                    else:
                        vzBrCP = cobra.model.vz.BrCP(fvTenant, name=profile['contract'])
                        tempContract[profile['contract']] = vzBrCP
                    vzSubj = cobra.model.vz.Subj(vzBrCP, consMatchT=profile['consMatchT'], descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'], prio=profile['prio'], provMatchT=profile['provMatchT'], revFltPorts=profile['revFltPorts'], targetDscp=profile['targetDscp'])
                    tempSubject[profile['name']] = vzSubj

            for profile in profiles['security']:
               if profile['subCategory'] == 'filter':
                    vzFilter = cobra.model.vz.Filter(fvTenant, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                    tempFilter[profile['name']] = vzFilter
                    if profile['subject']:
                        if profile['subject'] in tempSubject:
                            vzSubj = tempSubject[profile['subject']]
                        else:
                            vzSubj = cobra.model.vz.Subj(vzBrCP, name=profile['subject'])
                            tempSubject[profile['subject']] = vzSubj
                        vzRsSubjFiltAtt = cobra.model.vz.RsSubjFiltAtt(vzSubj, tnVzFilterName=profile['name'])

            for profile in profiles['security']:        
                if profile['subCategory'] == 'filterEntry':
                    #if not available in temporary storage create new object and add
                    if profile['filter'] in tempFilter:
                        vzFilter = tempFilter[profile['filter']]
                    else:
                        vzFilter = cobra.model.vz.Filter(fvTenant, name=profile['filter'])
                        tempFilter[profile['filter']] = vzFilter
                    vzEntry = cobra.model.vz.Entry(vzFilter, applyToFrag=profile['applyToFrag'], arpOpc=profile['arpOpc'], dFromPort=profile['dFromPort'], dToPort=profile['dToPort'], 
                        descr=profile['descr'], etherT=profile['etherT'], icmpv4T=profile['icmpv4T'], icmpv6T=profile['icmpv6T'], 
                        matchDscp=profile['matchDscp'], name=profile['name'], nameAlias=profile['nameAlias'], prot=profile['prot'], 
                        sFromPort=profile['sFromPort'], sToPort=profile['sToPort'], stateful=profile['stateful'], tcpRules=profile['tcpRules'])

            #UPDATE TO INCLUDE OTHER TYPES OF DOMAINS - ONLY PHYSICAL CAN BE COMMITTED AT THIS POINT
            #load epg objects
            if verbose:
                count = len(temp_epg.keys())
                if count > 0:
                    print('STATUS: Found x{} EPGs. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: EPGs have not been defined within the build file.')
            for profile in profiles['epg']:
                #check if available in temporary storage - if not create new object and add
                if profile['tenant'] in temp_tenant:
                    fvTenant = temp_tenant[profile['tenant']]
                else:
                    fvTenant = cobra.model.fv.Tenant(polUni, name=profile['tenant'])
                    temp_tenant[profile['tenant']] = fvTenant
                if profile['application-profile'] in temp_app_profile:
                    fvAp = temp_app_profile[profile['application-profile']]
                else:
                    fvAp = cobra.model.fv.Ap(fvTenant, name=profile['application-profile'])
                    temp_app_profile[profile['application-profile']] = fvAp
                fvAEPg = cobra.model.fv.AEPg(fvAp, descr=profile['descr'], 
                    fwdCtrl=profile['fwdCtrl'], isAttrBasedEPg=profile['isAttrBasedEPg'], matchT=profile['matchT'], name=profile['name'], 
                    nameAlias=profile['nameAlias'], pcEnfPref=profile['pcEnfPref'], prefGrMemb=profile['prefGrMemb'], prio='unspecified')
                if profile['domain']:
                    fvRsDomAtt = cobra.model.fv.RsDomAtt(fvAEPg, tDn='uni/phys-'+profile['domain'])
                if profile['contractProvide']:
                    fvRsProv = cobra.model.fv.RsProv(fvAEPg, tnVzBrCPName=profile['contractProvide'])
                if profile['contractConsume']:
                    vRsCons = cobra.model.fv.RsCons(fvAEPg, tnVzBrCPName=profile['contractConsume'])
                temp_epg[profile['name']] = fvAEPg

            #load vrf objects
            #if verbose:
            #    count = len(vrf.keys())
            #    if count > 0:
            #        print('STATUS: Found x{} VRFs. Loading into top-level object.'.format(count))
            #    else:
            #        print('STATUS: No VRFshave been provided within the build file.')
            for profile in profiles['vrf']:
                if profile['tenant'] in temp_tenant:
                    fvTenant = temp_tenant[profile['tenant']]
                else:
                    fvTenant = cobra.model.fv.Tenant(polUni, profile['tenant'])
                    temp_tenant[profile['tenant']] = fvTenant
                fvCtx = cobra.model.fv.Ctx(fvTenant, bdEnforcedEnable=profile['bdEnforcedEnable'], 
                    descr=profile['descr'], knwMcastAct=profile['knwMcastAct'], name=profile['name'], 
                    nameAlias=profile['nameAlias'], pcEnfDir=profile['pcEnfDir'], pcEnfPref=profile['pcEnfPref'])
            
            #load bridge-domains
            if verbose:
                count = len(temp_bridge_domain.keys())
                if count > 0:
                    print('STATUS: Found x{} Bridge-Domains. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: Bridge-Domains have not been defined within the build file.')
            for profile in profiles['bridge-domain']:
                if profile['tenant'] in temp_tenant:
                    fvTenant = temp_tenant[profile['tenant']]
                else:
                    fvTenant = cobra.model.fv.Tenant(polUni, profile['tenant'])
                    temp_tenant[profile['tenant']] = fvTenant
                #convert MAC address format
                macAddress = '00:22:BD:F8:19:FF' #default MAC address
                if profile['mac']:
                    macAddress = profile['mac'].replace('-', ':')
                fvBD = cobra.model.fv.BD(fvTenant, OptimizeWanBandwidth=profile['OptimizeWanBandwidth'], arpFlood=profile['arpFlood'], descr=profile['descr'], mac=macAddress,
                    epClear=profile['epClear'], epMoveDetectMode=profile['epMoveDetectMode'], intersiteBumTrafficAllow=profile['intersiteBumTrafficAllow'], 
                    intersiteL2Stretch=profile['intersiteL2Stretch'], ipLearning=profile['ipLearning'], limitIpLearnToSubnets=profile['limitIpLearnToSubnets'], llAddr=profile['llAddr'], 
                    mcastAllow=profile['mcastAllow'], multiDstPktAct=profile['multiDstPktAct'], name=profile['name'], 
                    nameAlias=profile['nameAlias'], type=profile['type'], 
                    unicastRoute=profile['unicastRoute'], unkMacUcastAct=profile['unkMacUcastAct'], unkMcastAct=profile['unkMcastAct'], 
                    vmac=profile['vmac'])
                temp_bridge_domain[profile['name']] = fvBD
                #link bridge-domain to EPG
                if profile['epg']:
                    if profile['epg'] in temp_epg:
                        fvAEPg = temp_epg[profile['epg']]
                    else:
                        fvAEPg = fvAEPg = cobra.model.fv.AEPg(fvAp, name=profile['epg'])
                        temp_epg[profile['epg']] = fvAEPg
                    fvRsBd = cobra.model.fv.RsBd(fvAEPg, tnFvBDName=profile['name'])
                #link bridge-domain to VRF
                if profile['vrf']:
                    fvRsCtx = cobra.model.fv.RsCtx(fvBD, tnFvCtxName=profile['vrf'])
                #link provided subnets to the bridge-domain
            
            #load subnets under relevant bridge-domains
            for profile in profiles['subnet']:
                if verbose:
                    print('STATUS: Building subnets under Bridge-Domains.')
                if profile['bridge-domain'] in temp_bridge_domain:
                    fvBD = temp_bridge_domain[profile['bridge-domain']]
                else:
                    fvBD = cobra.model.fv.BD(fvTenant, name=profile['bridge-domain'])
                    temp_bridge_domain[profile['bridge-domain']] = fvBD
                fvSubnet = cobra.model.fv.Subnet(fvBD, descr=profile['descr'], ip=profile['ip'], name=profile['name'], nameAlias=profile['nameAlias'], preferred=profile['preferred'], virtual=profile['virtual'], scope=profile['scope'])

            #load links for configured bridge-domains to L3outs
            for profile in profiles['bridgeDomainLink']:
                if verbose:
                    print("STATUS: Linking Bridge-Domain '{}' to L3Out '{}'.".format(profile['bridge-domain'], profile['l3out']))
                
                if profile['tenant'] in temp_tenant:
                    fvTenant = temp_tenant[profile['tenant']]
                else:
                    fvTenant = cobra.model.fv.Tenant(polUni, profile['tenant'])
                    temp_tenant[profile['tenant']] = fvTenant
                
                if profile['bridge-domain'] in temp_bridge_domain:
                    fvBD = temp_bridge_domain[profile['bridge-domain']]
                else:
                    fvBD = cobra.model.fv.BD(fvTenant, name=profile['bridge-domain'])
                    temp_bridge_domain[profile['bridge-domain']] = fvBD
                fvRsBDToOut = cobra.model.fv.RsBDToOut(fvBD, tnL3extOutName=profile['l3out'])
            
            """    
            #load DHCP options
            for profile in profiles['dhcpOptionPolicy']:
                fvTenant = temp_tenant[profile['tenant']]
                dhcpOptionPol = cobra.model.dhcp.OptionPol(fvTenant, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                temp_dhcpOption[profile['name']] = dhcpOptionPol
            #link options to DHCP options policy
            for profile in profiles['dhcpOption']:
                dhcpOptionPol = temp_dhcpOptionPol[profile['dhcpOptionPolicy']]
                dhcpOption = cobra.model.dhcp.Option(dhcpOptionPol, data=profile['data'], name=profile['name'], nameAlias=profile['nameAlias'])
                
            #load DHCP relay policies
            dhcpRelayP = cobra.model.dhcp.RelayP(fvTenant, descr='', mode='visible', name='test_relayPol', nameAlias='', owner='tenant')
            dhcpProvDhcp = cobra.model.dhcp.ProvDhcp(dhcpRelayP, addr='172.16.1.17', name='vlan403_epg', nameAlias='')
            dhcpRsProv = cobra.model.dhcp.RsProv(dhcpRelayP, addr='172.16.1.17', forceResolve='yes', rType='mo', tCl='fvAEPg', tDn='uni/tn-RCH/ap-rch_domain_app/epg-vlan403_epg', tType='mo')
            
            #load DHCP relay labels
            for profile in profiles['dhcpRelayLabel']:
                fvBD = temp_bridge_domain[profile['bridge-domain']]
                dhcpLbl = cobra.model.dhcp.Lbl(fvBD, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                #link provided options policy
                dhcpRsDhcpOptionPol = cobra.model.dhcp.RsDhcpOptionPol(dhcpLbl, tType='name', tnDhcpOptionPolName=profile['tnDhcpOptionPolName'])
                #link provided name policy
                #link provided options policy
            """
            #load l3out profiles
            for profile in profiles['l3out']:
                if verbose:
                    count = len(tempL3Out.keys())
                    if count > 0:
                        print('STATUS: Found x{} L3Out profiles. Loading into top-level object.'.format(count))
                    else:
                        print('STATUS: L3Out profiles have not been defined within the build file.')
                if profile['tenant'] in temp_tenant:
                    fvTenant = temp_tenant[profile['tenant']]
                else:
                    fvTenant = cobra.model.fv.Tenant(polUni, profile['tenant'])
                    temp_tenant[profile['tenant']] = fvTenant
                l3extOut = cobra.model.l3ext.Out(fvTenant, descr=profile['descr'], enforceRtctrl='export', name=profile['name'], nameAlias=profile['nameAlias'], targetDscp=profile['targetDscp'])
                if profile['enablePIM'] == 'yes':
                    pimExtP = cobra.model.pim.ExtP(l3extOut, enabledAf='ipv4-mcast', name='pim')
                if profile['extDomain']:
                    l3extRsL3DomAtt = cobra.model.l3ext.RsL3DomAtt(l3extOut, tDn='uni/l3dom-'+profile['extDomain'])
                if profile['vrf']:
                    l3extRsEctx = cobra.model.l3ext.RsEctx(l3extOut, tnFvCtxName=profile['vrf'])
                tempL3Out[profile['name']] = l3extOut
            
            #load node profiles
            if verbose:
                count = len(tempNodeProfile.keys())
                if count > 0:
                    print('STATUS: Found x{} Node Profiles. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: Node Profiles have not been defined within the build file.')
            for profile in profiles['nodeProfile']:
                if profile['L3Out'] in tempL3Out:
                    l3extOut = tempL3Out[profile['L3Out']]
                else:
                    l3extOut = cobra.model.l3ext.Out(fvTenant, name=profile['L3Out'])
                    tempL3Out[profile['L3Out']] = l3extOut
                nodeDN = 'topology/pod-'+profile['podID']+'/node-'+profile['nodeID']
                l3extLNodeP = cobra.model.l3ext.LNodeP(l3extOut, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'], targetDscp=profile['targetDscp'])
                l3extRsNodeL3OutAtt = cobra.model.l3ext.RsNodeL3OutAtt(l3extLNodeP, rtrId=profile['rtrId'], rtrIdLoopBack=profile['rtrIdLoopBack'], tDn=nodeDN)
                l3extInfraNodeP = cobra.model.l3ext.InfraNodeP(l3extRsNodeL3OutAtt, fabricExtCtrlPeering='no', fabricExtIntersiteCtrlPeering='no')
                tempNodeProfile[profile['name']] = l3extLNodeP
                
                #store node attributes for later reference
                if nodeDN in tempNodeAttribute.keys():
                    tempNodeAttribute[nodeDN].append((profile['name'], l3extRsNodeL3OutAtt))
                else:    
                    tempNodeAttribute[nodeDN] = []
                    tempNodeAttribute[nodeDN].append((profile['name'], l3extRsNodeL3OutAtt))

            #enable protocols on defined l3outs
            for profile in profiles['l3OutProtocol']:
                prot = profile['protocols'].split(',')
                if profile['L3Out'] in tempL3Out:
                    l3extOut = tempL3Out[profile['L3Out']]
                else:
                    l3extOut = cobra.model.l3ext.Out(fvTenant, name=profile['L3Out'])
                    tempL3Out[profile['L3Out']] = l3extOut
                for protocol in prot:
                    if protocol == 'bgp':
                        bgpExtP = cobra.model.bgp.ExtP(l3extOut)
                    if protocol == 'ospf':
                        ospfExtP = cobra.model.ospf.ExtP(l3extOut, areaCost=profile['areaCost'], areaCtrl=profile['areaCtrl'], areaId=profile['areaId'], areaType=profile['areaType'])
                    if protocol == 'eigrp':
                        eigrpExtP = cobra.model.eigrp.ExtP(l3extOut, asn=profile['asn'])

            #attach static routes to interface profiles
            for profile in profiles['staticRoute']:
                #check which node profile we need to apply this to
                nodeDN = 'topology/pod-'+profile['podID']+'/node-'+profile['nodeID']
                l3extRsNodeL3OutAtt = False
                if nodeDN in tempNodeAttribute.keys():
                    for tup in tempNodeAttribute[nodeDN]:
                        if profile['nodeProfile'] == tup[NODEPROFILE]:
                            l3extRsNodeL3OutAtt = tup[ATTRIBUTE]
                            ipRouteP = cobra.model.ip.RouteP(l3extRsNodeL3OutAtt, ip=profile['ip'])
                            ipNexthopP = cobra.model.ip.NexthopP(ipRouteP, nhAddr=profile['nhAddr'])
                            break

            #attach network/s to l3out
            for profile in profiles['networks']:
                if profile['L3Out'] in tempL3Out:
                    l3extOut = tempL3Out[profile['L3Out']]
                else:
                    l3extOut = cobra.model.l3ext.Out(fvTenant, name=profile['L3Out'])
                    tempL3Out[profile['L3Out']] = l3extOut
                l3extInstP = cobra.model.l3ext.InstP(l3extOut, descr=profile['descr'], name=profile['name'], prefGrMemb=profile['prefGrMemb'], prio=profile['prio'], targetDscp=profile['targetDscp'])
                networkName = profile['name']
                
                #store networks for later reference
                if networkName in tempNetworks.keys():
                    tempNetworks[networkName].append((profile['L3Out'], l3extInstP))
                else:    
                    tempNetworks[networkName] = []
                    tempNetworks[networkName].append((profile['L3Out'], l3extInstP))
                
                #attach contracts to relevant networks (CONSUME)
                if profile['conConsume']:
                    fvRsCons = cobra.model.fv.RsCons(l3extInstP, tnVzBrCPName=profile['conConsume'])

                #attach contracts to relevant networks (PROVIDE)
                if profile['conProvide']:
                    fvRsProv = cobra.model.fv.RsProv(l3extInstP, tnVzBrCPName=profile['conProvide'])

            #attach subnets to network
            for profile in profiles['subnets']:
                l3extInstP = False
                networkName = profile['network']
                if networkName in tempNetworks.keys():
                    for tup in tempNetworks[networkName]:
                        if profile['L3Out'] == tup[PROFILENAME]:
                            l3extInstP = tup[ATTRIBUTE]
                            l3extSubnet = cobra.model.l3ext.Subnet(l3extInstP, aggregate=profile['aggregate'], descr=profile['descr'], ip=profile['ip'])
                            fvRsCustQosPol = cobra.model.fv.RsCustQosPol(l3extInstP, tnQosCustomPolName=profile['tnQosCustomPolName'])
                            break

            #attach export route-maps to l3outs
            #ONLY DEFAULT IMPORT/EXPORT PROFILES SUPPORTED AT THIS STAGE
            for profile in profiles['l3OutRouteMap']:
                if profile['L3Out'] in tempL3Out:
                    l3extOut = tempL3Out[profile['L3Out']]
                else:
                    l3extOut = cobra.model.l3ext.Out(fvTenant, name=profile['L3Out'])
                    tempL3Out[profile['L3Out']] = l3extOut
                rtctrlProfile = cobra.model.rtctrl.Profile(l3extOut, descr='', name='default-'+profile['direction'])
                rtctrlCtxP = cobra.model.rtctrl.CtxP(rtctrlProfile, action='permit', descr='', name=profile['contextName'], nameAlias='', order='0')
                if profile['contextName'] not in tempRouteMapContext.keys():
                    tempRouteMapContext[profile['contextName']] = []
                tempRouteMapContext[profile['contextName']].append((profile['L3Out'], rtctrlCtxP))

            #load l3out route-map match objects
            for profile in profiles['routeMapMatch']:
                if profile['type'] == 'match':
                    if profile['tenant'] in temp_tenant:
                        fvTenant = temp_tenant[profile['tenant']]
                    else:
                        fvTenant = cobra.model.fv.Tenant(polUni, profile['tenant'])
                        temp_tenant[profile['tenant']] = fvTenant
                    rtctrlSubjP = cobra.model.rtctrl.SubjP(fvTenant, descr='', name=profile['name'], nameAlias='')
                    rtctrlMatchRtDest = cobra.model.rtctrl.MatchRtDest(rtctrlSubjP, aggregate=profile['aggregate'], descr=profile['descr'], ip=profile['ip'])

            #link match rules to route-map contexts
            #ONLY MATCH STATEMENTS SUPPORTED AT THIS STAGE
            for profile in profiles['routeMapRules']:
                #link statements to route-maps
                if profile['context'] in tempRouteMapContext.keys():
                    for context in tempRouteMapContext[profile['context']]:
                        if context[PROFILENAME] == profile['L3Out']:
                            rtctrlCtxP = context[ATTRIBUTE]
                            rtctrlRsCtxPToSubjP = cobra.model.rtctrl.RsCtxPToSubjP(rtctrlCtxP, tnRtctrlSubjPName=profile['subjectName'])
                            break

            #associate node interface profiles to L3Out
            for profile in profiles['intProfile']:
                if profile['nodeProfile'] in tempNodeProfile:
                    l3extLNodeP = tempNodeProfile[profile['nodeProfile']]
                else:
                    l3extLNodeP = l3extLNodeP = cobra.model.l3ext.LNodeP(l3extOut, name=profile['nodeProfile'])
                    tempNodeProfile[profile['nodeProfile']] = l3extLNodeP
                intType = profile['ifInstT']

                #L3Out point-to-point dot1q tagged routed sub-interface
                if intType == 'sub-interface':
                    #update MAC addres format
                    macAddress = '00:22:BD:F8:19:FF' #default MAC address load
                    if profile['mac']:
                        macAddress = profile['mac'].replace('-', ':') 
                    l3extLIfP = cobra.model.l3ext.LIfP(l3extLNodeP, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                    l3extRsPathL3OutAtt = cobra.model.l3ext.RsPathL3OutAtt(l3extLIfP, addr=profile['addr'], mac=macAddress, descr='', encap='vlan-'+profile['encapVlan'], ifInstT=intType, llAddr=profile['llAddr'], mtu=profile['mtu'], tDn='topology/pod-'+profile['podID']+'/paths-'+profile['nodeID']+'/pathep-[eth'+profile['chassisCard']+'/'+profile['chassisPort']+']', targetDscp=profile['targetDscp'])
                    l3extRsNdIfPol = cobra.model.l3ext.RsNdIfPol(l3extLIfP, tnNdIfPolName=profile['tnNdIfPolName'])
                    l3extRsIngressQosDppPol = cobra.model.l3ext.RsIngressQosDppPol(l3extLIfP, tnQosDppPolName=profile['tnQosDppPolName'])
                    l3extRsEgressQosDppPol = cobra.model.l3ext.RsEgressQosDppPol(l3extLIfP, tnQosDppPolName=profile['tnQosDppPolName'])

                #L3Out point-to-point routed interface
                if intType == 'l3-port':
                    l3extLIfP = cobra.model.l3ext.LIfP(l3extLNodeP, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                    l3extRsPathL3OutAtt = cobra.model.l3ext.RsPathL3OutAtt(l3extLIfP, addr=profile['addr'], descr='', encap='unknown', ifInstT=intType, llAddr=profile['llAddr'], mtu=profile['mtu'], tDn='topology/pod-'+profile['podID']+'/paths-'+profile['nodeID']+'/pathep-[eth'+profile['chassisCard']+'/'+profile['chassisPort']+']', targetDscp=profile['targetDscp'])
                    l3extRsNdIfPol = cobra.model.l3ext.RsNdIfPol(l3extLIfP, tnNdIfPolName=profile['tnNdIfPolName'])
                    l3extRsIngressQosDppPol = cobra.model.l3ext.RsIngressQosDppPol(l3extLIfP, tnQosDppPolName=profile['tnQosDppPolName'])
                    l3extRsEgressQosDppPol = cobra.model.l3ext.RsEgressQosDppPol(l3extLIfP, tnQosDppPolName=profile['tnQosDppPolName'])

                #L3Out SVI interface
                if intType ==  'ext-svi':
                    #update MAC address format
                    macAddress = '00:22:BD:F8:19:FF' #default MAC address
                    if profile['mac']:
                        macAddress = profile['mac'].replace('-', ':')
                    l3extLIfP = cobra.model.l3ext.LIfP(l3extLNodeP, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                    l3extRsPathL3OutAtt = cobra.model.l3ext.RsPathL3OutAtt(l3extLIfP, addr=profile['addr'], descr='', encap='vlan-'+profile['encapVlan'], ifInstT=intType, llAddr=profile['llAddr'], mac=macAddress, mode=profile['mode'], mtu=profile['mtu'], tDn='topology/pod-'+profile['podID']+'/paths-'+profile['nodeID']+'/pathep-['+profile['accessProfile']+']', targetDscp=profile['targetDscp'])
                    l3extRsNdIfPol = cobra.model.l3ext.RsNdIfPol(l3extLIfP, tnNdIfPolName=profile['tnNdIfPolName'])
                    l3extRsIngressQosDppPol = cobra.model.l3ext.RsIngressQosDppPol(l3extLIfP, tnQosDppPolName=profile['tnQosDppPolName'])
                    l3extRsEgressQosDppPol = cobra.model.l3ext.RsEgressQosDppPol(l3extLIfP, tnQosDppPolName=profile['tnQosDppPolName'])

                #create and associate relevant profiles and attach to the current l3extLIfP
                if profile['bfdProfile']:
                        bfdIfP = cobra.model.bfd.IfP(l3extLIfP)
                        bfdRsIfPol = cobra.model.bfd.RsIfPol(bfdIfP, tnBfdIfPolName=profile['bfdProfile'])
                if profile['PIMProfile']:
                    pimIfP = cobra.model.pim.IfP(l3extLIfP)
                    pimRsIfPol = cobra.model.pim.RsIfPol(pimIfP, tDn='uni/tn-RCH/pimifpol-'+profile['PIMProfile'])
                if profile['OSPFIntProfile']:
                    ospfIfP = cobra.model.ospf.IfP(l3extLIfP, authKeyId=profile['authKeyId'], authType=profile['authType'])
                    ospfRsIfPol = cobra.model.ospf.RsIfPol(ospfIfP, tnOspfIfPolName=profile['OSPFIntProfile'])
                if profile['EIGRPIntProfile']:
                    eigrpIfP = cobra.model.eigrp.IfP(l3extLIfP)
                    eigrpRsIfPol = cobra.model.eigrp.RsIfPol(eigrpIfP, tnEigrpIfPolName=profile['EIGRPIntProfile'])
                if profile['BGPIntProfile']:
                    bgpProtP = cobra.model.bgp.ProtP(l3extLNodeP)
                    bgpRsBgpNodeCtxPol = cobra.model.bgp.RsBgpNodeCtxPol(bgpProtP, tnBgpCtxPolName=profile['BGPIntProfile'])

            #link routing protocol profiles to parent interface policies
            if verbose:
                count = len(profiles['intProtocol'])
                if count > 0:
                    print('STATUS: Found routing protocol policies. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: Routing Protocol Policies have not been defined within the build file.')
            for profile in profiles['intProtocol']:
                if profile['nodeProfile'] in tempNodeProfile:
                    l3extLNodeP = tempNodeProfile[profile['nodeProfile']]
                else:
                    l3extLNodeP = l3extLNodeP = cobra.model.l3ext.LNodeP(l3extOut, name=profile['nodeProfile'])
                    tempNodeProfile[profile['nodeProfile']] = l3extLNodeP
                if profile['protocol'].lower() == 'eigrp' or profile['protocol'].lower() == 'ospf':
                    l3extLIfP = cobra.model.l3ext.LIfP(l3extLNodeP, profile['protocolProfile'])

            #BGP peer profile link to node profile
            for profile in profiles['BGPPeer']:
                if profile['nodeProfile'] in tempNodeProfile:
                    l3extLNodeP = tempNodeProfile[profile['nodeProfile']]
                else:
                    l3extLNodeP = l3extLNodeP = cobra.model.l3ext.LNodeP(l3extOut, name=profile['nodeProfile'])
                    tempNodeProfile[profile['nodeProfile']] = l3extLNodeP      
                bgpPeerP = cobra.model.bgp.PeerP(l3extLNodeP, addr=profile['localAddr'], allowedSelfAsCnt=profile['allowedSelfAsCnt'], ctrl=profile['ctrl'], peerCtrl=profile['peerCtrl'], privateASctrl='', ttl=profile['multihopValue'], weight=profile['weight'])
                bgpRsPeerPfxPol = cobra.model.bgp.RsPeerPfxPol(bgpPeerP, tnBgpPeerPfxPolName=profile['prefixPolicy'])
                bgpLocalAsnP = cobra.model.bgp.LocalAsnP(bgpPeerP, localAsn=profile['localASN'])
                bgpAsP = cobra.model.bgp.AsP(bgpPeerP, asn=profile['remoteASN'])

            #create the base leaf switch policy groups (CUSTOM ATTACHED POLICIES ARE NOT YET SUPPORTED)
            if verbose:
                count = len(profiles['switchPolicy'])
                if count > 0:
                    print('STATUS: Found x{} Switch Profile Policies. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: Switch Profile Policies have not been defined within the build file.')
            for profile in profiles['switchPolicy']:
                if profile['subCategory'] == 'leafPolicyGroup':
                    infraAccNodePGrp = cobra.model.infra.AccNodePGrp(infraFuncP, descr=profile['descr'], name=profile['name'])
                    infraRsBfdIpv6InstPol = cobra.model.infra.RsBfdIpv6InstPol(infraAccNodePGrp, tnBfdIpv6InstPolName=profile['tnBfdIpv6InstPolName'])
                    infraRsMonNodeInfraPol = cobra.model.infra.RsMonNodeInfraPol(infraAccNodePGrp, tnMonInfraPolName=profile['tnMonInfraPolName'])
                    infraRsFcInstPol = cobra.model.infra.RsFcInstPol(infraAccNodePGrp, tnFcInstPolName=profile['tnFcInstPolName'])
                    infraRsBfdIpv4InstPol = cobra.model.infra.RsBfdIpv4InstPol(infraAccNodePGrp, tnBfdIpv4InstPolName=profile['tnBfdIpv4InstPolName'])
                    infraRsL2NodeAuthPol = cobra.model.infra.RsL2NodeAuthPol(infraAccNodePGrp, tnL2NodeAuthPolName=profile['tnL2NodeAuthPolName'])
                    infraRsTopoctrlFwdScaleProfPol = cobra.model.infra.RsTopoctrlFwdScaleProfPol(infraAccNodePGrp, tnTopoctrlFwdScaleProfilePolName=profile['tnTopoctrlFwdScaleProfilePolName'])
                    infraRsFcFabricPol = cobra.model.infra.RsFcFabricPol(infraAccNodePGrp, tnFcFabricPolName=profile['tnFcFabricPolName'])
                    infraRsLeafCoppProfile = cobra.model.infra.RsLeafCoppProfile(infraAccNodePGrp, tnCoppLeafProfileName=profile['tnCoppLeafProfileName'])
                    infraRsMstInstPol = cobra.model.infra.RsMstInstPol(infraAccNodePGrp, tnStpInstPolName=profile['tnStpInstPolName'])
                    infraRsPoeInstPol = cobra.model.infra.RsPoeInstPol(infraAccNodePGrp, tnPoeInstPolName=profile['tnPoeInstPolName'])

                #create the base spine switch policy groups (CUSTOM ATTACHED POLICIES ARE NOT YET SUPPORTED)
                if profile['subCategory'] == 'spinePolicyGroup':
                    infraSpineAccNodePGrp = cobra.model.infra.SpineAccNodePGrp(infraFuncP, descr=profile['descr'], name=profile['name'])
                    infraRsSpineCoppProfile = cobra.model.infra.RsSpineCoppProfile(infraSpineAccNodePGrp, tnCoppSpineProfileName=profile['tnCoppSpineProfileName'])

                #load VPC protection groups
                if profile['subCategory'] == 'vpcProtectionGroup':
                    fabricExplicitGEp = cobra.model.fabric.ExplicitGEp(fabricProtPol, id=profile['vpcID'], name=profile['name'])
                    fabricRsVpcInstPol = cobra.model.fabric.RsVpcInstPol(fabricExplicitGEp, tnVpcInstPolName=profile['tnVpcInstPolName'])
                    fabricNodePEp = cobra.model.fabric.NodePEp(fabricExplicitGEp, id=profile['nodeID01'], podId=profile['podId'])
                    fabricNodePEp2 = cobra.model.fabric.NodePEp(fabricExplicitGEp, id=profile['nodeID02'], podId=profile['podId'])

            #load switch profiles
            if verbose:
                count = len(profiles['switchProfile'])
                if count > 0:
                    print('STATUS: Found x{} Switch Profiles. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: Switch Profiles have not been not within the build file.')
            for profile in profiles['switchProfile']:
                if profile['subCategory'] == 'leaf':
                    infraNodeP = cobra.model.infra.NodeP(infraInfra, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                    if profile['intProfile']:
                        infraRsAccPortP = cobra.model.infra.RsAccPortP(infraNodeP, tDn='uni/infra/accportprof-'+profile['intProfile'])
                    infraLeafS = cobra.model.infra.LeafS(infraNodeP, name=profile['leafName'], type='range')
                    infraRsAccNodePGrp = cobra.model.infra.RsAccNodePGrp(infraLeafS, tDn='uni/infra/funcprof/accnodepgrp-'+profile['policyGroup'])
                    if profile['nodeBlock'] :
                        blocks = profile['nodeBlock'].split('-')
                        if len(blocks) > 1:
                            infraNodeBlk = cobra.model.infra.NodeBlk(infraLeafS, name=profile['leafName'], from_=blocks[0], to_=blocks[1])
                        if len(blocks) == 1:
                            infraNodeBlk = cobra.model.infra.NodeBlk(infraLeafS, name=profile['leafName'], from_=blocks[0], to_=blocks[0])
                if profile['subCategory'] == 'spine':
                    infraSpineP = cobra.model.infra.SpineP(infraInfra, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                    infraSpineS = cobra.model.infra.SpineS(infraSpineP, name=profile['spineName'], type='range')
                    if profile['policyGroup']:
                        infraRsSpineAccNodePGrp = cobra.model.infra.RsSpineAccNodePGrp(infraSpineS, tDn='uni/infra/funcprof/spaccnodepgrp-'+profile['policyGroup'])
                    if profile['nodeBlock']:
                        blocks = profile['nodeBlock'].split('-')
                        if len(blocks) > 1:
                            infraNodeBlk = cobra.model.infra.NodeBlk(infraSpineS, name=profile['spineName'], from_=blocks[0], to_=blocks[1])
                        if len(blocks) == 1:
                            infraNodeBlk = cobra.model.infra.NodeBlk(infraSpineS, name=profile['spineName'], from_=blocks[0], to_=blocks[0])
                    if profile['intProfile']:
                        infraRsSpAccPortP = cobra.model.infra.RsSpAccPortP(infraSpineP, tDn='uni/infra/spaccportprof-'+profile['intProfile'])

            #load interface profiles
            if verbose:
                count = len(profiles['interface'])
                if count > 0:
                    print('STATUS: Found x{} Interface Profiles. Loading into top-level object.'.format(count))
                else:
                    print('STATUS: Interface Profiles have not been defined within the build file.')
            for profile in profiles['interface']:
                if profile['subCategory'] == 'link':
                    fabricHIfPol = cobra.model.fabric.HIfPol(infraInfra, name=profile['name'], autoNeg=profile['autoNeg'], descr=profile['descr'], 
                        fecMode=profile['fecMode'], linkDebounce=profile['linkDebounce'], speed=profile['speed'])
                if profile['subCategory'] == 'flow-control':
                    pass
                if profile['subCategory'] == 'cdp':
                    cdpIfPol = cobra.model.cdp.IfPol(infraInfra, adminSt=profile['adminSt'], descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                if profile['subCategory'] == 'lldp':
                    lldpIfPol = cobra.model.lldp.IfPol(infraInfra, adminRxSt=profile['adminRxSt'], adminTxSt=profile['adminTxSt'], descr=profile['descr'], 
                        name=profile['name'], nameAlias=profile['nameAlias'])
                if profile['subCategory'] == 'channel':
                    lacpLagPol = cobra.model.lacp.LagPol(infraInfra, ctrl=profile['ctrl'], descr=profile['descr'], 
                        maxLinks=profile['maxLinks'], minLinks=profile['minLinks'], mode=profile['mode'], name=profile['name'], nameAlias=profile['nameAlias'])
                if profile['subCategory'] == 'mcp':
                    mcpIfPol = cobra.model.mcp.IfPol(infraInfra, adminSt=profile['adminSt'], descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                if profile['subCategory'] == 'stp':        
                    stpIfPol = cobra.model.stp.IfPol(infraInfra, ctrl=profile['ctrl'], descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                #create interface policy groups
                if profile['subCategory'] == 'policyGroup':
                    if profile['type'] == 'access':
                        if profile['nodeType'] == 'leaf':
                            infraAccPortGrp = cobra.model.infra.AccPortGrp(infraFuncP, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                            infraRsStpIfPol = cobra.model.infra.RsStpIfPol(infraAccPortGrp, tnStpIfPolName='')
                            infraRsQosIngressDppIfPol = cobra.model.infra.RsQosIngressDppIfPol(infraAccPortGrp, tnQosDppPolName='')
                            infraRsStormctrlIfPol = cobra.model.infra.RsStormctrlIfPol(infraAccPortGrp, tnStormctrlIfPolName=profile['storm-control'])
                            infraRsQosEgressDppIfPol = cobra.model.infra.RsQosEgressDppIfPol(infraAccPortGrp, tnQosDppPolName='')
                            infraRsMonIfInfraPol = cobra.model.infra.RsMonIfInfraPol(infraAccPortGrp, tnMonInfraPolName='')
                            infraRsQosSdIfPol = cobra.model.infra.RsQosSdIfPol(infraAccPortGrp, tnQosSdIfPolName='')
                            infraRsPoeIfPol = cobra.model.infra.RsPoeIfPol(infraAccPortGrp, tnPoeIfPolName='')
                            infraRsAttEntP = cobra.model.infra.RsAttEntP(infraAccPortGrp)
                            infraRsMcpIfPol = cobra.model.infra.RsMcpIfPol(infraAccPortGrp, tnMcpIfPolName=profile['mcp'])
                            infraRsCdpIfPol = cobra.model.infra.RsCdpIfPol(infraAccPortGrp, tnCdpIfPolName=profile['cdp'])
                            infraRsL2IfPol = cobra.model.infra.RsL2IfPol(infraAccPortGrp, tnL2IfPolName='')
                            infraRsQosDppIfPol = cobra.model.infra.RsQosDppIfPol(infraAccPortGrp, tnQosDppPolName='')
                            infraRsCoppIfPol = cobra.model.infra.RsCoppIfPol(infraAccPortGrp, tnCoppIfPolName='')
                            infraRsQosPfcIfPol = cobra.model.infra.RsQosPfcIfPol(infraAccPortGrp, tnQosPfcIfPolName='')
                            infraRsHIfPol = cobra.model.infra.RsHIfPol(infraAccPortGrp, tnFabricHIfPolName=profile['link-level'])
                            infraRsL2PortSecurityPol = cobra.model.infra.RsL2PortSecurityPol(infraAccPortGrp, tnL2PortSecurityPolName='')
                            infraRsL2PortAuthPol = cobra.model.infra.RsL2PortAuthPol(infraAccPortGrp, tnL2PortAuthPolName='')
                            infraRsFcIfPol = cobra.model.infra.RsFcIfPol(infraAccPortGrp, tnFcIfPolName='')
                            infraRsLldpIfPol = cobra.model.infra.RsLldpIfPol(infraAccPortGrp, tnLldpIfPolName=profile['lldp'])
                            infraRsAttEntP = cobra.model.infra.RsAttEntP(infraAccPortGrp, tDn=('uni/infra/attentp-'+profile['aaep']))
                        if profile['nodeType'] == 'spine':
                            infraSpAccPortGrp = cobra.model.infra.SpAccPortGrp(infraFuncP, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                            infraRsHIfPol = cobra.model.infra.RsHIfPol(infraSpAccPortGrp, tnFabricHIfPolName=profile['link-policy'])
                            infraRsCoppIfPol = cobra.model.infra.RsCoppIfPol(infraSpAccPortGrp, tnCoppIfPolName=profile['copp'])
                            infraRsCdpIfPol = cobra.model.infra.RsCdpIfPol(infraSpAccPortGrp, tnCdpIfPolName=profile['cdp'])
                            infraRsAttEntP = cobra.model.infra.RsAttEntP(infraSpAccPortGrp, tDn=('uni/infra/attentp-'+profile['aaep']))    
                    if profile['type'] == 'channel':
                        if profile['nodeType'] == 'leaf':
                            infraAccBndlGrp = cobra.model.infra.AccBndlGrp(infraFuncP, descr=profile['descr'], lagT='link', name=profile['name'], nameAlias=profile['nameAlias'])
                            infraRsLacpPol = cobra.model.infra.RsLacpPol(infraAccBndlGrp, tnLacpLagPolName=profile['lagPolicy'])
                            infraRsStpIfPol = cobra.model.infra.RsStpIfPol(infraAccBndlGrp, tnStpIfPolName='')
                            infraRsQosIngressDppIfPol = cobra.model.infra.RsQosIngressDppIfPol(infraAccBndlGrp, tnQosDppPolName='')
                            infraRsStormctrlIfPol = cobra.model.infra.RsStormctrlIfPol(infraAccBndlGrp, tnStormctrlIfPolName=profile['storm-control'])
                            infraRsQosEgressDppIfPol = cobra.model.infra.RsQosEgressDppIfPol(infraAccBndlGrp, tnQosDppPolName='')
                            infraRsMonIfInfraPol = cobra.model.infra.RsMonIfInfraPol(infraAccBndlGrp, tnMonInfraPolName='')
                            infraRsQosSdIfPol = cobra.model.infra.RsQosSdIfPol(infraAccBndlGrp, tnQosSdIfPolName='')
                            #infraRsPoeIfPol = cobra.model.infra.RsPoeIfPol(infraAccBndlGrp, tnPoeIfPolName='')
                            infraRsAttEntP = cobra.model.infra.RsAttEntP(infraAccBndlGrp)
                            infraRsMcpIfPol = cobra.model.infra.RsMcpIfPol(infraAccBndlGrp, tnMcpIfPolName=profile['mcp'])
                            infraRsCdpIfPol = cobra.model.infra.RsCdpIfPol(infraAccBndlGrp, tnCdpIfPolName=profile['cdp'])
                            infraRsL2IfPol = cobra.model.infra.RsL2IfPol(infraAccBndlGrp, tnL2IfPolName='')
                            infraRsQosDppIfPol = cobra.model.infra.RsQosDppIfPol(infraAccBndlGrp, tnQosDppPolName='')
                            infraRsCoppIfPol = cobra.model.infra.RsCoppIfPol(infraAccBndlGrp, tnCoppIfPolName='')
                            infraRsQosPfcIfPol = cobra.model.infra.RsQosPfcIfPol(infraAccBndlGrp, tnQosPfcIfPolName='')
                            infraRsHIfPol = cobra.model.infra.RsHIfPol(infraAccBndlGrp, tnFabricHIfPolName=profile['link-level'])
                            infraRsL2PortSecurityPol = cobra.model.infra.RsL2PortSecurityPol(infraAccBndlGrp, tnL2PortSecurityPolName='')
                            infraRsL2PortAuthPol = cobra.model.infra.RsL2PortAuthPol(infraAccBndlGrp, tnL2PortAuthPolName='')
                            infraRsFcIfPol = cobra.model.infra.RsFcIfPol(infraAccBndlGrp, tnFcIfPolName='')
                            infraRsLldpIfPol = cobra.model.infra.RsLldpIfPol(infraAccBndlGrp, tnLldpIfPolName=profile['lldp'])
                            infraRsAttEntP = cobra.model.infra.RsAttEntP(infraAccBndlGrp, tDn=('uni/infra/attentp-'+profile['aaep']))
                    if profile['type'] == 'vpc':
                        if profile['nodeType'] == 'leaf':
                            infraAccBndlGrp = cobra.model.infra.AccBndlGrp(infraFuncP, descr=profile['descr'], lagT='node', name=profile['name'], nameAlias=profile['nameAlias'])
                            infraRsLacpPol = cobra.model.infra.RsLacpPol(infraAccBndlGrp, tnLacpLagPolName=profile['lagPolicy'])
                            infraRsStpIfPol = cobra.model.infra.RsStpIfPol(infraAccBndlGrp, tnStpIfPolName='')
                            infraRsQosIngressDppIfPol = cobra.model.infra.RsQosIngressDppIfPol(infraAccBndlGrp, tnQosDppPolName='')
                            infraRsStormctrlIfPol = cobra.model.infra.RsStormctrlIfPol(infraAccBndlGrp, tnStormctrlIfPolName=profile['storm-control'])
                            infraRsQosEgressDppIfPol = cobra.model.infra.RsQosEgressDppIfPol(infraAccBndlGrp, tnQosDppPolName='')
                            infraRsMonIfInfraPol = cobra.model.infra.RsMonIfInfraPol(infraAccBndlGrp, tnMonInfraPolName='')
                            infraRsQosSdIfPol = cobra.model.infra.RsQosSdIfPol(infraAccBndlGrp, tnQosSdIfPolName='')
                            #infraRsPoeIfPol = cobra.model.infra.RsPoeIfPol(infraAccBndlGrp, tnPoeIfPolName='')
                            infraRsAttEntP = cobra.model.infra.RsAttEntP(infraAccBndlGrp)
                            infraRsMcpIfPol = cobra.model.infra.RsMcpIfPol(infraAccBndlGrp, tnMcpIfPolName=profile['mcp'])
                            infraRsCdpIfPol = cobra.model.infra.RsCdpIfPol(infraAccBndlGrp, tnCdpIfPolName=profile['cdp'])
                            infraRsL2IfPol = cobra.model.infra.RsL2IfPol(infraAccBndlGrp, tnL2IfPolName='')
                            infraRsQosDppIfPol = cobra.model.infra.RsQosDppIfPol(infraAccBndlGrp, tnQosDppPolName='')
                            infraRsCoppIfPol = cobra.model.infra.RsCoppIfPol(infraAccBndlGrp, tnCoppIfPolName='')
                            infraRsQosPfcIfPol = cobra.model.infra.RsQosPfcIfPol(infraAccBndlGrp, tnQosPfcIfPolName='')
                            infraRsHIfPol = cobra.model.infra.RsHIfPol(infraAccBndlGrp, tnFabricHIfPolName=profile['link-level'])
                            infraRsL2PortSecurityPol = cobra.model.infra.RsL2PortSecurityPol(infraAccBndlGrp, tnL2PortSecurityPolName='')
                            infraRsL2PortAuthPol = cobra.model.infra.RsL2PortAuthPol(infraAccBndlGrp, tnL2PortAuthPolName='')
                            infraRsFcIfPol = cobra.model.infra.RsFcIfPol(infraAccBndlGrp, tnFcIfPolName='')
                            infraRsLldpIfPol = cobra.model.infra.RsLldpIfPol(infraAccBndlGrp, tnLldpIfPolName=profile['lldp'])
                            infraRsAttEntP = cobra.model.infra.RsAttEntP(infraAccBndlGrp, tDn=('uni/infra/attentp-'+profile['aaep']))

                #leaf/spine interface policy objects
                if profile['subCategory'] == 'profile':
                    if profile['nodeType'] == 'leaf':
                        infraAccPortP = cobra.model.infra.AccPortP(infraInfra, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                        tempLeafProfile[profile['name']] = infraAccPortP
                    if profile['nodeType'] == 'spine':
                        infraSpAccPortP = cobra.model.infra.SpAccPortP(infraInfra, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'])
                #Access port selectors
                if profile['subCategory'] == 'accessPortSelector':
                    portRange = profile['chassisPort'].split('-')
                    fromPort = profile['chassisPort']
                    toPort = profile['chassisPort']
                    if profile['intProfile'] in tempLeafProfile:
                        infraAccPortP = tempLeafProfile[profile['intProfile']]
                    else:
                        infraAccPortP = cobra.model.infra.AccPortP(infraInfra, name=profile['intProfile'])
                        tempLeafProfile[profile['intProfile']] = infraAccPortP
                    if len(portRange) > 1:
                        fromPort = portRange[0]
                        toPort = portRange[1]
                    if profile['channelProfile']:
                        #port-channel defined
                        infraHPortS = cobra.model.infra.HPortS(infraAccPortP, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'],type='range')
                        
                        #check if assigned leaf ID starts with 1 - denotes a node in pod 1. Everything in pod 2 needs FEX ID of 101.
                        #Note: This logical is specific and needs to be generised
                        patt = re.compile(r'[23456789]\d+')
                        if re.match(patt, clean_input(profile['leafID'])):
                            infraRsAccBaseGrp = cobra.model.infra.RsAccBaseGrp(infraHPortS, fexId='101', tDn='uni/infra/funcprof/accbundle-'+profile['channelProfile'])
                        else:
                            infraRsAccBaseGrp = cobra.model.infra.RsAccBaseGrp(infraHPortS, fexId=profile['leafID'], tDn='uni/infra/funcprof/accbundle-'+profile['channelProfile'])

                        infraPortBlk = cobra.model.infra.PortBlk(infraHPortS, name=profile['blockName'], fromCard=profile['chassisCard'], fromPort=fromPort, toCard=profile['chassisCard'], toPort=toPort, descr=profile['blockDescr'])
                        
                        #VPC defined
                        #infraHPortS = cobra.model.infra.HPortS(infraAccPortP, descr='', name='eth1_42', nameAlias='', ownerKey='', ownerTag='', type='range')
                        #infraRsAccBaseGrp = cobra.model.infra.RsAccBaseGrp(infraHPortS, fexId='101', forceResolve='yes', rType='mo', tCl='infraAccBndlGrp', tDn='uni/infra/funcprof/accbundle-test_vpc', tType='mo')
                        #infraPortBlk = cobra.model.infra.PortBlk(infraHPortS, descr='', fromCard='1', fromPort='42', name='block2', nameAlias='', toCard='1', toPort='42')
                    else:          
                        #single interface definition
                        infraHPortS = cobra.model.infra.HPortS(infraAccPortP, descr=profile['descr'], name=profile['name'], nameAlias=profile['nameAlias'],type='range')
                        #check if assigned leaf ID starts with 1 - denotes a node in pod 1. Everything in pod 2 needs FEX ID of 101.
                        #Note: This logical is specific and needs to be generised
                        patt = re.compile(r'[23456789]\d+')
                        if re.match(patt, clean_input(profile['leafID'])):
                            infraRsAccBaseGrp = cobra.model.infra.RsAccBaseGrp(infraHPortS, fexId='101', tDn='uni/infra/funcprof/accportgrp-'+profile['policyGroup'])
                        else:
                            infraRsAccBaseGrp = cobra.model.infra.RsAccBaseGrp(infraHPortS, fexId=profile['leafID'], tDn='uni/infra/funcprof/accportgrp-'+profile['policyGroup'])
                        infraPortBlk = cobra.model.infra.PortBlk(infraHPortS, name=profile['blockName'], fromCard=profile['chassisCard'], fromPort=fromPort, toCard=profile['chassisCard'], toPort=toPort, descr=profile['blockDescr'])

            #################################################################
            #Static linkage of EPG to physical interface SAMPLES
            #################################################################
            
            #### ACCESS PORT
            # CHANGE MODE TO: untagged
            
            # 802.1P PORT
            # Change MODE TO: native
            
            ### TRUNK SAMPLES
            #ACCESS PORT SAMPLE
            #fvRsPathAtt = cobra.model.fv.RsPathAtt(fvAEPg, descr='', encap='vlan-403', extMngdBy='', forceResolve='yes', instrImedcy='immediate', mode='regular', primaryEncap='unknown', rType='mo', tCl='fabricPathEp', tDn='topology/pod-1/paths-101/pathep-[eth1/41]', tType='mo')
            
            #PC SAMPLE
            #fvRsPathAtt = cobra.model.fv.RsPathAtt(fvAEPg, descr='', encap='vlan-403', extMngdBy='', forceResolve='yes', instrImedcy='immediate', mode='regular', primaryEncap='unknown', rType='mo', tCl='fabricPathEp', tDn='topology/pod-1/paths-102/pathep-[testRouter03_pc]', tType='mo')
            
            #VPC SAMPLE
            #fvRsPathAtt = cobra.model.fv.RsPathAtt(fvAEPg, descr='', encap='vlan-403', extMngdBy='', forceResolve='yes', instrImedcy='immediate', mode='regular', primaryEncap='unknown', rType='mo', tCl='fabricPathEp', tDn='topology/pod-1/protpaths-101-102/pathep-[test_vpc]', tType='mo')        
                    
        except OSError as err:
            print('ERROR: Unable to create MO via Cobra framework. Check your loadsheet variables!')
            print(err)
            sys.exit(1)

        #attempt to perform final commit
        try:
            config_request = cobra.mit.request.ConfigRequest()
            config_request.addMo(polUni)
            session.commit(config_request)
        except requests.CommitError as err:
            print('ERROR: An error occured commiting defined MO to the APIC', URL)
            print(err)
            print('Exiting program.')
            exit(1)

        #output application runtime
        print("\n*** Estimated runtime: ",datetime.now()-start, "***\n")

    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit(1) 

if __name__ == '__main__':
    main()