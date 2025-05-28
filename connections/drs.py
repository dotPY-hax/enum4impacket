from impacket.dcerpc.v5 import epm, transport
from impacket.dcerpc.v5.drsuapi import MSRPC_UUID_DRSUAPI, hDRSDomainControllerInfo, DRSBind, NTDSAPI_CLIENT_GUID, \
    DRS_EXTENSIONS_INT, DRS_EXT_GETCHGREQ_V6, DRS_EXT_GETCHGREPLY_V6, DRS_EXT_GETCHGREQ_V8, DRS_EXT_STRONG_ENCRYPTION, \
    NULLGUID
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

from connections.secret_parse import parse_secret
from connections.smb import smb

def get_domain_controllers(username, secret, target_ip):
    nthash, lmhash, password = parse_secret(secret)

    smb_connection = smb(target_ip, username, secret, "")
    domain = smb_connection.getServerDomain()

    # YOINK!! Yoinked from goldenpac and refactored

    print('Calling DRSDomainControllerInfo()')
    string_binding = epm.hept_map(smb_connection.getRemoteHost(), MSRPC_UUID_DRSUAPI, protocol='ncacn_ip_tcp')
    rpc_transport = transport.DCERPCTransportFactory(string_binding)

    smb_connection.close()

    try:
        rpc_transport.set_credentials(username, password, domain, lmhash, nthash)
    except AttributeError:
        pass # dont @ me

    dce = rpc_transport.get_dce_rpc()
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.connect()
    dce.bind(MSRPC_UUID_DRSUAPI)

    request = DRSBind()
    request['puuidClientDsa'] = NTDSAPI_CLIENT_GUID
    drs = DRS_EXTENSIONS_INT()
    drs['cb'] = len(drs)  # - 4
    drs['dwFlags'] = DRS_EXT_GETCHGREQ_V6 | DRS_EXT_GETCHGREPLY_V6 | DRS_EXT_GETCHGREQ_V8 | DRS_EXT_STRONG_ENCRYPTION
    drs['SiteObjGuid'] = drs['ConfigObjGUID'] = NULLGUID
    drs['Pid'] = drs['dwReplEpoch'] = drs['dwFlagsExt'] = 0
    drs['dwExtCaps'] = 127
    request['pextClient']['cb'] = len(drs.getData())
    request['pextClient']['rgb'] = list(drs.getData())
    resp = dce.request(request)
    drs_handle = resp['phDrs']
    domain_controller_info = hDRSDomainControllerInfo(dce, drs_handle, domain, 1)

    dce.disconnect()
    domain_controllers = []

    for domain_controller in domain_controller_info['pmsgOut']['V1']['rItems']:
        print(f'Found domain controller {domain_controller['DnsHostName'][:-1]}')
        domain_controllers.append(domain_controller['DnsHostName'][:-1])

    return domain_controllers