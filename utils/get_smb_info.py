from concurrent.futures import ThreadPoolExecutor, as_completed

from connections.nrpc import NRPCConnection
from connections.smb import SMBConnection

def get_smb_info(ip, username, secret, domain):
    shares = [None]
    no_signing = None
    domain_controller_ip = None
    try:
        with SMBConnection("", "", ip, domain) as smb:
            no_signing = smb.isSigningRequired()
    except:
        shares = ["NO ACCESS"]

    try:
        with SMBConnection(username, secret, ip, domain) as smb:
            no_signing = smb.isSigningRequired()
            shares = smb.listShares()

    except:
        shares = ["NO ACCESS"]

    try:
        with NRPCConnection(username, secret, ip, domain) as nrpc:
            domain_controller_ip, domain_controller_name = nrpc.get_primary_domain_controller()

    except:
        pass

    return [ip, no_signing, shares], domain_controller_ip


def get_smb_info_list(ips, username, secret, domain):
    smb_info, domain_controllers = [], []

    with ThreadPoolExecutor(max_workers=256) as executor:
        futures = [executor.submit(get_smb_info, ip, username, secret, domain) for ip in ips]

    for future in as_completed(futures):
        share_info, domain_controller = future.result()
        if share_info:
            smb_info.append(share_info)
        if domain_controller:
            domain_controllers.append(domain_controller)
    return smb_info, list(set(domain_controllers))
