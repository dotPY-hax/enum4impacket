import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from connections.nrpc import NRPCConnection
from connections.samr import SamrConnection


def run_single_target(username, secret, target, domain):
    try:
        with NRPCConnection(username, secret, target, domain) as nrpc:
            print("NRPC - OK")
        with SamrConnection(username, secret, target, domain) as samr:
            print("SAMR - OK")

        return True, target
    except:
        return False, target


def run_nrpc_target(username, secret, target, domain):
    try:
        with NRPCConnection(username, secret, target, domain) as nrpc:
            print("NRPC - OK")
        return True, target
    except:
        return False, target

def run_samr_target(username, secret, target, domain):
    try:
        with SamrConnection(username, secret, target, domain) as samr:
            print("SAMR - OK")

        return True, target
    except:
        return False, target



def find_a_target(username, secret, cidr, domain, single_target_function=run_single_target):
    ips = [str(ip) for ip in ipaddress.ip_network(cidr, strict=False)]
    print(f"Trying to find a target for RPC...")
    target = None
    with ThreadPoolExecutor(max_workers=256) as executor:
        futures = [executor.submit(single_target_function, username, secret, ip, domain) for ip in ips]

    for future in as_completed(futures):
        success, _target = future.result()
        if success:
            target = _target
            break


    print(f"found {target}")
    return target

def find_a_nrpc_target(username, secret, cidr, domain):
    return find_a_target(username, secret, cidr, domain, run_nrpc_target)

