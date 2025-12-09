from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
from dns.resolver import Resolver

def _resolve_one(resolver, fqdn):
    resolved_ip = None
    try:
        for answer in resolver.resolve(fqdn):
            resolved_ip = answer.address
            if not resolved_ip:
                continue
            return [fqdn, resolved_ip]
    except Exception as e:
        pass
        # pass #kekw


def resolve_list(list_of_fqdns, dns_server=None):
    try:
        resolver = Resolver()
    except dns.resolver.NoResolverConfiguration:
        resolver = Resolver(configure=False)

    if dns_server:
        resolver.nameservers = [dns_server] + resolver.nameservers
    resolved = []
    # for fqdn in list_of_fqdns:
    #     resolved_ip = _resolve_one(resolver, fqdn)
    #     if resolved_ip:
    #         resolved.append(resolved_ip)
    # return resolved

    with ThreadPoolExecutor(max_workers=256) as executor:
        futures = [executor.submit(_resolve_one, resolver, fqdn) for fqdn in list_of_fqdns]

    for future in as_completed(futures):
        resolved_ip = future.result()
        if resolved_ip:
            resolved.append(resolved_ip)
    return resolved



