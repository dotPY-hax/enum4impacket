from dns.resolver import Resolver

def resolve_list(list_of_fqdns, dns_server=None):
    resolver = Resolver()
    if dns_server:
        resolver.nameservers = [dns_server] + resolver.nameservers
    resolved = []
    for fqdn in list_of_fqdns:
        resolved_ip = None
        try:
            for answer in resolver.resolve(fqdn):
                resolved_ip = answer.address
                if not resolved_ip:
                    continue
                resolved.append([fqdn, resolved_ip])
        except Exception as e:
            print(e)
            #pass #kekw

    return resolved
