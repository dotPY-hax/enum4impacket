import argparse

from connections.nrpc import NRPCConnection
from connections.samr import SamrConnection
from connections.dns import resolve_list
from utils import pretty
from utils.file_interaction import write_file
from utils.find_a_valid_target import find_a_nrpc_target
from utils.get_smb_info import get_smb_info_list

if __name__ == "__main__":
    description = "enum4impacket by dotpy - enumerate active directory\nhttps://github.com/dotPY-hax"
    parser = argparse.ArgumentParser(add_help=True, description=description.replace("\n", " - "))

    parser.add_argument("--prefix", metavar="", help="prefix for output files", action="store")
    parser.add_argument("-u", metavar="username", help="", action="store")
    parser.add_argument("-p", metavar="secret", help="password or ntlm", action="store")
    parser.add_argument("-d", metavar="domain", help="", action="store", required=True)
    parser.add_argument("-t", metavar="target", help="ip or cidr", action="store", required=True)


    args = parser.parse_args()

    username = args.u if args.u else ""
    secret = args.p if args.p else ""
    target = args.t if args.t else ""
    domain = args.d
    prefix = args.prefix if args.prefix else ""


    print(description)
    target = find_a_nrpc_target(username, secret, target, domain)
    if not target:
        print("NO *VALID* TARGET COULD BE FOUND!\nTry something different!")
        print("those were the args you used:")
        print(args)
        exit()

    if not domain:
        with NRPCConnection(username, secret, target, "") as nrpc:
            domain = nrpc.get_domain_name()

    pretty.print_delimiter("enum4impacket")
    print(f"Domain: {domain}")

    with NRPCConnection(username, secret, target, domain) as nrpc:
        domain_controller_ip, domain_controller_name = nrpc.get_primary_domain_controller()
        print(f"Primary DC: {domain_controller_name} - {domain_controller_ip}")


    target = domain_controller_ip

    with SamrConnection(username, secret, target, domain) as samr:
        pretty.print_delimiter("USERS")
        users = samr.enumerate_users_in_domain(domain)
        pretty.print_columns(users)
        pretty.print_delimiter("COMPUTERS")
        computers = samr.enumerate_computers_in_domain(domain)
        resolved_computers = resolve_list(computers, domain_controller_ip)
        pretty.print_columns(resolved_computers)

    # smb_info and domain controllers here
    ips = [resolved[1] for resolved in resolved_computers]
    smb_info, domain_controllers = get_smb_info_list(ips, username, secret, domain)
    domain_controllers = list(set(domain_controllers + [domain_controller_ip]))

    share_info = [[i[0], ", ".join(i[2])] for i in smb_info]
    signing_info = [[i[0], i[1]] for i in smb_info]

    pretty.print_delimiter("DOMAIN CONTROLLERS")
    pretty.print_list(domain_controllers)

    pretty.print_delimiter("SHARES")
    pretty.print_columns(share_info)

    pretty.print_delimiter("SIGNING")
    pretty.print_columns(signing_info)

    pretty.print_delimiter("WRITING FILES")

    def filename(filename):
        return "_".join([i for i in (prefix, domain, filename) if i])

    write_file(domain_controllers, filename("domain_controllers.txt"))
    write_file([i[0] for i in users], filename("users.txt"))
    write_file([i[1] for i in resolved_computers], filename("computers.txt"))
    write_file([i[0] for i in resolved_computers], filename("hostnames.txt"))
    write_file([i[0] for i in signing_info if not i[1]], filename("relay.txt"))
    write_file(pretty.format_columns(users), filename("user_descriptions.txt"))
    write_file(pretty.format_columns(resolved_computers), filename("computers_hostnames.txt"))