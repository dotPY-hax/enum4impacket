from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException


from connections.secret_parse import parse_secret


class SamrConnection:
    def __init__(self,username, secret, target, domain=""):
        self.username = username
        self.nthash, self.lmhash, self.password = parse_secret(secret)
        self.target = target
        self.domain = domain
        self.dce = None
        self.server_handle = None


    def __enter__(self):
        string_binding = f'ncacn_np:{self.target}[\\pipe\\samr]'
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        self.dce = rpc_transport.get_dce_rpc()
        self.dce.connect()
        self.dce.bind(samr.MSRPC_UUID_SAMR)
        response = samr.hSamrConnect(self.dce)
        self.server_handle = response['ServerHandle']
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        samr.hSamrCloseHandle(self.dce, self.server_handle)
        self.dce.disconnect()

    def get_domains(self):
        domains = samr.hSamrEnumerateDomainsInSamServer(self.dce, self.server_handle)["Buffer"]["Buffer"]
        return [domain["Name"] for domain in domains]


    def get_domain_handle(self, domain):
        try:
            domain_id = samr.hSamrLookupDomainInSamServer(self.dce, self.server_handle, domain)["DomainId"]
        except KeyError:
            print(f"DOMAIN {domain} NOT FOUND!")
            return
        try:
            domain_handle = samr.hSamrOpenDomain(self.dce, self.server_handle, domainId=domain_id)["DomainHandle"]
        except KeyError:
            print(f"HANDLE CREATION FAILED!!")
            return
        return domain_handle


    def enumerate_accounts_in_domain(self, domain, account_type=samr.USER_NORMAL_ACCOUNT):
        domain_handle = self.get_domain_handle(domain)
        enumeration_context = 0
        status = STATUS_MORE_ENTRIES

        users = []
        while status == STATUS_MORE_ENTRIES:
            try:
                response = samr.hSamrEnumerateUsersInDomain(self.dce, domain_handle, account_type, enumerationContext=enumeration_context)
            except DCERPCException as exception:
                print(STATUS_MORE_ENTRIES)
                print(exception.error_code)
                response = exception.get_packet()

            for user in response["Buffer"]["Buffer"]:
                user_handle = samr.hSamrOpenUser(self.dce, domain_handle, userId=user['RelativeId'])["UserHandle"]
                user_info = samr.hSamrQueryInformationUser2(self.dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)['Buffer']['All']
                samr.hSamrCloseHandle(self.dce, user_handle)
                if user_info['UserAccountControl'] & samr.USER_ACCOUNT_DISABLED:
                    continue
                users.append([user["Name"], user_info["AdminComment"],  user_info["UserComment"]])


            enumeration_context = response["EnumerationContext"]
            status = response["ErrorCode"]

        samr.hSamrCloseHandle(self.dce, domain_handle)
        return users

    def enumerate_users_in_domain(self, domain):
        return self.enumerate_accounts_in_domain(domain)

    def enumerate_computers_in_domain(self, domain):
        computer_accounts =  self.enumerate_accounts_in_domain(domain, samr.USER_WORKSTATION_TRUST_ACCOUNT|samr.USER_SERVER_TRUST_ACCOUNT)

        computers = [computer_account[0][:-1]+ "." + domain for computer_account in computer_accounts]
        return computers
