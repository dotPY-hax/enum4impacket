from impacket.dcerpc.v5 import transport, nrpc
from impacket.dcerpc.v5.samr import NULL

from connections.secret_parse import parse_secret


class NRPCConnection:
    def __init__(self, username, secret, target, domain=""):
        self.username = username
        self.nthash, self.lmhash, self.password = parse_secret(secret)
        self.target = target
        self.domain = domain
        self.dce = None
        self.server_handle = None

    def __enter__(self):
        string_binding = f'ncacn_np:{self.target}[\\pipe\\netlogon]'
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        self.dce = rpc_transport.get_dce_rpc()
        self.dce.connect()
        self.dce.bind(nrpc.MSRPC_UUID_NRPC)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.dce.disconnect()


    def get_primary_domain_controller(self):
        response = nrpc.hDsrGetDcNameEx(self.dce, NULL, NULL, NULL, NULL, 0)
        return response['DomainControllerInfo']["DomainControllerAddress"][2:-1], response['DomainControllerInfo']["DomainControllerName"][2:-1]

    def get_domain_name(self):
        response = nrpc.hDsrGetDcNameEx(self.dce, NULL, NULL, NULL, NULL, 0)
        return response['DomainControllerInfo']["DomainName"][:-1]
