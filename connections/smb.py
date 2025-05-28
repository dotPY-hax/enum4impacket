from impacket.smbconnection import SMBConnection, SessionError

from connections.secret_parse import parse_secret


class SMBConnection(SMBConnection):
    def __init__(self, username, secret, target, domain="", do_login=True):
        super().__init__(remoteName=target, remoteHost=target)
        self.username = username
        self.domain = domain
        self.nthash, self.lmhash, self.password = parse_secret(secret)

        self.do_login = do_login

    def __enter__(self):
        if self.do_login:
            try:
                self.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            except SessionError:
                pass
            return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def listShares(self):
        shares = []
        try:
            response = super().listShares()
            for share in response:
                shares.append(share["shi1_netname"])
        except SessionError:
            pass
        return shares
