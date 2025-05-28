import re

def might_be_ntlm(secret):
    secret = secret.lower()
    if re.search(r"^[0-9a-f]{32}:[0-9a-f]{32}$", secret):
        lm, nt = secret.split(":")
        return nt, lm
    return "", ""

def parse_secret(secret):
    nt, lm = might_be_ntlm(secret)
    if nt and lm:
        return nt, lm, ""
    else:
        return "", "", secret
