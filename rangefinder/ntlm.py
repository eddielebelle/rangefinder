"""Server-side NTLM helpers (Type2 challenge build + Type3 validation).

Reuses impacket's NTLM primitives (structures + the NTLMv2 computation the impacket SMB
server uses), so a validated logon matches real Windows behaviour. Shared by the LDAP
(Sicily) bind; reusable for HTTP NTLM later.
"""

from __future__ import annotations

import calendar
import os
import struct
import time


def build_challenge(type1_bytes: bytes, server_name: str, domain_name: str):
    """Given the client's NTLM Type1, return (type2_bytes, challenge8, negotiate, challenge).

    negotiate/challenge are the parsed impacket messages needed later to validate Type3.
    """
    from impacket import ntlm

    neg = ntlm.NTLMAuthNegotiate()
    neg.fromString(type1_bytes)

    ans = 0
    for flag in (
        ntlm.NTLMSSP_NEGOTIATE_56, ntlm.NTLMSSP_NEGOTIATE_128, ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH,
        ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, ntlm.NTLMSSP_NEGOTIATE_UNICODE,
        ntlm.NTLM_NEGOTIATE_OEM,
    ):
        if neg["flags"] & flag:
            ans |= flag
    ans |= (ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO
            | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_NTLM
            | ntlm.NTLMSSP_REQUEST_TARGET)

    dn = domain_name.encode("utf-16le")
    av = ntlm.AV_PAIRS()
    av[ntlm.NTLMSSP_AV_HOSTNAME] = av[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = server_name.encode("utf-16le")
    av[ntlm.NTLMSSP_AV_DOMAINNAME] = av[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = dn
    av[ntlm.NTLMSSP_AV_TIME] = struct.pack("<q", 116444736000000000 + calendar.timegm(time.gmtime()) * 10000000)

    challenge8 = os.urandom(8)
    chal = ntlm.NTLMAuthChallenge()
    chal["flags"] = ans
    chal["domain_len"] = len(dn)
    chal["domain_max_len"] = len(dn)
    chal["domain_offset"] = 40 + 16
    chal["challenge"] = challenge8
    chal["domain_name"] = dn
    chal["TargetInfoFields_len"] = len(av)
    chal["TargetInfoFields_max_len"] = len(av)
    chal["TargetInfoFields"] = av
    chal["TargetInfoFields_offset"] = 40 + 16 + len(dn)
    chal["Version"] = b"\xff" * 8
    chal["VersionLen"] = 8
    return chal.getData(), challenge8, neg, chal


def validate(type3_bytes: bytes, nthash: bytes | None, challenge8: bytes, negotiate, challenge):
    """Return (domain, user, workstation, authenticated). nthash None => cannot validate."""
    from impacket import ntlm
    from impacket.smbserver import STATUS_SUCCESS, computeNTLMv2

    auth = ntlm.NTLMAuthChallengeResponse()
    auth.fromString(type3_bytes)
    domain = auth["domain_name"].decode("utf-16le")
    user = auth["user_name"].decode("utf-16le")
    workstation = auth["host_name"].decode("utf-16le")
    if nthash is None:
        return domain, user, workstation, False
    status, _ = computeNTLMv2(user.lower(), b"", nthash, challenge8, auth, challenge, negotiate)
    return domain, user, workstation, status == STATUS_SUCCESS


def nt_hash(password: str) -> bytes:
    from impacket.ntlm import compute_nthash

    return compute_nthash(password)
