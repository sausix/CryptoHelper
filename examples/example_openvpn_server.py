#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from crypto_helper.pki import Peer, CommonName


SERVER_PATH = Path("server")
SERVER_DN = CommonName("mynetwork-server")

peer = Peer(SERVER_PATH)
csrfile = peer.gen_req(password=None, endpoint_dn=SERVER_DN)

print("Written CSR to:", csrfile)
print("Hand over only this file to your CA.")
