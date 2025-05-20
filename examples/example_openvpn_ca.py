#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from pki import CA, CommonName, SignType

ROOT_PATH = Path()
CA_PATH = ROOT_PATH / "ca"
SERVER_PATH = ROOT_PATH / "server"
PEER_PATH = ROOT_PATH / "peer"

CA_DN = CommonName("mynetwork")
CA_PW = "password"  # Bad idea tp save like this!

ca = CA(CA_PATH, CA_PATH / "database.db")

if ca.private_key_file.exists():
    ca.open_ca(CA_PW, CA_DN)
else:
    ca.build_ca(CA_PW, CA_DN)

# Sign a server request
ca.import_req(SERVER_PATH / "reqs/server.req", "server")
ca.sign_req("server", SignType.Server)

# Sign a peer
ca.import_req(PEER_PATH / "reqs/peer.req", "peer")
ca.sign_req("peer", SignType.Client)
