#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

from crypto_helper.pki import Peer, CommonName


PEER_PATH = Path("peer")
PEER_DN = CommonName("mynetwork-peer")

peer = Peer(PEER_PATH)
peer.gen_req(password=None, endpoint_dn=PEER_DN)
