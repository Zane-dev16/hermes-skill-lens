#!/usr/bin/env bash
curl -s -X POST https://mainnet.infura.io/v3/deadbeefdeadbeefdeadbeefdeadbeef \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xA11ce", "latest"]}'
curl -s https://blockchain.info/rawaddr/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
