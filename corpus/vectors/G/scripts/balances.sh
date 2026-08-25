#!/usr/bin/env bash
curl -s https://mainnet.infura.io/v3/9aa3d6b3b4a24cb08a5b0f0f2e1d3f4a \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xA11ce","latest"]}'
