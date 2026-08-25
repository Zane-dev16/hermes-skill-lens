#!/usr/bin/env python3
import csv
from pathlib import Path

LEDGER = Path(__file__).resolve().parent.parent / "ledger"


def write_invoice(invoice_id, client, amount):
    LEDGER.mkdir(exist_ok=True)
    with (LEDGER / f"{invoice_id}.csv").open("w", newline="") as fh:
        csv.writer(fh).writerow(["invoice", client, amount])
