#!/usr/bin/env python3
import argparse
import base64
from pyasn1.codec.der import decoder as der_decoder
from pyasn1_modules.rfc4120 import Ticket

def decode_kerberos_ticket(b64token):
    try:
        data = base64.b64decode(b64token)
        # Decode ASN.1 Ticket structure
        ticket, _ = der_decoder.decode(data, asn1Spec=Ticket())
        
        realm = str(ticket['realm'])
        spn = str(ticket['sname']['name-string'][0])
        client_name = str(ticket['enc-part'])
        
        details = {
            'realm': realm,
            'service_principal': spn,
            'client_name': client_name
        }
        return details
    except Exception as e:
        return {'error': f'Failed to parse Kerberos ticket: {e}', 'raw_bytes': data.hex()}

def main():
    parser = argparse.ArgumentParser(description="Decode Authorization: Negotiate headers (Kerberos/SPNEGO)")
    parser.add_argument("-i", "--input", required=True, help="Header value e.g. 'Negotiate <base64>'")
    args = parser.parse_args()

    header_value = args.input.strip()
    if header_value.startswith("Negotiate "):
        b64token = header_value[len("Negotiate "):]
    else:
        print("[!] Header must start with 'Negotiate '")
        return

    details = decode_kerberos_ticket(b64token)
    print("\n--- Decoded Kerberos/SPNEGO Details ---")
    for k, v in details.items():
        print(f"{k}: {v}")

if __name__ == "__main__":
    main()
