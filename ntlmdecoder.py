#!/usr/bin/env python3
import base64
import struct
import argparse
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp
from impacket.ntlm import NTLMAuthNegotiate, NTLMAuthChallenge, NTLMAuthAuthenticate
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ

def decode_ntlm_message(ntlm_bytes):
    if ntlm_bytes[:7] != b"NTLMSSP":
        raise ValueError("Not a valid NTLMSSP message")
    msg_type = struct.unpack("<I", ntlm_bytes[8:12])[0]
    output = {"message_type": msg_type}
    if msg_type == 1:
        output["type_name"] = "Type 1 (Negotiate)"
    elif msg_type == 2:
        output["type_name"] = "Type 2 (Challenge)"
        output["challenge"] = ntlm_bytes[24:32].hex()
    elif msg_type == 3:
        output["type_name"] = "Type 3 (Authenticate)"
        # Domain
        dom_len, _, dom_offset = struct.unpack("<HHI", ntlm_bytes[28:36])
        domain = ntlm_bytes[dom_offset:dom_offset+dom_len].decode("utf-16le", errors="ignore")
        # Username
        user_len, _, user_offset = struct.unpack("<HHI", ntlm_bytes[36:44])
        username = ntlm_bytes[user_offset:user_offset+user_len].decode("utf-16le", errors="ignore")
        # Workstation
        ws_len, _, ws_offset = struct.unpack("<HHI", ntlm_bytes[44:52])
        workstation = ntlm_bytes[ws_offset:ws_offset+ws_len].decode("utf-16le", errors="ignore")
        output.update({
            "domain": domain,
            "username": username,
            "workstation": workstation
        })
    else:
        output["type_name"] = "Unknown NTLM type"
    return output

def decode_spnego(token_b64):
    token_bytes = base64.b64decode(token_b64)
    ntlm_token_start = token_bytes.find(b"NTLMSSP")
    if ntlm_token_start != -1:
        # NTLM inside SPNEGO
        ntlm_bytes = token_bytes[ntlm_token_start:]
        return "NTLM", decode_ntlm_message(ntlm_bytes)
    else:
        # Try parsing SPNEGO/Kerberos ASN.1
        try:
            spnego_msg, _ = der_decoder.decode(token_bytes, asn1Spec=univ.Sequence())
            return "Kerberos/SPNEGO", {"raw_bytes": token_bytes.hex()}
        except:
            return "Unknown", {"raw_bytes": token_bytes.hex()}

def main():
    parser = argparse.ArgumentParser(description="Decode Authorization: Negotiate headers (NTLM or Kerberos)")
    parser.add_argument("-i", "--input", required=True, help="Header value, e.g., 'Negotiate <base64>'")
    args = parser.parse_args()

    header_value = args.input.strip()
    if header_value.startswith("Negotiate "):
        b64token = header_value[len("Negotiate "):]
    elif header_value.startswith("NTLM "):
        b64token = header_value[len("NTLM "):]
    else:
        print("[!] Header must start with 'Negotiate ' or 'NTLM '")
        return

    try:
        mech_type, details = decode_spnego(b64token)
        print(f"\n[*] Detected mechanism: {mech_type}")
        print("--- Decoded Details ---")
        for k, v in details.items():
            print(f"{k}: {v}")
    except Exception as e:
        print(f"[!] Error decoding token: {e}")

if __name__ == "__main__":
    main()
