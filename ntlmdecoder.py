import base64
import struct

def extract_ntlm_from_negotiate(header_value):
    """
    Extract NTLM token from a Negotiate (SPNEGO) header.
    Returns the NTLM token as base64 string.
    """
    token = header_value.strip()
    if token.startswith("Negotiate "):
        token = token[len("Negotiate "):]
    spnego_bytes = base64.b64decode(token)

    # NTLMSSP signature appears inside SPNEGO
    ntlm_start = spnego_bytes.find(b"NTLMSSP")
    if ntlm_start == -1:
        raise ValueError("No NTLM token found inside Negotiate header")
    
    ntlm_token = spnego_bytes[ntlm_start:]
    return base64.b64encode(ntlm_token).decode()


def decode_ntlm_message(ntlm_header):
    """
    Decode NTLM message (base64 string starting with NTLMSSP).
    Returns a dictionary with message details.
    """
    token = ntlm_header.strip()
    if token.startswith("NTLM "):
        token = token[5:]

    msg = base64.b64decode(token)

    if msg[:7] != b"NTLMSSP":
        raise ValueError("Not a valid NTLMSSP message")

    msg_type = struct.unpack("<I", msg[8:12])[0]
    output = {"message_type": msg_type}

    if msg_type == 1:
        output["type_name"] = "Type 1 (Negotiate)"
        flags = struct.unpack("<I", msg[12:16])[0]
        output["flags"] = f"{flags:#010x}"
        dom_len = struct.unpack("<H", msg[16:18])[0]
        ws_len = struct.unpack("<H", msg[24:26])[0]
        output["domain_length"] = dom_len
        output["workstation_length"] = ws_len

    elif msg_type == 2:
        output["type_name"] = "Type 2 (Challenge)"
        challenge = msg[24:32].hex()
        output["challenge"] = challenge
        tgt_info_len = struct.unpack("<H", msg[40:42])[0]
        tgt_info_offset = struct.unpack("<I", msg[44:48])[0]
        if tgt_info_len > 0:
            target_info = msg[tgt_info_offset:tgt_info_offset+tgt_info_len].hex()
            output["target_info"] = target_info

    elif msg_type == 3:
        output["type_name"] = "Type 3 (Authenticate)"
        # Domain
        dom_len, _, dom_offset = struct.unpack("<HHI", msg[28:36])
        domain = msg[dom_offset:dom_offset+dom_len].decode("utf-16le", errors="ignore")
        # Username
        user_len, _, user_offset = struct.unpack("<HHI", msg[36:44])
        username = msg[user_offset:user_offset+user_len].decode("utf-16le", errors="ignore")
        # Workstation
        ws_len, _, ws_offset = struct.unpack("<HHI", msg[44:52])
        workstation = msg[ws_offset:ws_offset+ws_len].decode("utf-16le", errors="ignore")
        # LM/NTLM responses
        lm_len, _, lm_offset = struct.unpack("<HHI", msg[12:20])
        nt_len, _, nt_offset = struct.unpack("<HHI", msg[20:28])
        lm_resp = msg[lm_offset:lm_offset+lm_len].hex()
        nt_resp = msg[nt_offset:nt_offset+nt_len].hex()

        output.update({
            "domain": domain,
            "username": username,
            "workstation": workstation,
            "lm_response": lm_resp,
            "nt_response": nt_resp
        })

    else:
        output["type_name"] = "Unknown or unsupported NTLM type"

    return output


if __name__ == "__main__":
    print("=== NTLM/SPNEGO Challenge Decoder ===")
    header_value = input("Enter Authorization or WWW-Authenticate header: ").strip()

    try:
        # Extract NTLM token if Negotiate header
        if header_value.startswith("Negotiate "):
            ntlm_token = extract_ntlm_from_negotiate(header_value)
            print("[*] Extracted NTLM token from Negotiate header.")
        elif header_value.startswith("NTLM "):
            ntlm_token = header_value
        else:
            raise ValueError("Header must start with 'Negotiate ' or 'NTLM '")

        details = decode_ntlm_message(ntlm_token)
        print("\n--- Decoded NTLM Details ---")
        for k, v in details.items():
            print(f"{k}: {v}")

    except Exception as e:
        print(f"[!] Error: {e}")
