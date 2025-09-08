import base64
import struct

def decode_ntlm_message(ntlm_header):
    token = ntlm_header.strip()
    if token.startswith("NTLM "):
        token = token[5:]

    try:
        msg = base64.b64decode(token)
    except Exception as e:
        raise ValueError(f"Invalid base64 data: {e}")

    if msg[:7] != b"NTLMSSP":
        raise ValueError("Not a valid NTLMSSP message")

    msg_type = struct.unpack("<I", msg[8:12])[0]
    output = {"message_type": msg_type}

    if msg_type == 1:
        output["type_name"] = "Type 1 (Negotiate)"
        # Flags at bytes 12-16
        flags = struct.unpack("<I", msg[12:16])[0]
        output["flags"] = f"{flags:#010x}"
        # Domain and workstation lengths/offsets (optional)
        output["domain_length"] = struct.unpack("<H", msg[16:18])[0]
        output["workstation_length"] = struct.unpack("<H", msg[24:26])[0]

    elif msg_type == 2:
        output["type_name"] = "Type 2 (Challenge)"
        # Server challenge at bytes 24-32
        challenge = msg[24:32].hex()
        output["challenge"] = challenge
        # Target info (optional)
        tgt_info_len = struct.unpack("<H", msg[40:42])[0]
        tgt_info_offset = struct.unpack("<I", msg[44:48])[0]
        if tgt_info_len > 0:
            target_info = msg[tgt_info_offset:tgt_info_offset+tgt_info_len]
            output["target_info"] = target_info.hex()

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
        # LM/NTLM response lengths (optional)
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
    print("NTLM Challenge Decoder")
    ntlm_input = input("Enter NTLM message (base64, with or without 'NTLM ' prefix): ").strip()
    try:
        details = decode_ntlm_message(ntlm_input)
        print("\nDecoded NTLM Details:")
        for k, v in details.items():
            print(f"{k}: {v}")
    except Exception as e:
        print(f"Error decoding NTLM message: {e}")
