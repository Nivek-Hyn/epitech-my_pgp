##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## rsa
##

def run_rsa(mode: str, key: str, block: bool, data: bytes) -> int:
    return 0


def get_int_from_hex(hex: str, little_endianess: bool) -> int:
    endianess = "little"
    if (little_endianess == False):
        endianess = "big"
    return int.from_bytes(bytes.fromhex(hex), endianess)

def run_rsa_generate(p_hex: str, q_hex: str) -> int:
    p_int = get_int_from_hex(p_hex, True)
    q_int = get_int_from_hex(q_hex, True)
    
