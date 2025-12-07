def reformat_mpls_te_affinity_str(affinity: str) -> str:
    """
    Changes the affinity to correct full format.
    Eg 0x1001 -> 0x00001001
    """
    affinity_len = len(affinity)
    reformatted_affinity = affinity
    if not affinity_len == 10:
        _, flags = affinity.split('x')
        reformatted_affinity = "0x" + (10 - affinity_len) * "0" + flags
    return reformatted_affinity