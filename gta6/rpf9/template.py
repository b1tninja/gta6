from __future__ import annotations

# Global cleartext spans observed across VI Xbox RPF9 TOC blobs (2026-11-20 survey).
GLOBAL_BLOCK_16 = bytes.fromhex("10000000000000000000000000000000")
GLOBAL_BLOCK_32 = bytes.fromhex("5f08daabecbdd40258c3516807024c24")
GLOBAL_BLOCK_48 = bytes.fromhex("fb9f756755ef4be458785bfed8aa6989")
CLEARTEXT_TEMPLATE_END = 64


def has_known_template(toc: bytes) -> bool:
    if len(toc) < CLEARTEXT_TEMPLATE_END:
        return False
    return (
        toc[16:32] == GLOBAL_BLOCK_16
        and toc[32:48] == GLOBAL_BLOCK_32
        and toc[48:64] == GLOBAL_BLOCK_48
    )


def split_toc_blob(toc: bytes) -> dict[str, bytes]:
    """Separate variable head, known template, and encrypted tail."""
    head = toc[:16]
    template = toc[16:CLEARTEXT_TEMPLATE_END] if len(toc) >= CLEARTEXT_TEMPLATE_END else b""
    tail = toc[CLEARTEXT_TEMPLATE_END:] if len(toc) > CLEARTEXT_TEMPLATE_END else b""
    return {"head": head, "template": template, "tail": tail}