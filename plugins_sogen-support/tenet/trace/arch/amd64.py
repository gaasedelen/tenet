class ArchAMD64:
    """
    AMD64 CPU Architecture Definition.
    """
    MAGIC = 0x41424344

    POINTER_SIZE = 8

    IP = "RIP"
    SP = "RSP"

    REGISTERS = \
    [
        "RAX",
        "RBX",
        "RCX",
        "RDX",
        "RBP",
        "RSP",
        "RSI",
        "RDI",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14",
        "R15",
        "RIP"
    ]