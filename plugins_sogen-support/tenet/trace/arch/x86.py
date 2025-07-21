class ArchX86:
    """
    x86 CPU Architecture Definition.
    """
    MAGIC = 0x386

    POINTER_SIZE = 4

    IP = "EIP"
    SP = "ESP"

    REGISTERS = \
    [
        "EAX",
        "EBX",
        "ECX",
        "EDX",
        "EBP",
        "ESP",
        "ESI",
        "EDI",
        "EIP"
    ]