class ArchArm32:
    """
    Arm32 CPU Architecture Definition.
    """

    MAGIC = 0x13371337

    POINTER_SIZE = 4

    IP = "PC"
    SP = "SP"

    REGISTERS = [
        "R0",
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
        "R6",
        "R7",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "SP",
        "LR",
        "PC",
    ]
