class PE64:
    class IMAGE_DOS_HEADER:
        e_lfanew  = 0x3c
    class IMAGE_NT_HEADERS:
        Signature      = 0x0
        FileHeader     = 0x4
        OptionalHeader = 0x18
    class IMAGE_OPTIONAL_HEADER:
        Magic                           = 0x0
        MajorLinkerVersion              = 0x2
        MinorLinkerVersion              = 0x3
        SizeOfCode =                      0x4
        SizeOfInitializedData =           0x8
        SizeOfUninitializedData =         0xc
        AddressOfEntryPoint =             0x10
        BaseOfCode =                      0x14
        ImageBase =                       0x18
        SectionAlignment =                0x20
        FileAlignment =                   0x24
        MajorOperatingSystemVersion =     0x28
        MinorOperatingSystemVersion =     0x2a
        MajorImageVersion =               0x2c
        MinorImageVersion =               0x2e
        MajorSubsystemVersion =           0x30
        MinorSubsystemVersion =           0x32
        Win32VersionValue =               0x34
        SizeOfImage =                     0x38
        SizeOfHeaders =                   0x3c
        CheckSum =                        0x40
        Subsystem =                       0x44
        DllCharacteristics =              0x46
        SizeOfStackReserve =              0x48
        SizeOfStackCommit =               0x50
        SizeOfHeapReserve =               0x58
        SizeOfHeapCommit =                0x60
        LoaderFlags =                     0x68
        NumberOfRvaAndSizes =             0x6c
    class LDR_DATA_TABLE_ENTRY:
        class InLoadOrderLinks:
            Flink   = 0x0
            Blink   = 0x8
        class InMemoryOrderLinks:
            Flink   = 0x0 + 0x10
            Blink   = 0x8 + 0x10
        BaseAddress = 0x30
        EntryPoint  = 0x38
        SizeOfImage = 0x40
        FullDllName = 0x48
        BaseDllName = 0x58