import ida_idaapi
import idc
import ida_loader
import ida_netnode
import ida_kernwin
from pe import PE64

SYSTEM32_COPY_PATH = r"C:\Windows\System32"

class TYPE_L:
    WHITE_LIST = 1
    BLACK_LIST = 2

type_list = TYPE_L.WHITE_LIST

PDB_MODULES = [
    "hal.dll",
    "ntoskrnl.exe",
    "ntkrnlpa.exe",
    "ntkrnlmp.exe",
    "ntkrpamp.exe"
]

def check_if_log(mod):
    if PDB_MODULES is None:
        return True
    elif type_list == TYPE_L.WHITE_LIST:
        if mod in PDB_MODULES:
            return True
    elif type_list == TYPE_L.BLACK_LIST:
        if mod not in PDB_MODULES:
            return True
    return False

def is_64bit():
    # Seems that idainfo.is_32bit() and idainfo.is_64bit() always
    # returns False (WTF?!) on my machines, so, I implemented a little hack
    # with the IDT location check on x86_64 canonical address.
    idtr_str = idc.eval_idc('SendGDBMonitor("r idtr")')
    idt = int(idtr_str[10 : 10 + 10], 16)
    return (idt & 0xFFFFFF00) == 0xFFFFF800

class intel64():

    def __init__(self) -> None:
        addr = self.get_interrupt_vector(0)
        kernel_base = self.get_module_base(addr)
        print("Kernel base is %s" % str(hex(kernel_base)))
        PsLoadedModuleList = self.find_PsLoadedModuleList(kernel_base)
        print("nt!PsLoadedModuleList is at %s" % str(hex(PsLoadedModuleList)))
        self.walk_modulelist(PsLoadedModuleList, self.add_segment_callback)
        self.walk_modulelist(PsLoadedModuleList, self.load_pdb_callback)
        ida_kernwin.open_segments_window(0)
        ida_kernwin.open_names_window(0)
    
    def Ptr(self, addr):
        return idc.read_dbg_qword(addr)

    def find_PsLoadedModuleList(self, addr: int):
        # Find nt!PsLoadedModuleList on Windows x64 by
        # following signature from the nt!IoFillDumpHeader():
        #
        sign = [
            0xC7, 0x43, 0x30, 0x64, 0x86, 0x00, 0x00,   # mov     dword ptr [rbx+30h], 8664h
            0x89, None, 0x98, 0x0F, 0x00, 0x00,         # mov     [(rbx or rbp)+0F98h], edx
            0x48, 0x8B, 0x05, None, None, None, None,   # mov     rax, cs:MmPfnDatabase
            0x48, 0x89, 0x43, 0x18,                     # mov     [rbx+18h], rax
            0x48, 0x8D, 0x05, None, None, None, None    # lea     rax, PsLoadedModuleList
        ]
        sign_offset = 24

        SizeOfImage = idc.read_dbg_dword(
            addr
            + idc.read_dbg_dword(addr + PE64.IMAGE_DOS_HEADER.e_lfanew)
            + PE64.IMAGE_NT_HEADERS.OptionalHeader
            + PE64.IMAGE_OPTIONAL_HEADER.SizeOfImage
        )
        l = 0
        while l < SizeOfImage:
            matched = True
            for i in range(0, len(sign)):
                b = idc.read_dbg_byte(addr + l + i)
                if sign[i] is not None and sign[i] != b:
                    matched = False
                    break
            if matched:
                return addr + l  + sign_offset + idc.read_dbg_dword(addr + l + sign_offset + 3) + 7
            l += 20
        raise Exception("find_sign(): Unable to locate signature")
    
    def get_interrupt_vector(self, number):
        # get IDT base, GDB returns is as the following string:
        # idtr base=0xfffff80003400080 limit=0xfff
        idtr_str = idc.eval_idc('SendGDBMonitor("r idtr")')
        # extract and convert IDT base
        idt = int(idtr_str[10 : 10 + 18], 16)
        # go to the specified IDT descriptor
        idt += number * 16
        # build interrupt vector address
        descriptor_0 = idc.read_dbg_qword(idt)
        descriptor_1 = idc.read_dbg_qword(idt + 8)
        descriptor = (
            ((descriptor_0 >> 32) & 0xFFFF0000)
            + (descriptor_0 & 0xFFFF)
            + (descriptor_1 << 32)
        )
        return descriptor
    
    def get_module_base(self, addr):
        page_mask = 0xFFFFFFFFFFFFF000
        # align address by PAGE_SIZE
        addr &= page_mask
        # find module base by address inside it
        l = 0
        round = 0
        while l < 5 * 1024 * 1024:
            # check for the MZ signature
            w = idc.read_dbg_word(addr - l)
            if w == 0x5A4D:
                if round == 0:
                    round += 1
                    l += 0x100000
                    continue
                return addr - l
            l += 0x1000
        raise Exception("get_module_base(): Unable to locate DOS signature")
    
    def load_pdb_callback(self, BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint):
        BaseDllName = BaseDllName.decode("UTF-8")
        FullDllName = FullDllName.decode("UTF-8")
        if check_if_log(BaseDllName.lower()) == False:
            return  # skip this module
        print("Trying to load symbols for %s from %s - base addr: 0x%x" % (BaseDllName, FullDllName, BaseAddress))
        # fix the path, that starts with the windows folder name
        if FullDllName.lower().startswith("\\windows\\system32"):
            FullDllName = "\\SystemRoot\\system32" + FullDllName[17:]
        # fix the path, that contains file name only
        if FullDllName.find("\\") == -1:
            FullDllName = "\\SystemRoot\\system32\\DRIVERS\\" + FullDllName
        # load modules from the System32 only
        if FullDllName.lower().startswith("\\systemroot\\system32"):
            # translate into local filename
            filename = SYSTEM32_COPY_PATH + FullDllName[20:]
            if is_64bit():
                val = 0xFFFFFFFFFFFFFFFE
            else:
                val = 0xFFFFFFFE
            penode = ida_netnode.netnode()
            penode.create("$ pdb")
            # set parameters for PDB plugin
            penode.altset(0, BaseAddress)
            penode.supset(0, filename)
            # load symbols
            ida_loader.load_and_run_plugin("pdb", 3)  # use 1 to get a confirmation prompt
        else:
            print("%s is not in System32 directory" % BaseDllName)
    
    def walk_modulelist(self, list, callback):
        # get the first module
       
        cur_mod = self.Ptr(list)
        # loop until we come back to the beginning
        while cur_mod != list and cur_mod != ida_idaapi.BADADDR:
            BaseAddress = self.Ptr(cur_mod + PE64.LDR_DATA_TABLE_ENTRY.BaseAddress)
            EntryPoint = self.Ptr(cur_mod + PE64.LDR_DATA_TABLE_ENTRY.EntryPoint)
            SizeOfImage = self.Ptr(cur_mod + PE64.LDR_DATA_TABLE_ENTRY.SizeOfImage)
            FullDllName = self.get_unistr(cur_mod + PE64.LDR_DATA_TABLE_ENTRY.FullDllName).encode(
                "utf-8"
            )
            BaseDllName = self.get_unistr(cur_mod + PE64.LDR_DATA_TABLE_ENTRY.BaseDllName).encode(
                "utf-8"
            )
            # get next module (FLink)
            next_mod = self.Ptr(cur_mod)
            print(" * %s %s" % (str(hex(BaseAddress)), FullDllName))
            if callback is not None:
                callback(BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint)
            # check that BLink points to the previous structure
            if self.Ptr(next_mod + PE64.LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Blink) != cur_mod:
                raise Exception("walk_modulelist(): List error")
            cur_mod = next_mod

    def add_segment_callback(
        self, BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint
    ):
        print(
            "BaseAddress: 0x%X , BaseDllName %s , FullDllName %s"
            % (BaseAddress, BaseDllName, FullDllName)
        )
        # do we already have a segment for this module?
        if (
            idc.get_segm_start(BaseAddress) != BaseAddress
            or idc.get_segm_end(BaseAddress) != BaseAddress + SizeOfImage
        ):
            try:
                # if not, create one
                idc.AddSeg(
                    BaseAddress,
                    BaseAddress + SizeOfImage,
                    0,
                    2, # Segment type
                    idc.saRelByte,
                    idc.scPriv,
                )
                idc.set_segm_attr(BaseAddress, idc.SEGATTR_PERM, 7)
                idc.set_segm_name(BaseAddress, BaseDllName.decode("UTF-8"))
            except:
                pass

    def load_pdb_callback(self, BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint):
        BaseDllName = BaseDllName.decode("UTF-8")
        FullDllName = FullDllName.decode("UTF-8")
        if check_if_log(BaseDllName.lower()) == False:
            return  # skip this module
        print("Trying to load symbols for %s from %s - base addr: 0x%x" % (BaseDllName, FullDllName, BaseAddress))
        # fix the path, that starts with the windows folder name
        if FullDllName.lower().startswith("\\windows\\system32"):
            FullDllName = "\\SystemRoot\\system32" + FullDllName[17:]
        # fix the path, that contains file name only
        if FullDllName.find("\\") == -1:
            FullDllName = "\\SystemRoot\\system32\\DRIVERS\\" + FullDllName
        # load modules from the System32 only
        if FullDllName.lower().startswith("\\systemroot\\system32"):
            # translate into local filename
            filename = SYSTEM32_COPY_PATH + FullDllName[20:]
            if is_64bit():
                val = 0xFFFFFFFFFFFFFFFE
            else:
                val = 0xFFFFFFFE
            penode = ida_netnode.netnode()
            penode.create("$ pdb")
            # set parameters for PDB plugin
            penode.altset(0, BaseAddress)
            penode.supset(0, filename)
            # load symbols
            ida_loader.load_and_run_plugin("pdb", 3)  # use 1 to get a confirmation prompt
        else:
            print("%s is not in System32 directory" % BaseDllName)

    def get_unistr(self, addr:int):
        length = idc.read_dbg_word(addr)
        start = self.Ptr(addr + 0x8)
        if length > 1000:
            raise Exception("get_unistr(): String too long")
        res = ""
        c = 0
        while length > 0:
            c = idc.read_dbg_word(start)
            if c == 0 or c == None:
                break
            res += chr(c)
            start += 2
            length -= 2
        return res

if __name__ == '__main__':
    if is_64bit():
        intel64()
        exit()
    raise Exception("Fuck it! I didn't rewrite de 32-bit code")