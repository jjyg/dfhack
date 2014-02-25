/*
https://github.com/peterix/dfhack
Copyright (c) 2009-2012 Petr Mrázek (peterix@gmail.com)

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any
damages arising from the use of this software.

Permission is granted to anyone to use this software for any
purpose, including commercial applications, and to alter it and
redistribute it freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must
not claim that you wrote the original software. If you use this
software in a product, an acknowledgment in the product documentation
would be appreciated but is not required.

2. Altered source versions must be plainly marked as such, and
must not be misrepresented as being the original software.

3. This notice may not be removed or altered from any source
distribution.
*/

#include "Internal.h"

#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <map>
using namespace std;

#include "VersionInfo.h"
#include "VersionInfoFactory.h"
#include "Error.h"
#include "MemAccess.h"
using namespace DFHack;
namespace DFHack
{
    class PlatformSpecific
    {
    public:
        PlatformSpecific()
        {
            base = 0;
            sections = 0;
        };
        HANDLE my_handle;
        uint32_t my_pid;
        IMAGE_NT_HEADERS pe_header;
        IMAGE_SECTION_HEADER * sections;
        char * base;
    };
}
Process::Process(VersionInfoFactory * factory)
{
    HMODULE hmod = NULL;
    DWORD needed;
    bool found = false;
    identified = false;
    my_descriptor = NULL;

    d = new PlatformSpecific();
    // open process
    d->my_pid = GetCurrentProcessId();
    d->my_handle = GetCurrentProcess();
    // try getting the first module of the process
    if(EnumProcessModules(d->my_handle, &hmod, sizeof(hmod), &needed) == 0)
    {
        return; //if enumprocessModules fails, give up
    }

    // got base ;)
    d->base = (char *)hmod;

    // read from this process
    try
    {
        uint32_t pe_offset = readDWord(d->base+0x3C);
        read(d->base + pe_offset, sizeof(d->pe_header), (uint8_t *)&(d->pe_header));
        const size_t sectionsSize = sizeof(IMAGE_SECTION_HEADER) * d->pe_header.FileHeader.NumberOfSections;
        d->sections = (IMAGE_SECTION_HEADER *) malloc(sectionsSize);
        read(d->base + pe_offset + sizeof(d->pe_header), sectionsSize, (uint8_t *)(d->sections));
    }
    catch (exception &)
    {
        return;
    }
    VersionInfo* vinfo = factory->getVersionInfoByPETimestamp(d->pe_header.FileHeader.TimeDateStamp);
    if(vinfo)
    {
        identified = true;
        // give the process a data model and memory layout fixed for the base of first module
        my_descriptor  = new VersionInfo(*vinfo);
        my_descriptor->rebaseTo(getBase());
    }
}

Process::~Process()
{
    // destroy our rebased copy of the memory descriptor
    delete my_descriptor;
    if(d->sections != NULL)
        free(d->sections);
}

/*
typedef struct _MEMORY_BASIC_INFORMATION
{
  void *  BaseAddress;
  void *  AllocationBase;
  uint32_t  AllocationProtect;
  size_t RegionSize;
  uint32_t  State;
  uint32_t  Protect;
  uint32_t  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
*/
/*
//Internal structure used to store heap block information.
struct HeapBlock
{
      PVOID dwAddress;
      DWORD dwSize;
      DWORD dwFlags;
      ULONG reserved;
};
*/

static void GetDosNames(std::map<string, string> &table)
{
    // Partially based on example from msdn:
    // Translate path with device name to drive letters.
    TCHAR szTemp[512];
    szTemp[0] = '\0';

    if (GetLogicalDriveStrings(sizeof(szTemp)-1, szTemp))
    {
        TCHAR szName[MAX_PATH];
        TCHAR szDrive[3] = " :";
        BOOL bFound = FALSE;
        TCHAR* p = szTemp;

        do
        {
            // Copy the drive letter to the template string
            *szDrive = *p;

            // Look up each device name
            if (QueryDosDevice(szDrive, szName, MAX_PATH))
                table[szName] = szDrive;

            // Go to the next NULL character.
            while (*p++);
        } while (*p); // end of string
    }
}

void Process::getMemRanges( vector<t_memrange> & ranges )
{
    MEMORY_BASIC_INFORMATION MBI;
    //map<char *, unsigned int> heaps;
    uint64_t movingStart = 0;
    PVOID LastAllocationBase = 0;
    map <char *, string> nameMap;
    map <string,string> dosDrives;

    // get page size
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uint64_t PageSize = si.dwPageSize;

    // get dos drive names
    GetDosNames(dosDrives);

    ranges.clear();

    // enumerate heaps
    // HeapNodes(d->my_pid, heaps);
    // go through all the VM regions, convert them to our internal format
    while (VirtualQueryEx(d->my_handle, (const void*) (movingStart), &MBI, sizeof(MBI)) == sizeof(MBI))
    {
        movingStart = ((uint64_t)MBI.BaseAddress + MBI.RegionSize);
        if(movingStart % PageSize != 0)
            movingStart = (movingStart / PageSize + 1) * PageSize;

        // Skip unallocated address space
        if (MBI.State & MEM_FREE)
            continue;

        // Find range and permissions
        t_memrange temp;
        memset(&temp, 0, sizeof(temp));

        temp.start   = (char *) MBI.BaseAddress;
        temp.end     =  ((char *)MBI.BaseAddress + (uint64_t)MBI.RegionSize);
        temp.valid   = true;

        if (!(MBI.State & MEM_COMMIT))
            temp.valid = false; // reserved address space
        else if (MBI.Protect & PAGE_EXECUTE)
            temp.execute = true;
        else if (MBI.Protect & PAGE_EXECUTE_READ)
            temp.execute = temp.read = true;
        else if (MBI.Protect & PAGE_EXECUTE_READWRITE)
            temp.execute = temp.read = temp.write = true;
        else if (MBI.Protect & PAGE_EXECUTE_WRITECOPY)
            temp.execute = temp.read = temp.write = true;
        else if (MBI.Protect & PAGE_READONLY)
            temp.read = true;
        else if (MBI.Protect & PAGE_READWRITE)
            temp.read = temp.write = true;
        else if (MBI.Protect & PAGE_WRITECOPY)
            temp.read = temp.write = true;

        // Merge areas with the same properties
        if (!ranges.empty() && LastAllocationBase == MBI.AllocationBase)
        {
            auto &last = ranges.back();

            if (last.end == temp.start &&
                last.valid == temp.valid && last.execute == temp.execute &&
                last.read == temp.read && last.write == temp.write)
            {
                last.end = temp.end;
                continue;
            }
        }

#if 1
        // Find the mapped file name
        if (GetMappedFileName(d->my_handle, temp.start, temp.name, 1024))
        {
            int vsize = strlen(temp.name);

            // Translate NT name to DOS name
            for (auto it = dosDrives.begin(); it != dosDrives.end(); ++it)
            {
                int ksize = it->first.size();
                if (strncmp(temp.name, it->first.data(), ksize) != 0)
                    continue;

                memcpy(temp.name, it->second.data(), it->second.size());
                memmove(temp.name + it->second.size(), temp.name + ksize, vsize + 1 - ksize);
                break;
            }
        }
        else
            temp.name[0] = 0;
#else
        // Find the executable name
        char *base = (char*)MBI.AllocationBase;

        if(nameMap.count(base))
        {
            strncpy(temp.name, nameMap[base].c_str(), 1023);
        }
        else if(GetModuleBaseName(d->my_handle, (HMODULE)base, temp.name, 1024))
        {
            std::string nm(temp.name);

            nameMap[base] = nm;

            // this is our executable! (could be generalized to pull segments from libs, but whatever)
            if(d->base == base)
            {
                for(int i = 0; i < d->pe_header.FileHeader.NumberOfSections; i++)
                {
                    /*char sectionName[9];
                    memcpy(sectionName,d->sections[i].Name,8);
                    sectionName[8] = 0;
                    string nm;
                    nm.append(temp.name);
                    nm.append(" : ");
                    nm.append(sectionName);*/
                    nameMap[base + d->sections[i].VirtualAddress] = nm;
                }
            }
        }
        else
            temp.name[0] = 0;
#endif

        // Push the entry
        LastAllocationBase = MBI.AllocationBase;
        ranges.push_back(temp);
    }
}

uintptr_t Process::getBase()
{
    if(d)
        return (uintptr_t) d->base;
    return 0x400000;
}

int Process::adjustOffset(int offset, bool to_file)
{
    if (!d)
        return -1;

    for(int i = 0; i < d->pe_header.FileHeader.NumberOfSections; i++)
    {
        auto &section = d->sections[i];

        if (to_file)
        {
            unsigned delta = offset - section.VirtualAddress;
            if (delta >= section.Misc.VirtualSize)
                continue;
            if (!section.PointerToRawData || delta >= section.SizeOfRawData)
                return -1;
            return (int)(section.PointerToRawData + delta);
        }
        else
        {
            unsigned delta = offset - section.PointerToRawData;
            if (!section.PointerToRawData || delta >= section.SizeOfRawData)
                continue;
            if (delta >= section.Misc.VirtualSize)
                return -1;
            return (int)(section.VirtualAddress + delta);
        }
    }

    return -1;
}


string Process::doReadClassName (void * vptr)
{
    char * rtti = readPtr((char *)vptr - 0x4);
    char * typeinfo = readPtr(rtti + 0xC);
    string raw = readCString(typeinfo + 0xC); // skips the .?AV
    raw.resize(raw.length() - 2);// trim @@ from end
    return raw;
}

uint32_t Process::getTickCount()
{
    return GetTickCount();
}

string Process::getPath()
{
    HMODULE hmod;
    DWORD junk;
    char String[255];
    EnumProcessModules(d->my_handle, &hmod, 1 * sizeof(HMODULE), &junk); //get the module from the handle
    GetModuleFileNameEx(d->my_handle,hmod,String,sizeof(String)); //get the filename from the module
    string out(String);
    return(out.substr(0,out.find_last_of("\\")));
}

bool Process::setPermisions(const t_memrange & range,const t_memrange &trgrange)
{
    DWORD newprotect=0;
    if(trgrange.read && !trgrange.write && !trgrange.execute)newprotect=PAGE_READONLY;
    if(trgrange.read && trgrange.write && !trgrange.execute)newprotect=PAGE_READWRITE;
    if(!trgrange.read && !trgrange.write && trgrange.execute)newprotect=PAGE_EXECUTE;
    if(trgrange.read && !trgrange.write && trgrange.execute)newprotect=PAGE_EXECUTE_READ;
    if(trgrange.read && trgrange.write && trgrange.execute)newprotect=PAGE_EXECUTE_READWRITE;
    DWORD oldprotect=0;
    bool result;
    result=VirtualProtect((LPVOID)range.start,(char *)range.end-(char *)range.start,newprotect,&oldprotect);

    return result;
}

void* Process::memAlloc(const int length)
{
    void *ret;
    // returns 0 on error
    ret = VirtualAlloc(0, length, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!ret)
        ret = (void*)-1;
    return ret;
}

int Process::memDealloc(void *ptr, const int length)
{
    // can only free the whole region at once
    // vfree returns 0 on error
    return !VirtualFree(ptr, 0, MEM_RELEASE);
}

int Process::memProtect(void *ptr, const int length, const int prot)
{
    int prot_native = 0;
    DWORD old_prot = 0;

    // only support a few constant combinations
    if (prot == 0)
        prot_native = PAGE_NOACCESS;
    else if (prot == Process::MemProt::READ)
        prot_native = PAGE_READONLY;
    else if (prot == (Process::MemProt::READ | Process::MemProt::WRITE))
        prot_native = PAGE_READWRITE;
    else if (prot == (Process::MemProt::READ | Process::MemProt::WRITE | Process::MemProt::EXEC))
        prot_native = PAGE_EXECUTE_READWRITE;
    else if (prot == (Process::MemProt::READ | Process::MemProt::EXEC))
        prot_native = PAGE_EXECUTE_READ;
    else
        return -1;

    return !VirtualProtect(ptr, length, prot_native, &old_prot);
}

__declspec(naked)
unsigned long Process::generic_call(void *fptr, unsigned long stack_fixup, unsigned long regs_used,
        unsigned long r_eax, unsigned long r_ebx, unsigned long r_ecx, unsigned long r_edx,
        unsigned long r_esi, unsigned long r_edi, unsigned long r_ebp,
        unsigned long stack0, unsigned long stack1, unsigned long stack2, unsigned long stack3,
        unsigned long stack4, unsigned long stack5, unsigned long stack6, unsigned long stack7)
{
    // TODO add sanity checks ? eg stack_fixup should be in [0,4,8..32]
    __asm {
        // saved registers
        // C ABI require us to preserve ebx, esi, edi, ebp for our caller
        push ebp
        push edi
        push esi
        push ebx

        // regs_used is a bitfield in the low 16bits to mark registers we want to set from our argument list
        // the high 16bits hold the register number for the register used by the target function to store the return value
        // eg 0 = eax, 1 = ebx, ...
        // store this register number here, so we can access it in the return stub
        push regs_used
        shr dword ptr [esp], 16

        // function stack parameters
        push stack7
        push stack6
        push stack5
        push stack4
        push stack3
        push stack2
        push stack1
        push stack0

        // cook a magic function return address
        // this points to a stub according to stack_fixup
        // the called function will return to it, its job is to:
        //  - honor stack_fixup
        //  - pop the previous stackX arguments
        //  - save the callee return value
        //  - restore the saved registers to honor the C ABI for our caller
        cmp stack_fixup, 0
        jnz stack_fixup_more_0
        push ret_fixup_0
        jmp stack_fixup_ready
    stack_fixup_more_0:
        cmp stack_fixup, 4
        jnz stack_fixup_more_4
        push ret_fixup_4
        jmp stack_fixup_ready
    stack_fixup_more_4:
        cmp stack_fixup, 8
        jnz stack_fixup_more_8
        push ret_fixup_8
        jmp stack_fixup_ready
    stack_fixup_more_8:
        cmp stack_fixup, 12
        jnz stack_fixup_more_12
        push ret_fixup_12
        jmp stack_fixup_ready
    stack_fixup_more_12:
        cmp stack_fixup, 16
        jnz stack_fixup_more_16
        push ret_fixup_16
        jmp stack_fixup_ready
    stack_fixup_more_16:
        cmp stack_fixup, 20
        jnz stack_fixup_more_20
        push ret_fixup_20
        jmp stack_fixup_ready
    stack_fixup_more_20:
        cmp stack_fixup, 24
        jnz stack_fixup_more_24
        push ret_fixup_24
        jmp stack_fixup_ready
    stack_fixup_more_24:
        cmp stack_fixup, 28
        jnz stack_fixup_more_28
        push ret_fixup_28
        jmp stack_fixup_ready
    stack_fixup_more_28:
        push ret_fixup_32
    stack_fixup_ready:

        // push the address of the function we want to call (we can't do a call register as we may have no free register, eg regs_used = 0x7f)
        push fptr

        // function register parameters
        // set a register only if its bit is set in regs_used
        // load ebp last, as it may be used by the assembler to access the func params (regs_used etc)
        test regs_used, 1
        jnz skip_eax
        mov eax, r_eax
    skip_eax:
        test regs_used, 2
        jnz skip_ebx
        mov ebx, r_ebx
    skip_ebx:
        test regs_used, 4
        jnz skip_ecx
        mov ecx, r_ecx
    skip_ecx:
        test regs_used, 8
        jnz skip_edx
        mov edx, r_edx
    skip_edx:
        test regs_used, 16
        jnz skip_esi
        mov esi, r_esi
    skip_esi:
        test regs_used, 32
        jnz skip_edi
        mov edi, r_edi
    skip_edi:
        test regs_used, 64
        jnz skip_ebp
        mov ebp, r_ebp
    skip_ebp:

        // this is the actual target function call
        // after this instruction, eip = fptr, and esp points to the return stub we set up previously
        ret


        // cooked return stubs for the target function
        // in here we cant access any of our C arguments (until we fixup the stack) nor any register
    ret_fixup_0:
        add esp, 4
    ret_fixup_4:
        add esp, 4
    ret_fixup_8:
        add esp, 4
    ret_fixup_12:
        add esp, 4

    ret_fixup_16:
        add esp, 4
    ret_fixup_20:
        add esp, 4
    ret_fixup_24:
        add esp, 4
    ret_fixup_28:
        add esp, 4
    ret_fixup_32:

        // stack now points to the integer identifying the return value register
        cmp dword ptr [esp], 0
        jz ret_done

        cmp dword ptr [esp], 1
        jnz ret_not_ebx
        mov eax, ebx
        jmp ret_done
    ret_not_ebx:
        cmp dword ptr [esp], 2
        jnz ret_not_ecx
        mov eax, ecx
        jmp ret_done
    ret_not_ecx:
        cmp dword ptr [esp], 3
        jnz ret_not_edx
        mov eax, edx
        jmp ret_done
    ret_not_edx:
        cmp dword ptr [esp], 4
        jnz ret_not_esi
        mov eax, esi
        jmp ret_done
    ret_not_esi:
        cmp dword ptr [esp], 5
        jnz ret_not_edi
        mov eax, edi
        jmp ret_done
    ret_not_edi:
        cmp dword ptr [esp], 6
        jnz ret_not_ebp
        mov eax, ebp
    ret_not_ebp:
    ret_done:
        add esp, 4  // pop the regs_used value

        // now we saved the return value in eax
        // restore the caller saved register
        push ebx
        push esi
        push edi
        push ebp

        // mission accomplished
        ret
    }
}
