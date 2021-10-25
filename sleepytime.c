#include <inttypes.h>
#include <stdio.h>
#include "AddressHunter.h"

// kernel32.dll exports
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef BOOL(WINAPI* CLOSEHANDLE)(HANDLE);
typedef HANDLE(WINAPI* GETCURRENTPROCESS)();
typedef HMODULE(WINAPI* GETMODULEHANDLEA)(LPCSTR);
typedef VOID(WINAPI* SLEEP)(DWORD);
typedef BOOL(WINAPI* VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PWORD);

// User32.dll export
typedef int(WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);


byte XOR(byte data, byte key) {
    return data ^ key;
}

ULONGLONG RoundUp(ULONGLONG numToRound, ULONGLONG multiple)
{
    //Use modulo to check if it fits perfectly or needs padding. The multiple is 4096 because thats the page size on this system. You can get pagesize via windows api but just hard coded for now
    float modulo = numToRound % multiple;
    if (modulo == 0) {
        return numToRound;
    }
    else {
        return ((numToRound / multiple) * multiple) + multiple;
    }
}

void encryptMemorySegment(UINT64 startAddr, UINT64 length) {

}
    

void sleepytime() {
    //dlls to dynamically load during runtime
    UINT64 kernel32dll, user32dll;
    //symbols to dynamically resolve from dll during runtime
    UINT64 LoadLibraryAFunc, GetModuleHandleAFunc, VirtualProtectFunc, SleepFunc, MessageBoxAFunc;

    // Get base address of the Kernel32 dll in memory cause I need to parse it to get some functions
    kernel32dll = GetKernel32();

    ////LoadLibraryA...I dont actually need it for the real thing but I need it to get MessageBox in user32dll so I can debug the shellcode otherwise I got no freaking idea if it's working
    //REMOVE WHATS AFTER THIS IN PROD
    CHAR loadlibrarya_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    LoadLibraryAFunc = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);

    CHAR user32_c[] = { 'u', 's', 'e', 'r', '3', '2','.', 'd', 'l', 'l', 0 };
    user32dll = (UINT64)((LOADLIBRARYA)LoadLibraryAFunc)(user32_c);

    CHAR getMessageBoxA_c[] = { 'M','e','s','s','a','g','e','B','o','x','A', 0 };
    MessageBoxAFunc = GetSymbolAddress((HANDLE)user32dll, getMessageBoxA_c);

    //REMOVE WHATS BEFORE THIS IN PROD


    //Get the GetModuleHandleA function with returns a module aka a pointer to the beginning of the PE in memory for the process you specify. If you leave it null it returns for current process.
    // We need it so we can pass that module to the section parsing function which returns an array of structs with the important info for each section: start addr, size in memory, rwx permissions
    CHAR getmoduleHandleA_c[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A', 0};
    GetModuleHandleAFunc = GetSymbolAddress((HANDLE)kernel32dll, getmoduleHandleA_c);
    HMODULE module = ((GETMODULEHANDLEA)GetModuleHandleAFunc)(NULL);


    CHAR getvirtualProtect_c[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0 };
    VirtualProtectFunc = GetSymbolAddress((HANDLE)kernel32dll, getvirtualProtect_c);
   
    CHAR getSleep_c[] = { 'S','l','e','e','p', 0 };
    SleepFunc = GetSymbolAddress((HANDLE)kernel32dll, getSleep_c);
    
   
    _SECTION sections = getSections(module);
    UINT64 currentSectionHeaderAddrr = sections.sectionHeader;

    byte key = 0x23;

    DWORD lpflOldProtect;
    

    CHAR testMessage[] = { 'B','e','f','o','r','e','S','l','e','e','p', 0};
    ((MESSAGEBOXA)MessageBoxAFunc)(NULL, testMessage, testMessage, MB_OK);

    //Encrypt
    for (int i = 0; i < sections.numberOfSections; i++) {
        UINT64 sectionStartAddr = sections.startAddr + ((PIMAGE_SECTION_HEADER)currentSectionHeaderAddrr)->VirtualAddress;
        // Build the struct thatll give me all the info I need about a section. 
        //1. sectionStartAddr is a pointer to where the section starts in memory
        //2. VirtualSize is the size of the section so I can add it to the start address to know where it ends
        //3. Characteristics shifted left by 28 bits. That is because characteristics contains lots of values on 32 bit but we only want the 4 first bits aka 1 hex value. 2 = execute , 4 = red , 8 = write. So if the valuea fter shifting 28 bits is E(14) you have full rwx. If it's 8 you only have write...etc
        // view https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header for more information about the bit values
        //Iterate over all the bytes of the section
        //I Need to round up the virtual size to something that matches a page size because thats the smallest unit of memory you can work with for stuff like that. Aka if I have 65000 bytes to change Ill need to round 
        //that up to how many times 4096 fits in it + 1
        SIZE_T size = (DWORD)RoundUp(((PIMAGE_SECTION_HEADER)currentSectionHeaderAddrr)->Misc.VirtualSize, 0x1000);
        //Now my current issue is it crashes when modifying the .text section cause yeah lol its where my code is. This will only work if I'm executing from shellcode on the heap I think.
        DWORD permissionToRestore = ((PIMAGE_SECTION_HEADER)currentSectionHeaderAddrr)->Characteristics >> 28;


        ((VIRTUALPROTECT)VirtualProtectFunc)(sectionStartAddr, size, PAGE_READWRITE, &lpflOldProtect);


        for (byte* currentBytePointer = sectionStartAddr; currentBytePointer < (sectionStartAddr + ((PIMAGE_SECTION_HEADER)currentSectionHeaderAddrr)->Misc.VirtualSize); currentBytePointer++) {
            *currentBytePointer = XOR(*currentBytePointer, key);
        }

        //Move to the next section header
        UINT64 tmp = currentSectionHeaderAddrr + 40;
        currentSectionHeaderAddrr = (UINT64)currentSectionHeaderAddrr + 40;
    }

    //Encrypt PE HEADERS so startAddr + 
    ((VIRTUALPROTECT)VirtualProtectFunc)(sections.startAddr, 4096, PAGE_READWRITE, &lpflOldProtect);
    for (byte* currentBytePointer = sections.startAddr; currentBytePointer < (sections.startAddr + 4096); currentBytePointer++) {
        *currentBytePointer = XOR(*currentBytePointer, key);
    }

    //Sleep for 20 sec
    CHAR testMessage2[] = { 'T','i','m','e','T','o','S','l','e','e','p', 0 };
    ((MESSAGEBOXA)MessageBoxAFunc)(NULL, testMessage2, testMessage2, MB_OK);
    ((SLEEP)SleepFunc)(20000);


    //Decrypt PE HEADERS
    for (byte* currentBytePointer = sections.startAddr; currentBytePointer < (sections.startAddr + 4096); currentBytePointer++) {
        *currentBytePointer = XOR(*currentBytePointer, key);
    }
    ((VIRTUALPROTECT)VirtualProtectFunc)(sections.startAddr, 4096, PAGE_READONLY, &lpflOldProtect);
    CHAR testMessage4[] = { 'P','E','H','e','a','d','I','s','d','e','c', 0 };
    ((MESSAGEBOXA)MessageBoxAFunc)(NULL, testMessage4, testMessage4, MB_OK);
    //Decrypt
    //Reset the sectionHeaderAddrr to the first one
    currentSectionHeaderAddrr = sections.sectionHeader;
    //for (int i = 0; i < sections.numberOfSections; i++) {
    for (int i = 0; i < 1; i++) {
        UINT64 sectionStartAddr = sections.startAddr + ((PIMAGE_SECTION_HEADER)currentSectionHeaderAddrr)->VirtualAddress;
        // Build the struct thatll give me all the info I need about a section. 
        //1. sectionStartAddr is a pointer to where the section starts in memory
        //2. VirtualSize is the size of the section so I can add it to the start address to know where it ends
        //3. Characteristics shifted left by 28 bits. That is because characteristics contains lots of values on 32 bit but we only want the 4 first bits aka 1 hex value. 2 = execute , 4 = red , 8 = write. So if the valuea fter shifting 28 bits is E(14) you have full rwx. If it's 8 you only have write...etc
        // view https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header for more information about the bit values
        //Iterate over all the bytes of the section
        //I Need to round up the virtual size to something that matches a page size because thats the smallest unit of memory you can work with for stuff like that. Aka if I have 65000 bytes to change Ill need to round 
        //that up to how many times 4096 fits in it + 1
        SIZE_T size = (DWORD)RoundUp(((PIMAGE_SECTION_HEADER)currentSectionHeaderAddrr)->Misc.VirtualSize, 0x1000);
        //Now my current issue is it crashes when modifying the .text section cause yeah lol its where my code is. This will only work if I'm executing from shellcode on the heap I think.

        
        for (byte* currentBytePointer = sectionStartAddr; currentBytePointer < (sectionStartAddr + ((PIMAGE_SECTION_HEADER)currentSectionHeaderAddrr)->Misc.VirtualSize); currentBytePointer++) {
            *currentBytePointer = XOR(*currentBytePointer, key);
        }
        byte permissionToRestore = ((PIMAGE_SECTION_HEADER)currentSectionHeaderAddrr)->Characteristics >> 28;

        //RWX
        if (permissionToRestore == 14) {
            ((VIRTUALPROTECT)VirtualProtectFunc)(sectionStartAddr, size, PAGE_EXECUTE_READWRITE, &lpflOldProtect);
        }
        //RW
        else if (permissionToRestore == 12) {
            ((VIRTUALPROTECT)VirtualProtectFunc)(sectionStartAddr, size, PAGE_READWRITE, &lpflOldProtect);
        }
        //WX
        else if (permissionToRestore == 10) {
            ((VIRTUALPROTECT)VirtualProtectFunc)(sectionStartAddr, size, PAGE_EXECUTE_WRITECOPY, &lpflOldProtect);
        }
        //W
        else if (permissionToRestore == 8) {
            ((VIRTUALPROTECT)VirtualProtectFunc)(sectionStartAddr, size, PAGE_WRITECOPY, &lpflOldProtect);
        }
        //RX
        else if (permissionToRestore == 6) {
            ((VIRTUALPROTECT)VirtualProtectFunc)(sectionStartAddr, size, PAGE_EXECUTE_READ, &lpflOldProtect);
        }
        //R
        else if (permissionToRestore == 4) {
            ((VIRTUALPROTECT)VirtualProtectFunc)(sectionStartAddr, size, PAGE_READONLY, &lpflOldProtect);
        }
        //X
        else if (permissionToRestore == 2) {
            ((VIRTUALPROTECT)VirtualProtectFunc)(sectionStartAddr, size, PAGE_EXECUTE, &lpflOldProtect);
        }



        //Move to the next section header
        UINT64 tmp = currentSectionHeaderAddrr + 40;
        currentSectionHeaderAddrr = (UINT64)currentSectionHeaderAddrr + 40;
    }
	return;
}


//int main(int argc, char* argv[])
//{
//    sleepytime(5000);
//    return(0);
//}