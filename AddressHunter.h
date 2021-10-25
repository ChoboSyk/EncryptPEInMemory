#include <windows.h>
#include <inttypes.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define KERNEL32DLL_HASH 0x6A4ABC5B

//redefine UNICODE_STR struct
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

//redefine PEB_LDR_DATA struct
typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

//redefine LDR_DATA_TABLE_ENTRY struct
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//redefine PEB_FREE_BLOCK struct
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

//redefine PEB struct
typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;


typedef struct _SECTION
{
    UINT64 startAddr;
    UINT64 sectionHeader;
    UINT64 numberOfSections;

}_SECTION, * _PSECTION;

// main hashing function for ror13
__forceinline DWORD ror13(DWORD d)
{
    return _rotr(d, 13);
}

__forceinline DWORD hash(char* c)
{
    register DWORD h = 0;
    do
    {
        h = ror13(h);
        h += *c;
    } while (*++c);

    return h;
}

// function to fetch the base address of kernel32.dll from the Process Environment Block
UINT64 GetKernel32() {
    ULONG_PTR kernel32dll, val1, val2, val3;
    USHORT usCounter;

    // kernel32.dll is at 0x60 offset and __readgsqword is compiler intrinsic,
    // so we don't need to extract it's symbol

    kernel32dll = __readgsqword(0x60);

    kernel32dll = (ULONG_PTR)((_PPEB)kernel32dll)->pLdr;
    val1 = (ULONG_PTR)((PPEB_LDR_DATA)kernel32dll)->InMemoryOrderModuleList.Flink;
    while (val1) {
        val2 = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
        usCounter = ((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.Length;
        val3 = 0;

        //calculate the hash of kernel32.dll
        do {
            val3 = ror13((DWORD)val3);
            if (*((BYTE*)val2) >= 'a')
                val3 += *((BYTE*)val2) - 0x20;
            else
                val3 += *((BYTE*)val2);
            val2++;
        } while (--usCounter);

        // compare the hash kernel32.dll
        if ((DWORD)val3 == KERNEL32DLL_HASH) {
            //return kernel32.dll if found
            kernel32dll = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->DllBase;
            return kernel32dll;
        }
        val1 = DEREF(val1);
    }
    return 0;
}

// custom strcmp function since this function will be called by GetSymbolAddress
// which means we have to call strcmp before loading msvcrt.dll
// so we are writing our own my_strcmp so that we don't have to play with egg or chicken dilemma
int my_strcmp(const char* p1, const char* p2) {
    const unsigned char* s1 = (const unsigned char*)p1;
    const unsigned char* s2 = (const unsigned char*)p2;
    unsigned char c1, c2;
    do {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 == '\0') {
            return c1 - c2;
        }
    } while (c1 == c2);
    return c1 - c2;
}

UINT64 GetSymbolAddress(HANDLE hModule, LPCSTR lpProcName) {
    UINT64 dllAddress = (UINT64)hModule,
        symbolAddress = 0,
        exportedAddressTable = 0,
        namePointerTable = 0,
        ordinalTable = 0;

    if (hModule == NULL) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

    ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + ((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew);
    dataDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllAddress + dataDirectory->VirtualAddress);

    exportedAddressTable = (dllAddress + exportDirectory->AddressOfFunctions);
    namePointerTable = (dllAddress + exportDirectory->AddressOfNames);
    ordinalTable = (dllAddress + exportDirectory->AddressOfNameOrdinals);

    if (((UINT64)lpProcName & 0xFFFF0000) == 0x00000000) {
        exportedAddressTable += ((IMAGE_ORDINAL((UINT64)lpProcName) - exportDirectory->Base) * sizeof(DWORD));
        symbolAddress = (UINT64)(dllAddress + DEREF_32(exportedAddressTable));
    }
    else {
        DWORD dwCounter = exportDirectory->NumberOfNames;
        while (dwCounter--) {
            char* cpExportedFunctionName = (char*)(dllAddress + DEREF_32(namePointerTable));
            if (my_strcmp(cpExportedFunctionName, lpProcName) == 0) {
                exportedAddressTable += (DEREF_16(ordinalTable) * sizeof(DWORD));
                symbolAddress = (UINT64)(dllAddress + DEREF_32(exportedAddressTable));
                break;
            }
            namePointerTable += sizeof(DWORD);
            ordinalTable += sizeof(WORD);
        }
    }

    return symbolAddress;
}


_SECTION getSections(HANDLE hModule) {
    UINT64 peStartAddr = (UINT64)hModule;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    ntHeaders = (PIMAGE_NT_HEADERS)(peStartAddr + ((PIMAGE_DOS_HEADER)peStartAddr)->e_lfanew);
    IMAGE_FILE_HEADER fileHeader = ntHeaders->FileHeader;
    unsigned short numberOfSections = fileHeader.NumberOfSections;
    unsigned long long signatureSize = sizeof(ntHeaders->Signature);
    unsigned long long fileHeaderSize = sizeof(fileHeader);
    unsigned short sizeOfOptionalHeader = fileHeader.SizeOfOptionalHeader;
    //e_lfanew = start of pe | signature size = Pe signature | fileHeaderSize = CoffFileHEader | sizeOfOptionalHeader = OptionalHeaders | 
    PIMAGE_SECTION_HEADER sectionHeader = (peStartAddr + ((PIMAGE_DOS_HEADER)peStartAddr)->e_lfanew) + signatureSize + fileHeaderSize + sizeOfOptionalHeader;

    UINT64 sizeOfSections = 0;


    //_PSECTION sectionsList;
    //sectionsList = calloc(numberOfSections, sizeof(_PSECTION));

    _SECTION peInfo = { peStartAddr , sectionHeader , numberOfSections };


    //for (int i = 0; i < numberOfSections; i++) {
    //    UINT64 sectionStartAddr = peStartAddr + sectionHeader->VirtualAddress;
    //    // Build the struct thatll give me all the info I need about a section. 
    //    //1. sectionStartAddr is a pointer to where the section starts in memory
    //    //2. VirtualSize is the size of the section so I can add it to the start address to know where it ends
    //    //3. Characteristics shifted left by 28 bits. That is because characteristics contains lots of values on 32 bit but we only want the 4 first bits aka 1 hex value. 2 = execute , 4 = red , 8 = write. So if the valuea fter shifting 28 bits is E(14) you have full rwx. If it's 8 you only have write...etc
    //    // view https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header for more information about the bit values
    //    sectionsList[i].permissions = sectionHeader->Characteristics >> 28;
    //    sectionsList[i].startAddr = sectionStartAddr;
    //    sectionsList[i].virtualSize = sectionHeader->Misc.VirtualSize;
    //    sectionsList[i].numberOfSections = numberOfSections;
    //    UINT64 tmp = sectionHeader + 40;
    //    sectionHeader = (UINT64)sectionHeader + 40;
    //}

    return peInfo;
}