#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <Tlhelp32.h>
#pragma warning(disable:4996)

typedef struct link_node_t {
	int i;
}link_node_t;


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;

	PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (ULONG_PTR)(&((type *)0)->field)))

DWORD inline HashKey(char* key)
{
	DWORD nHash = 0;
	while (*key)
	{
		nHash = (nHash << 5) + nHash + *key++;
	}
	return nHash;
}

void fun()
{
	PLDR_DATA_TABLE_ENTRY pbeg;
	//char* pend;
	BYTE* ker32_base = NULL;

	__asm {
		mov eax, fs: [0x18] ;	//	get teb
		mov eax, [eax + 0x30];	//	get peb
		mov eax, [eax + 0xc];	//peb->ldr
		mov eax, [eax + 0xc];		//
		mov pbeg, eax;
	};
	PLDR_DATA_TABLE_ENTRY pLDR_DATA_TABLE_ENTRY;
	for (int i = 0; i < 4; i++)
	{

		if (pbeg->BaseDllName.Buffer[0] == 'K' && pbeg->BaseDllName.Buffer[1] == 'E' && pbeg->BaseDllName.Buffer[2] == 'R' &&
			pbeg->BaseDllName.Buffer[3] == 'N' && pbeg->BaseDllName.Buffer[4] == 'E' && pbeg->BaseDllName.Buffer[5] == 'L' &&
			pbeg->BaseDllName.Buffer[6] == '3' && pbeg->BaseDllName.Buffer[7] == '2')
		{
			ker32_base = pbeg->DllBase;
			break;
		}

		pbeg = (PLDR_DATA_TABLE_ENTRY)pbeg->InLoadOrderLinks.Flink;
	}
	IMAGE_DOS_HEADER* dos = ker32_base;
	IMAGE_NT_HEADERS32* nt = ker32_base + dos->e_lfanew;
	IMAGE_EXPORT_DIRECTORY* export = ker32_base + nt->OptionalHeader.DataDirectory[0].VirtualAddress;
	int export_count = export->NumberOfFunctions;
	int name_count = export->NumberOfNames;
	DWORD* fun_rva = ker32_base + export->AddressOfFunctions;
	DWORD* fun_name_rva = ker32_base + export->AddressOfNames;
	WORD* fun_name_ord = ker32_base + export->AddressOfNameOrdinals;

	HMODULE(*__stdcall fun_LoadLibraryA)(LPCSTR);
	FARPROC(*__stdcall fun_GetProcAddress)(
		HMODULE,
		LPCSTR
		);
	DWORD loadlibrary_hash = 119352438;
	DWORD getprocaddress_hash = 3268133210;
	for (int i = 0; i < name_count; i++)
	{
		char* fun_name = ker32_base + fun_name_rva[i];
		if (HashKey(fun_name) == loadlibrary_hash)
		{
			DWORD c = fun_rva[i];
			fun_LoadLibraryA = ker32_base + fun_rva[fun_name_ord[i]];
		}
		else if (HashKey(fun_name) == getprocaddress_hash)
		{
			fun_GetProcAddress = ker32_base + fun_rva[fun_name_ord[i]];
		}
	}
	HMODULE mod = fun_LoadLibraryA("kernel32.dll");
	void (*__stdcall fun_WinExec)();

	char cWinExec[] = {'W', 'i', 'n', 'E', 'x', 'e', 'c', '\0'};
	(FARPROC)fun_WinExec = fun_GetProcAddress(mod, cWinExec);
	char ccalc[] = { 'c','a','l','c','.','e','x','e','\0' };
	fun_WinExec(ccalc, SW_SHOWNORMAL);
}

int main()
{
	fun();
	return 0;
}