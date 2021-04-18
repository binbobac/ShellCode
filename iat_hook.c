
#include<windows.h>

int set_iat_hook()
{
	HMODULE image_base = GetModuleHandle(NULL);
	IMAGE_DOS_HEADER* dos = image_base;
	IMAGE_NT_HEADERS32* nt = (DWORD)image_base + dos->e_lfanew;
	IMAGE_IMPORT_DESCRIPTOR* import = (DWORD)image_base + nt->OptionalHeader.DataDirectory[1].VirtualAddress;
	DWORD import_size = nt->OptionalHeader.DataDirectory[1].Size;
	BOOL flag = FALSE;
	DWORD* import_fun = NULL;
	while (import->FirstThunk != NULL && flag == FALSE)
	{
		//char* a = (DWORD)image_base + import->Name;
		import_fun = (DWORD)image_base + import->FirstThunk;
		if (strcmp((DWORD)image_base + import->Name, "KERNEL32.dll") == 0)
		{
			IMAGE_THUNK_DATA32* thunk = (DWORD)image_base + import->OriginalFirstThunk;
			while (thunk)
			{
				IMAGE_IMPORT_BY_NAME* import_by_name = (DWORD)image_base + thunk->u1.ForwarderString;
				
				if (strcmp(import_by_name->Name, "MessageBoxA") == 0)
				{
					flag = TRUE;
					DWORD old_protect;
					VirtualProtect(import_fun, sizeof(DWORD), PAGE_READWRITE, &old_protect);
					DWORD x = *import_fun = 0x00; //在这修改；
					VirturalProtect(import_fun, sizeof(DWORD), old_protect, 0);
					break;
				}
				thunk++;
				import_fun++;
			}
			
		}
		import++;
	}

	return 0;
}
