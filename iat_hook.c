
#include<windows.h>

int set_iat_hook(const char* dll_name, const char* api_name, void** addr)
{
	HMODULE image_base = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dos = image_base;
	PIMAGE_NT_HEADERS nt = (char*)image_base + dos->e_lfanew;
	PIMAGE_IMPORT_DESCRIPTOR import = (char*)image_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	BOOL flag = FALSE;
	void** iat = NULL;
	while (import->FirstThunk != NULL && flag == FALSE)
	{
		iat = (char*)image_base + import->FirstThunk;
		if (stricmp((char*)image_base + import->Name, dll_name) == 0)
		{
			PIMAGE_THUNK_DATA thunk = (char*)image_base + import->OriginalFirstThunk;
			while (thunk->u1.AddressOfData)
			{
				IMAGE_IMPORT_BY_NAME* import_by_name = (char*)image_base + thunk->u1.ForwarderString;
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					if (IMAGE_ORDINAL(thunk->u1.Ordinal) == (SIZE_T)api_name)
					{
						flag = TRUE;
						DWORD old_protect;
						VirtualProtect(iat, sizeof(void*), PAGE_READWRITE, &old_protect);
						*addr = InterlockedExchangePointer(*iat, *addr);
						VirtualProtect(iat, sizeof(void*), old_protect, 0);
						break;
					}
				}
				else
				{
					if ((strcmp(import_by_name->Name, api_name) == 0))
					{
						flag = TRUE;
						DWORD old_protect;
						VirtualProtect(iat, sizeof(void*), PAGE_READWRITE, &old_protect);
						*addr = InterlockedExchangePointer(iat, *addr);
						VirtualProtect(iat, sizeof(void*), old_protect, 0);
						break;
					}

				}
				thunk++;
				iat++;
			}

		}
		import++;
	}

	return 0;
}