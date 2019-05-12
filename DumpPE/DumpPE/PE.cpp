#include "PE.h"

BOOL PEFile::OpenFile() {
	FileHandle = CreateFileA(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (FileHandle == INVALID_HANDLE_VALUE) {
		std::cerr << "Couldn't open file" << std::endl;
		return false;
	}
	return true;
}

BOOL PEFile::MapFile() {
	FileMapping = CreateFileMappingA(FileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (FileMapping == nullptr) {
		std::cerr << "Failed to create file mapping" << std::endl;
		return false;
	}
	base = MapViewOfFile(FileMapping, FILE_MAP_READ, 0, 0, 0);
	if (base == nullptr) {
		std::cerr << "Failed to map view of file" << std::endl;
		return false;
	}
	return true;
}

DWORD PEFile::RVAToOffset(PIMAGE_NT_HEADERS nt, DWORD rva) {
	PIMAGE_OPTIONAL_HEADER opt = &nt->OptionalHeader;
	PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)((BYTE*)opt + nt->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i != nt->FileHeader.NumberOfSections; i++) {
		if (rva >= sec[i].VirtualAddress && rva < (sec[i].VirtualAddress + sec[i].SizeOfRawData)) {
			return ((rva - sec[i].VirtualAddress) + sec[i].PointerToRawData);
		}
	}
	return rva;
}

PEFile::~PEFile() {
	if(base)
		UnmapViewOfFile(base);
	if (FileMapping)
		CloseHandle(FileMapping);
	if (FileHandle)
		CloseHandle(FileHandle);
}

VOID PEFile::ProcessFileExports() {
	PIMAGE_NT_HEADERS nt = ImageNtHeader(base);
	PIMAGE_EXPORT_DIRECTORY exp = nullptr;
	if (*((WORD*)base) != IMAGE_DOS_SIGNATURE &&
		*((DWORD*)nt) != IMAGE_NT_SIGNATURE) {
		std::cerr << "Not a valid PE executable" << std::endl;
		return;
	}
	if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return;
	DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	exp = (PIMAGE_EXPORT_DIRECTORY) ((BYTE*)base + RVAToOffset(nt, rva));

	for (int i = 0; i != exp->NumberOfNames; i++) {
		DWORD rva_names = (exp->AddressOfNames + (sizeof(DWORD) * i));
		rva_names = *(DWORD*)((BYTE*)base + RVAToOffset(nt, rva_names));
		BYTE* va = ((BYTE*)base + RVAToOffset(nt, rva_names));

		DWORD rva_ord = (exp->AddressOfNameOrdinals + (sizeof(WORD) * i));
		WORD ord = *((WORD*)((BYTE*)base + RVAToOffset(nt, rva_ord)));


		std::cout << ord + exp->Base << " " <<  va << std::endl;
	}

}

VOID PEFile::ProcessFileImports() {
	PIMAGE_NT_HEADERS nt = ImageNtHeader(base);
	PIMAGE_IMPORT_DESCRIPTOR imp = nullptr;

	if (*((WORD*)base) != IMAGE_DOS_SIGNATURE &&
		*((DWORD*)nt) != IMAGE_NT_SIGNATURE) {
		std::cerr << "Not a valid PE executable" << std::endl;
		return;
	}
	if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
		return;
	DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	imp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + RVAToOffset(nt, rva));
	while (imp->Name != 0) {
		DWORD rva_name = imp->Name;
		BYTE* ptr = ((BYTE*)base + RVAToOffset(nt, rva_name));
		std::cout << "\n" << "\t" << ptr << "\n" << std::endl;

		DWORD thunk;
		PIMAGE_THUNK_DATA _thunk;
		if (imp->OriginalFirstThunk != 0) {
			thunk = imp->OriginalFirstThunk;
		}
		else {
			thunk = imp->FirstThunk;
		}
		_thunk = (PIMAGE_THUNK_DATA)((BYTE*)base + RVAToOffset(nt, thunk));
			while (_thunk->u1.AddressOfData != 0) {
				if ((_thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG32)) {
					DWORD ord = _thunk->u1.AddressOfData;
					ord &= 0xFFFF;
					std::cout << "\t\t" << ord << std::endl;
					++_thunk;
				}
				else {
					DWORD by_name_rva = _thunk->u1.AddressOfData;
					PIMAGE_IMPORT_BY_NAME imp_by_name = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + RVAToOffset(nt, by_name_rva));
					DWORD hint = imp_by_name->Hint;
					BYTE * name = (BYTE*)imp_by_name->Name;

					std::cout << "\t\t" << std::uppercase << std::hex << hint << "  " << name << std::endl;
					++_thunk;
				}
			}
		imp++;
	}
}