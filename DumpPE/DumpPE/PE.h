#include <string>
#include <iostream>
#include <Windows.h>
#include <dbghelp.h>

class PEFile {
public:
	PEFile(std::string n) : file(n) {}
	BOOL OpenFile();
	BOOL MapFile();
	VOID ProcessFileExports();
	VOID ProcessFileImports();
	DWORD RVAToOffset(PIMAGE_NT_HEADERS, DWORD);

	~PEFile();

private:
	std::string file;
	HANDLE FileHandle = nullptr;
	HANDLE FileMapping = nullptr;
	LPVOID base = nullptr;
};