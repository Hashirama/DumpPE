#include <iostream>
#include <string>
#include <Windows.h>
#include "PE.h"

#pragma comment(lib, "dbghelp.lib")

int main(int argc, char *argv[]) {
	if (argc != 3) {
		std::cerr << "Usage: " << argv[0] << " [options] " << "[file]" << std::endl;
		std::cout << "Options: /exports\n \t/imports" << std::endl;
		return -1;
	}

	std::string option = argv[1];
	std::string file = argv[2];
	PEFile pe(file);
	if (!pe.OpenFile())
		return false;
	if (!pe.MapFile())
		return false;
	if (option == "/exports")
		pe.ProcessFileExports();
	if (option == "/imports")
		pe.ProcessFileImports();

	return 0;
}