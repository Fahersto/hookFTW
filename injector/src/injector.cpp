#include <cstdio>
#include <Windows.h>
#include <filesystem>
#include <string>

int main(int argc, char** argv)
{
	if(argc < 3)
	{
		printf("usage: .exe pid dllPath");
		return 1;
	}

	// get command line arguments
	DWORD processId = std::stoi(argv[1]);
	std::string dllPath = argv[2];
	
	auto currentPath = std::filesystem::current_path();
	auto name = currentPath.generic_string();

	// aquire a handle to the target process
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if(!processHandle)
	{
		printf("Error - Failed to open process [%d]\n", processId);
		return 1;
	}

	// allocate memory in the target process
	LPVOID remoteMemory = VirtualAllocEx(processHandle, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!remoteMemory)
	{
		printf("Error - Failed to allocate memory in target process\n");
		return 1;
	}

	// write path of .dll to target process
	bool memoryWritten = WriteProcessMemory(processHandle, remoteMemory, dllPath.c_str(), dllPath.length(), nullptr);
	if(!memoryWritten)
	{
		printf("Error - Failed to write .dll path to target process\n");
		return 1;
	}

	// create a thread in the target process which loads the .dll
	HANDLE hThread = CreateRemoteThread(
		processHandle,
		nullptr,
		NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA")),
		remoteMemory,
		NULL,
		nullptr
	);
	if (!hThread)
	{
		printf("Error - Failed to create thread in target process\n");
		return 1;
	}

	// cleanup
	CloseHandle(processHandle);
	//virtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE); //this is a race condition with the remote thread
	
	return 0;
}
