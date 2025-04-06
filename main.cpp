#include <iostream>
#include <windows.h>
#include <vector>

#include "offset.h"

#define PROCESS_NAME "Growtopia"

bool requestDebugPrivilege() {
    LUID luid;
    bool bRet = false;

    if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        HANDLE hToken = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            bRet = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            CloseHandle(hToken);

            bRet = (bRet && GetLastError() == ERROR_SUCCESS);
        }
    }

    return bRet;
}

int main() {
    if (!requestDebugPrivilege()) {
        std::cerr << "Failed to request debug privilege." << std::endl;
        return 1;
    }

    HWND hwnd = FindWindowA(nullptr, PROCESS_NAME);
    if (!hwnd) {
        std::cerr << "Failed to find " << PROCESS_NAME << " window." << std::endl;
        return 1;
    } else {
        std::cout << "Found " << PROCESS_NAME << " window." << std::endl;
    }

    DWORD processId = 0;
    GetWindowThreadProcessId(hwnd, &processId);
    if (processId == 0) {
        std::cerr << "Failed to get process ID." << std::endl;
        return 1;
    } else {
        std::cout << "Process ID: " << processId << std::endl;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "Failed to open process." << std::endl;
        return 1;
    } else {
        std::cout << "Opened process successfully." << std::endl;
    }

    std::vector<BYTE> bytesToWrite = { 0x4C, 0x8B, 0xD1, 0xB8, 0x50 };
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(hProcess, (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"), 
                       bytesToWrite.data(), bytesToWrite.size(), &bytesWritten);
    if (bytesWritten != bytesToWrite.size()) {
        std::cerr << "Failed to write memory." << std::endl;
        CloseHandle(hProcess);
        return 1;
    } else {
        std::cout << "Memory written successfully." << std::endl;
    }

    Offset offset { };
    offset.init(hProcess);

    CloseHandle(hProcess);
    return 0;
}