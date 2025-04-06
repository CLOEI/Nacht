#include "offset.h"

#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <iostream>

void Offset::init(HANDLE hProcess) {
    MODULEINFO moduleInfo;
    HMODULE hModule = GetRemoteModuleHandle(hProcess, "Growtopia.exe");

    if (hModule && GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
        uint64_t baseAddress = (uint64_t)moduleInfo.lpBaseOfDll;
        size_t moduleSize = moduleInfo.SizeOfImage;

        sendPacket = patternScan(hProcess, baseAddress, moduleSize, SEND_PACKET_SIGNATURE);
        std::cout << "SendPacket: " << std::hex << sendPacket << std::endl;
        sendPacketRaw = patternScan(hProcess, baseAddress, moduleSize, SEND_PACKET_RAW_SIGNATURE);
        std::cout << "SendPacketRaw: " << std::hex << sendPacketRaw << std::endl;
        enetHostService = patternScan(hProcess, baseAddress, moduleSize, ENET_HOST_SERVICE_SIGNATURE);
        std::cout << "ENetHostService: " << std::hex << enetHostService << std::endl;
    } else {
        std::cerr << "Failed to get module information." << std::endl;
    }
}

HMODULE Offset::GetRemoteModuleHandle(HANDLE hProcess, const char* moduleName) {
    HMODULE hModule = nullptr;
    MODULEENTRY32 moduleEntry = { 0 };
    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot." << std::endl;
        return nullptr;
    }

    if (Module32First(hSnapshot, &moduleEntry)) {
        do {
            if (_stricmp(moduleEntry.szModule, moduleName) == 0) {
                hModule = moduleEntry.hModule;
                break;
            }
        } while (Module32Next(hSnapshot, &moduleEntry));
    }

    CloseHandle(hSnapshot);
    return hModule;
}

uint64_t Offset::patternScan(HANDLE hProcess, uint64_t startAddress, size_t size, const char* signature) {
    std::vector<BYTE> pattern = { };
    std::vector<BYTE> mask = { };

    const char* current = signature;
    while (*current) {
        if (*current == ' ') {
            current++;
            continue;
        }

        if (*current == '?') {
            pattern.push_back(0);
            mask.push_back(false);
            current++;
            if (*current == '?') current++; 
        } else {
            pattern.push_back(static_cast<uint8_t>(strtol(current, nullptr, 16)));
            mask.push_back(true);
            current += 2;
        }
    }

    std::vector<uint8_t> buffer(size);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)startAddress, buffer.data(), size, &bytesRead)) {
        return 0;
    }

    for (size_t i = 0; i < bytesRead - pattern.size(); i++) {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); j++) {
            if (mask[j] && buffer[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }

        if (found) {
            return startAddress + i;
        }
    }

    return 0;
}
