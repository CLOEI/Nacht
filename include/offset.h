#pragma once

#include <Windows.h>
#include <cstdint>

#define SEND_PACKET_SIGNATURE "4C 89 44 24 ? 48 89 54 24 ? 89 4C 24"
#define SEND_PACKET_RAW_SIGNATURE "4C 89 4C 24 ? 44 89 44 24 ? 48 89 54 24 ? 89 4C 24"
#define ENET_HOST_SERVICE_SIGNATURE "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 45 8B F8"

void SendPacket(int32_t arg1, int64_t* arg2, void* arg3);
void SendPacketRaw(int32_t arg1, void* arg2, int32_t arg3, int64_t arg4, void* arg5, int32_t arg6);
// int enet_host_service(ENetHost *, ENetEvent *, enet_uint32);

class Offset {
    public:
        uint64_t sendPacket;
        uint64_t sendPacketRaw;
        uint64_t enetHostService;

        void init(HANDLE hProcess);
        HMODULE GetRemoteModuleHandle(HANDLE hProcess, const char* moduleName);
    private:
        uint64_t patternScan(HANDLE hProcess, uint64_t startAddress, size_t size, const char* signature);
};