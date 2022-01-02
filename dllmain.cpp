// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <iostream>

#include "runescape.h"

#include <string>

#include <windows.h>

#include "MinHook.h"

#include <fstream>

#include <map>

#include <Winsock2.h>

#include <time.h>

#pragma comment(lib, "WS2_32.lib")

#define LOG_FILE "log.txt"
std::fstream outputStream;
bool is_logging = false;
uintptr_t rs2Module = (uintptr_t) GetModuleHandleA("rs2client.exe");
uintptr_t isaac_obj;
SOCKET rs_socket = NULL;

std::string string_to_hex(const std::string & input) {
    static
    const char hex_digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c: input) {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

void log(const char * msg, bool newLine = true) {
    outputStream.open("C:\\Users\\workc\\l0lscape\\log.txt", std::ios_base::app);

    if (!outputStream.is_open()) {
        printf("Failed to open file.\n");
        return;
    }

    if (newLine)
        outputStream << msg << "\n";
    else
        outputStream << msg;

    outputStream.close();
}

void log_hex(const char * msg) {
    outputStream.open("C:\\Users\\workc\\l0lscape\\log.txt", std::ios_base::app);

    if (!outputStream.is_open()) {
        printf("Failed to open file.\n");
        return;
    }

    outputStream << std::hex << msg;
    outputStream.close();
}

//typedef void(__fastcall* _DoAction)(int a1, unsigned int a2, signed int actionIndex, int a4, int a5, int a6, __int64 a7, int a8, __int64 a9);
typedef void(__fastcall * _DoAction)(__int64 a1, char * a2, char * a3, int a4, __int64 a5, volatile signed __int32 ** a6, int a7, int a8, int a9, int a10, int a11, int a12, int a13, char a14, unsigned __int8 a15, __int64 * a16, unsigned __int8 a17, int a18);
_DoAction DoAction;

//__int64 __fastcall sub_115040(__int64 a1, unsigned int a2, unsigned int a3, unsigned __int8 a4)
typedef void(__fastcall * _DoAction1)(__int64 a1, unsigned int a2, unsigned int a3, unsigned __int8 a4);
_DoAction1 DoAction1;

//void __fastcall Test_Hook(__int64 a1, unsigned int a2, unsigned int a3, unsigned __int8 a4)
//{
//	std::cout << a1 << "\t: " << a2 << "\t:" << a3 << "\t:" << a4 << "\n";
//	return DoAction1(a1, a2, a3, a4);
//}
void __fastcall HookDoAction(__int64 a1, char * a2, char * a3, int a4, __int64 a5, volatile signed __int32 ** a6, int a7, int a8, int a9, int a10, int a11, int a12, int a13, char a14, unsigned __int8 a15, __int64 * a16, unsigned __int8 a17, int a18) {
    std::cout << a1 << "\t:\t" << a2 << "\t:\t" << a3 << "\n" << a4 << "\t:\t" << a5 << "\t:\t" << a6 << "\n" << a7 << "\t:\t" << a8 << "\t:\t" << a9 << "\n";
    std::cout << a10 << "\t:\t" << a11 << "\t:\t" << a12 << "\t:\t" << a13 << a14 << "\n" << a15 << "\t:\t" << a16 << "\t:\t" << a17 << "\n";

    return HookDoAction(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18);
}

typedef void(__fastcall * tMoveInv)(void * thisptr, int a, int b);
tMoveInv oMoveInv;

typedef void(__fastcall * tBury)(void * thisptr, int a, int b, int c, int d);
tBury oBury;

typedef void(__fastcall * _SendPacket)(__int64 a1,
    const char * a2, unsigned __int64 a3);
_SendPacket SendPacketO;

void __fastcall SendPacket(__int64 a1,
    const char * a2, unsigned __int64 a3) {
    if (rs_socket == NULL)
        rs_socket = a1;

    return SendPacketO(a1, a2, a3);
}

typedef char(__fastcall * CipherRefresh)(__int64 thisptr);
CipherRefresh cipher_refresh;
CipherRefresh manual_refresh = (CipherRefresh)((__int64)(rs2Module + 0x54F6B0));

char __fastcall refresh_cipher(__int64 sub_table) {
    std::cout << "[" << __TIMESTAMP__ << "] Isaac cipher table refreshed\n";
    return cipher_refresh(sub_table);
}

unsigned char yoinked_encrypt_opcode(unsigned char opcode) {
    unsigned char sub_table_count = * ((char * ) isaac_obj);
    printf("["
        __TIMESTAMP__ "] Assigned initial vars.\n");

    if (!sub_table_count) {
        manual_refresh((__int64) isaac_obj);
        printf("["
            __TIMESTAMP__ "] Called manual_refresh.\n");
        sub_table_count = 256;
    }

    printf("["
        __TIMESTAMP__ "] passed !sub_table_count.\n");
    //sub_table_count = sub_table_count - 1;
    *((char * ) isaac_obj) = sub_table_count; // This is not right... unless
    unsigned char shuffle = * ((char * )(isaac_obj + 0x4 + sub_table_count * 4));

    std::cout << "Shuffle:\t" << shuffle << "\n";

    unsigned char enc_opcode = opcode + shuffle;

    std::cout << "Enc Opcode:\t" << std::hex << enc_opcode << "\n";

    printf("["
        __TIMESTAMP__ "] returning encrypted opcode.\n");

    printf("%02X:%02X\n", opcode, enc_opcode);
    return enc_opcode;
}

// Hook Jagex send packet/encryption
//typedef void(__fastcall* EncryptOpcode)(__int64 a1, char original_opcode, int *isaac_table);
//EncryptOpcode encrypt_opcode_orig;
//typedef char(__fastcall* _EncryptOpcode)(__int64 a1, char original_opcode, int *isaac_table);
//_EncryptOpcode _encrypt_opcode_orig;
//
//typedef void(_fastcall* __Mtx_unlock)(__int64 mutexptr);
//__Mtx_unlock unlock_mutex_orig;
//void __fastcall unlock_mutex_hook(__int64  mutexptr) { return unlock_mutex_orig(mutexptr); }
//
//typedef void(__fastcall* __Mtx_lock)(__int64 mutexptr); /*: rs2client.exe + 0x595EB8*/
//__Mtx_lock lock_mutex_orig;
//void __fastcall lock_mutex_hook(__int64  mutexptr) { return lock_mutex_orig(mutexptr); }
//
//typedef void(__fastcall* _SendPacket)(__int64* thisptr, char** a2, unsigned int* a3, int** a4);
//_SendPacket send_packet_orig;
//void __fastcall send_packet(__int64* thisptr, char** a2, unsigned int* a3, int** a4)
//{
//	std::cout << thisptr << " " << a2 << " " << a3 << " " << a4 << "\n";
//	return send_packet_orig(thisptr, a2, a3, a4);
//}

//uintptr_t packet_mutex = (uintrptr_t)0x9C5498;

// osclient.exe + 0x73880
typedef void(__fastcall * _OSDoAction)(int a1, unsigned int a2, int a3, int a4, char * a5, __int64 a6, char a7, int a8, __int64 a9);
_OSDoAction OSDoAction;

// This is for oldschool.
// this project was me testing things, not writing anything to be used/maintained.
void __fastcall OsDoActionHook(int a1, unsigned int a2, int a3, int a4, char * a5, __int64 a6, char a7, int a8, __int64 a9) {
    printf("===========================================================================\n");
    std::cout << a1 << "\t" << a2 << "\t" << a3 << "\n";
    std::cout << a4 << "\t" << a5 << "\t" << a6 << "\t" << a7 << "\n";
    std::cout << a8 << "\t" << a9 << "\t" << "\n";
    printf("===========================================================================\n");
    return OSDoAction(a1, a2, a3, a4, a5, a6, a7, a8, a9);
}
//
//
//uintptr_t socket_module = (uintptr_t)(rs2Module + 0x4231A0);
//__int64 this_ptr = NULL;
//int* cipher_count;
//
//void drop_item1(int inv_slot, int id)
//{
//	char* packet_buffer = (char*)malloc(9);
//	if (packet_buffer != nullptr)
//	{
//		packet_buffer[0] = yoinked_encrypt_opcode(0x4c);
//		packet_buffer[1] = 0;
//		packet_buffer[2] = 0;
//		packet_buffer[3] = 0x95;
//		packet_buffer[4] = 0;
//		packet_buffer[5] = (char)(id & 0xFF) + 0x80;
//		packet_buffer[6] = (char)((id & 0xFF00) >> 8);
//		packet_buffer[7] = inv_slot;
//		packet_buffer[8] = 0;
//
//		send(rs_socket, (char*)packet_buffer, 9, 0);
//	}
//}

// Rs3 will send multiple packets in the same tick if it makes sense to do so,
// meaning this didn't work as it didn't properly lock/unlock Jagex's packet mutex.
void drop_item(int inv_slot, int id) {
    std::cout << inv_slot << "\n";
    ////net_log("Dropping item:\t%d:%d", slot, item_id);
    //lock_mutex_orig((__int64)0x9C54A0);

    //char* packet_buffer = (char*)malloc(18);
    //if (packet_buffer != nullptr)
    //{
    //	packet_buffer[0] = yoinked_encrypt_opcode(0x2F);
    //	packet_buffer[1] = 0x19;
    //	packet_buffer[2] = 0x0;
    //	packet_buffer[3] = 0xC5;
    //	packet_buffer[4] = 0x05;
    //	packet_buffer[5] = 0xC1;
    //	packet_buffer[6] = 0x05;
    //	packet_buffer[7] = 0x07;
    //	packet_buffer[8] = 0x0;
    //	packet_buffer[9] = 0xFF;
    //	packet_buffer[10] = 0xFF;
    //	packet_buffer[11] = inv_slot;
    //	packet_buffer[12] = 0x0;
    //	packet_buffer[13] = 0xFF;
    //	packet_buffer[14] = 0xFF;
    //	packet_buffer[15] = (char)(id  & 0xFF) + 0x80;
    //	packet_buffer[16] = (char)((id & 0xFF00) >> 8);
    //	packet_buffer[17] = 0x05;

    //	std::cout << "Constructed packet buffer:\t" << packet_buffer << "\n";
    //	send(rs_socket, (char*)packet_buffer, 17, 0);
    //}
    //free(packet_buffer);
    //unlock_mutex_orig((__int64)0x9C60F0);
}

std::map < char, int > key_value;

//void __fastcall encrypt_opcode(__int64 a1, char original_opcode, int* sub_table_object)
//{
//	if (this_ptr == NULL)
//		this_ptr = a1;
//
//	if (cipher_count == NULL)
//		cipher_count = sub_table_object;
//
//	printf("[" __TIMESTAMP__ "] Encrypt packet opcode (%02X)...", original_opcode);
//
//	return encrypt_opcode_orig(a1, original_opcode, sub_table_object);
//}

//typedef void(__fastcall* PacketAllocation)(__int64 *packet, __int64 *opcode);
//PacketAllocation OriginalPacketAllocation;
//
//void __fastcall AllocatePacket(__int64 *packet, __int64 *opcode)
//{
//	std::cout << "Packet:\t" << packet << "\tOP:\t" << opcode << "\n";
//	return OriginalPacketAllocation(packet, opcode);
//}

//void __fastcall send73(__int64 a1, int a2, int a3, __int64* a4, __int64* a5, int a6, __int64* a7, __int64 a8, __int64* a9, int a10)
//{
//	std::cout << a1 << "\t" << a2 << "\t" << a3 << "\t" << a4 << "\n";
//	std::cout << a5 << "\t" << a6 << "\t" << a7 << "\t" << a8 << "\n";
//	std::cout << a9 << "\t" << a10 << "\n";
//	std::cout << "--------------------------------------------------" << "\n";
//	return oPacket4(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
//}

void __fastcall HookMoveItem(void * thisptr, int a, int b) {
    std::cout << "int64_t a1:\t" << a << "\n" << "int64_t a2:\t" << b << "\n";
    std::cout << "RCX:\t" << & thisptr << "\n";
    //return oMoveInv(thisptr, a, b);
}

void __fastcall HookBuryBones(void * thisptr, int a, int b, int c, int d) {
    std::cout << "\n\nA:\t" << a << /*"\nb:\t" <<  b <<*/ "\nC:\t" << c << "\nD:\t" << d << "\n";

    std::cout << "RCX:\t" << & thisptr << "\n";

    return oBury(thisptr, a, b, c, d);
}

uintptr_t WINAPI L0L(HMODULE hModule) {
    log(__TIMESTAMP__ " Started.\n" );
    //--------------------------------------------------
    // Create Console
    AllocConsole();
    FILE * f;
    freopen_s( & f, "CONOUT$", "w", stdout);

    //--------------------------------------------------
    // Yoink Local Player 
    uintptr_t * localPlayerAddress = (uintptr_t * ) FindDMAAddy(rs2Module + 0x009A2C38, {
        0xC78,
        0x110,
        0x18,
        0x0
    });
    std::cout << "Local Player end of chain: " << & localPlayerAddress << "\n";

    //// Yoink engine-relative cursor X/Y
    uintptr_t * myPosAddress = (uintptr_t * )(rs2Module + 0x97639C - 0x4);

    ////--------------------------------------------------
    //// Yoink Inventory 
    uintptr_t * inventoryAddress = (uintptr_t * ) FindDMAAddy(rs2Module + 0x00976108, {
        0x388,
        0x20,
        0xD70,
        0x8,
        0x18
    });
    std::cout << "Inventory end of chain: " << & inventoryAddress << "\n";
    std::vector < InventorySlot > * myItems;

    isaac_obj = (uintptr_t) FindDMAAddy(rs2Module + 0x00997CA0, {
        0x3D0,
        0x18,
        0x20,
        0xC70,
        0x10,
        0x60
    });
    printf("["
        __TIMESTAMP__ "] Isaac Address: %08X", isaac_obj);

    if (MH_Initialize() != MH_OK)
        printf("Minhook boom~\n");

    if (encrypt_opcode_hook != 0)
        printf(__TIMESTAMP__ " Opcode enc hook failed.\n");

    //auto encrypt_hook_enable = MH_EnableHook((void*)encrypt_opcode_hook);
    //if (encrypt_hook_enable != 0)
    //	printf(__TIMESTAMP__ " Couldn't enable opcode encryption hook.\n");

    //if (isaac_refresh_hook != 0)
    //	printf(__TIMESTAMP__ " Cipher table refresh hook failed.\n");

    //auto cipher_enable = MH_EnableHook((void*)isaac_refresh_hook);
    //if (cipher_enable != 0)
    printf(__TIMESTAMP__ " Couldn't enable cipher table refresh hook.\n");

    if (send_packet_hook != 0)
        printf(__TIMESTAMP__ " SendPacket hook failed.\n");

    //if (mutex_lock_hook != 0)
    //	printf(__TIMESTAMP__ " MutexLock hook failed.\n");

    //auto mutex_lock_enable = MH_EnableHook((void*)mutex_lock_hook);
    //if (mutex_lock_hook != 0)
    //	printf(__TIMESTAMP__ " Couldn't enable mutex lock hook.\n");

    //--------------------------------------------------
    // Yoink Runescape functions
    //void* yoink_encryption = DetourFunction64((LPVOID)(rs2Module + 0x59680), &encrypt_opcode, 14);
    //oMoveInv = (tMoveInv)DetourFunction64((LPVOID)(rs2Module + 0x175D50), &HookMoveItem, 14);
    //oBury = (tBury)DetourFunction64((LPVOID)(rs2Module + 0x28530), &HookBuryBones, 20);	// Top of func hook
    //oBury = (tBury)DetourFunction64((LPVOID)(rs2Module + 0x285BC), &HookBuryBones, 14);	// bottom of func hook

    //int click_count = 0;
    while (true) {
        if (GetAsyncKeyState(VK_F7) & 1) {
            std::cout << "Isaac:\t" << rs_socket << "\n";
            std::cout << "Isaac &:\t" << & rs_socket << "\n";
            std::cout << "Isaac *:\t" << isaac_obj << "\n";
            printf("Isaac cast:%02X\n", *(char * ) isaac_obj);
        }
        //printf("[" __TIMESTAMP__ "] Assigned initial vars.\n");

        //if (!sub_table_count)
        //{
        //	manual_refresh((__int64)*isaac_obj);
        //	printf("[" __TIMESTAMP__ "] Called manual_refresh.\n");
        //	sub_table_count = 256;
        //printf("[" __TIMESTAMP__ "] passed !sub_table_count.\n");
        //sub_table_count = sub_table_count - 1;
        //*((char*)*isaac_obj) = sub_table_count;	// This is not right... unless
        //unsigned char shuffle = *((char*)(*isaac_obj + 0x4 + sub_table_count * 4));
        //unsigned char enc_opcode = opcode + shuffle;

        //printf("[" __TIMESTAMP__ "] returning encrypted opcode.\n");
        //return enc_opcode;

        //if (GetAsyncKeyState(VK_F6) & 1)
        //{
        //	//if (isaac == NULL)
        //	//{
        //	//	printf(__TIMESTAMP__ " isaac is still null. Has an opcode been encrypted by the game yet?\n");
        //	//}
        //	//else
        //	//{
        //	//	//cipher_refresh(isaac);
        //	//	printf(__TIMESTAMP__ " called refresh manually.\n");
        //	//}

        //	drop_item(0x1, 1519);
        //	//yoinked_encrypt_opcode(47);
        //	//std::cout << "NICE!!!\n";
        //}
        //if (GetAsyncKeyState(VK_LBUTTON) & 1)
        //{
        //	click_count++;
        //	printf("Click count: %d\n", click_count);
        //}

        //if (GetAsyncKeyState(VK_F12) & 1)
        //{
        //	std::map<char, int>::iterator it = key_value.begin();
        //	while (it != key_value.end())
        //	{
        //		if (it->second == click_count)
        //			printf("Opcode:\t%02X\tCount:%d\n", it->first, it->second);

        //		it++;
        //	}
        //}

        Player * localPlayer = (Player * ) localPlayerAddress;
        MyPos * MyPosition = (MyPos * ) myPosAddress;

        if (GetAsyncKeyState(VK_F8) & 1) {
            std::cout << std::to_string(localPlayer -> Animation) << "\n";
            std::cout << localPlayer -> Username << "\n";
            // Cursor X/Y. **NOT player position as I assumed prior :/**
            std::cout << MyPosition -> X << "\n";
            std::cout << MyPosition -> Y << "\n";
        }

        if (GetAsyncKeyState(VK_F10) & 1) {
            myItems = (std::vector < InventorySlot > * ) inventoryAddress;
            for (auto & item: * myItems) {
                std::cout << "Inventory slot:\n";
                std::cout << "\t\tItem:         " << IdToName(item.id) << "\n";
                std::cout << "\t\tItem ID:      " << std::to_string(item.id) << "\n";
                std::cout << "\t\tAmount:       " << std::to_string(item.amount) << "\n\n\n";
            }
            //std::cout << "Inventory slot one:\n";
            //std::cout << "\t\tItem ID:		" << &myItems->at(1).id		<< "\n";
            //std::cout << "\t\tAmount:		" << &myItems->at(1).amount	<< "\n\n\n";
        }

        if (GetAsyncKeyState(VK_F5) & 1) {

            size_t address;
            std::string data;
            int size;

            std::ifstream add_file;
            add_file.open("C:\\Users\\workc\\l0lscape\\add.txt");
            std::ifstream hex_file;
            hex_file.open("C:\\Users\\workc\\l0lscape\\hex.txt");
            std::ifstream size_file;
            size_file.open("C:\\Users\\workc\\l0lscape\\size.txt");

            add_file >> address;
            hex_file >> data;
            size_file >> size;

            //std::cout << "Address: ";
            //std::cin >> address;
            //std::cout << "\nData: ";
            //std::cin >> data;
            //std::cout << "\nSize: ";
            //std::cin >> size;

            // Nuked the typedef mybad.
            // SendOrig(address, data.c_str(), size);
        }

        if (GetAsyncKeyState(VK_F1) & 1)
            break;

        Sleep(1);
    }

    MH_DisableHook((void * ) encrypt_opcode_hook);
    //MH_DisableHook((void*)os_do_action_hook);

    fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CloseHandle(
            CreateThread(nullptr,
                0,
                (LPTHREAD_START_ROUTINE) L0L,
                hModule,
                0,
                nullptr
            )
        );
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
