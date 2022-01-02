#include "pch.h"
#include <Windows.h>
#include <string>
#include <cstdint>


uintptr_t SkillBase = 0x00996A80;
std::vector<uintptr_t> SkillBaseOffs = { 0x3D0, 0x40, 0xBC0, 0x20, 0xE8, 0x10 };	// Thieving being 0x1a8


struct MyPos
{
	int X;
	int Y;
};

class Player
{
public:
	char pad_0000[320]; //0x0000
	char Username[12]; //0x0140
	char pad_014C[2460]; //0x014C
	uint16_t Animation; //0x0AE8
	char pad_0AEA[3446]; //0x0AEA
}; //Size: 0x1860

class InventorySlot
{
public:
	int id;
	int amount;
};

std::string IdToName(int id)
{
	switch (id)
	{
	case 1519:
		return "Willow logs";
	case 1521:
		return "Oak logs";
	case 52:
		return "Arrow Shaft";
	case 440:
		return "Iron ore";
	case 447:
		return "Mithril ore";
	case 554:
		return "Fire rune";
	case 555:
		return "Water rune";
	case 557:
		return "Earth rune";
	case 559:
		return "Body rune";
	case 12158:
		return "Gold charm";
	case 12159:
		return "Green charm";
	case 12160:
		return "Crimson charm";
	case 12163:
		return "Blue charm";
	case 1965:
		return "Cabbage";
	default:
		return std::to_string(id);
	}
}

uintptr_t FindDMAAddy(uintptr_t ptr, std::vector<unsigned int> offsets)
{
	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i)
	{
		printf("[" __TIMESTAMP__ "] Following offset %04X.", offsets[i]);
		addr = *(uintptr_t*)addr;
		addr += offsets[i];
		std::cout << std::hex << addr << std::endl;
	}
	return addr;
}

//template <typename T>
//bool Hex2Dec(const std::string& hex, T& result)
//{
//	std::stringstream sS;
//	sS << std::hex << hex;
//	ss >> result;
//
//	return !sS.fail();
//}
