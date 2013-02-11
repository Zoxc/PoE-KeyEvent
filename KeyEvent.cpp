#include "KeyEvent.hpp"

REGHANDLE provider;

void _stdcall private_key(const char *key)
{
	EVENT_DATA_DESCRIPTOR data;

	unsigned char output[0x40];

	sha4((const unsigned char *)key, 0x200, output, false);

	EventDataDescCreate(&data, output, 0x40);

	EventWrite(provider, &PrivateKey, 1, &data);
}

void __declspec(naked) generate_key_pair_stub()
{
	__asm
	{
		pusha
		push    [ebp+8]
		call private_key
		popa
		pop     esi
		pop     ebp
		retn    18h
	}
}

void patch_function(char *address, void *function_pointer)
{
	unsigned function_address = reinterpret_cast<unsigned>(function_pointer) - reinterpret_cast<unsigned>(address) - 5;
	std::string replacement_string = std::string((char *)&function_address, 4);
	std::string replacement = "\xe9" + replacement_string;

	DWORD old_protection;
	if(VirtualProtect(address, replacement.length(), PAGE_EXECUTE_READWRITE, &old_protection) == 0)
		throw "Unable to unprotect code";

	std::memcpy(address, replacement.c_str(), replacement.length());

	DWORD unused;
	if(VirtualProtect(address, replacement.length(), old_protection, &unused) == 0)
		throw "Unable to reprotect code";
}

extern "C" __declspec(dllexport) DWORD after_injection(HMODULE module)
{
	try
	{
		if(EventRegister(&PoeKeyProvider, NULL, NULL, &provider))
			throw "Unable to register event provider";

		const unsigned char pattern[] = {0x55, 0x8B, 0xEC, 0x56, 0xFF, 0x75, 0x1C, 0x8B, 0xF1, 0xFF, 0x75, 0x14, 0x8B, 0x4E, 0x04, 0xFF, 0x75, 0x0C, 0x8B, 0x01, 0xFF, 0x75, 0x08, 0xFF, 0x50, 0x34, 0x84, 0xC0, 0x74, 0x2A, 0x8B, 0x46, 0x08, 0x8B, 0x4E, 0x04, 0x57, 0x8B, 0x38, 0x8B, 0x01, 0x6A, 0x01, 0xFF, 0x75, 0x18, 0xFF, 0x75, 0x10, 0xFF, 0x50, 0x1C, 0x03, 0x45, 0x08, 0x8B, 0x4E, 0x08, 0x50, 0xFF, 0x57, 0x34, 0x5F, 0x84, 0xC0, 0x74, 0x05, 0x33, 0xC0, 0x40, 0xEB, 0x02, 0x33, 0xC0, 0x5E, 0x5D, 0xC2, 0x18, 0x00};
		char mask[sizeof(pattern)];
		memset(mask, 0xFF, sizeof(mask));

		char *result = (char *)find_pattern(GetModuleHandle(0), ".text", (char *)pattern, mask, sizeof(pattern));

		patch_function(result + sizeof(pattern) - 5, generate_key_pair_stub);
	}
	catch(const char *error)
	{
		MessageBoxA(0, error, "KeyEvent Error", 0);
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	return TRUE;
}
