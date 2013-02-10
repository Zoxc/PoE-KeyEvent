#include "KeyEvent.hpp"

REGHANDLE provider;

void _stdcall private_key(const char *key)
{
	EVENT_DATA_DESCRIPTOR data;

	EventDataDescCreate(&data, key, 0x80);

	EventWrite(provider, &PrivateKey, 1, &data);
}

void __declspec(naked) generate_key_pair_stub()
{
	__asm
	{
		push    [ebp+0x0C]
		call private_key
		pop     esi
		pop     ebp
		retn    0Ch
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

		const unsigned char pattern[] = {0x55, 0x8B, 0xEC, 0x56, 0xFF, 0x75, 0x0C, 0x8B, 0xF1, 0xFF, 0x75, 0x08, 0x8B, 0x06, 0xFF, 0x50, 0x28, 0xFF, 0x75, 0x10, 0x8B, 0x06, 0xFF, 0x75, 0x0C, 0x8B, 0xCE, 0xFF, 0x75, 0x08, 0xFF, 0x50, 0x2C, 0x5E, 0x5D, 0xC2, 0x0C, 0x00};
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
