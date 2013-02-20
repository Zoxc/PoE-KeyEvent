#include "KeyEvent.hpp"

REGHANDLE provider;

#define Terminate(...) do { char buffer[500]; sprintf_s(buffer, __VA_ARGS__); throw buffer; } while(0)

enum BreakpointType
{
	BreakpointCode = 0,
	BreakpointReadWrite,
	BreakpointWrite
};

enum BreakpointSize
{
	BreakpointByte = 0,
	BreakpointWord,
	BreakpointDword,
	BreakpointQword
};

void CreateBreakpoint(CONTEXT* Context, void* Address, enum BreakpointType Type, enum BreakpointSize Size)
{
	DWORD* DrAddresses[] =
	{
		&Context->Dr0,
		&Context->Dr1,
		&Context->Dr2,
		&Context->Dr3
	};

	int i;

	int FirstFree = -1;

	for(i = 0; i < 4; i++)
	{
		if(!(Context->Dr7 & (1 << (i * 2))))
		{
			FirstFree = i;
			break;
		}
	}

	if(FirstFree == -1)
		Terminate("No more free breakpoints in thread %u\n", GetCurrentThreadId());

	*DrAddresses[FirstFree] = (DWORD)Address;

	Context->Dr7 |= (1 << (FirstFree * 2));

	Context->Dr7 &= ~(0xF << (FirstFree * 4 + 16));

	Context->Dr7 |= ((Type & 3) | ((Size & 3) << 2)) << (FirstFree * 4 + 16);
}

void CreateBreakpointInThread(unsigned int ThreadId, void* Address, enum BreakpointType Type, enum BreakpointSize Size)
{
	HANDLE Thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 0, ThreadId);
	CONTEXT Context; 

	if(!Thread)
		Terminate("CreateBreakpointInThread: Unable to get thread handle from thread %u (%u).\n", ThreadId, GetLastError());

	if(SuspendThread(Thread) == -1)
		Terminate("CreateBreakpointInThread: Unable to suspend thread %u (%u).\n", ThreadId, GetLastError());

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if(!GetThreadContext(Thread, &Context))
		Terminate("CreateBreakpointInThread: Unable to get thread context from thread %u (%u).\n", ThreadId, GetLastError());

	CreateBreakpoint(&Context, Address, Type, Size);

	if(!SetThreadContext(Thread, &Context))
		Terminate("CreateBreakpointInThread: Unable to set thread context to thread %u (%u).\n", ThreadId, GetLastError());

	if(ResumeThread(Thread) == -1)
		Terminate("CreateBreakpointInThread: Unable to resume thread %u (%u).\n", ThreadId, GetLastError());

	CloseHandle(Thread);
}

void *hooked_address;

void (__stdcall *ZwContinue)(CONTEXT* Context, int Unknown);

LONG NTAPI exception_handler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if(ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
		return EXCEPTION_CONTINUE_SEARCH;

	if(ExceptionInfo->ExceptionRecord->ExceptionAddress != hooked_address)
		return EXCEPTION_CONTINUE_SEARCH;

	EVENT_DATA_DESCRIPTOR data;

	unsigned char output[0x40];

	auto context = ExceptionInfo->ContextRecord;

	auto key = *(const unsigned char **)(context->Ebp + 8);

	sha4((const unsigned char *)key, 0x200, output, false);

	EventDataDescCreate(&data, output, 0x40);

	EventWrite(provider, &PrivateKey, 1, &data);

	// do pop ebp
	context->Ebp = *(DWORD *)context->Esp;
	context->Esp += 4;
	context->Eip++;

	ZwContinue(ExceptionInfo->ContextRecord, 0);

	return EXCEPTION_CONTINUE_SEARCH;
}

extern "C" __declspec(dllexport) DWORD after_injection(HMODULE module, DWORD main_thread)
{
	try
	{
		if(EventRegister(&PoeKeyProvider, NULL, NULL, &provider))
			throw "Unable to register event provider";

		const unsigned char pattern[] = {0x55, 0x8B, 0xEC, 0x56, 0xFF, 0x75, 0x1C, 0x8B, 0xF1, 0xFF, 0x75, 0x14, 0x8B, 0x4E, 0x04, 0xFF, 0x75, 0x0C, 0x8B, 0x01, 0xFF, 0x75, 0x08, 0xFF, 0x50, 0x34, 0x84, 0xC0, 0x74, 0x2A, 0x8B, 0x46, 0x08, 0x8B, 0x4E, 0x04, 0x57, 0x8B, 0x38, 0x8B, 0x01, 0x6A, 0x01, 0xFF, 0x75, 0x18, 0xFF, 0x75, 0x10, 0xFF, 0x50, 0x1C, 0x03, 0x45, 0x08, 0x8B, 0x4E, 0x08, 0x50, 0xFF, 0x57, 0x34, 0x5F, 0x84, 0xC0, 0x74, 0x05, 0x33, 0xC0, 0x40, 0xEB, 0x02, 0x33, 0xC0, 0x5E, 0x5D, 0xC2, 0x18, 0x00};
		char mask[sizeof(pattern)];
		memset(mask, 0xFF, sizeof(mask));

		char *result = (char *)find_pattern(GetModuleHandle(0), ".text", (char *)pattern, mask, sizeof(pattern));

		ZwContinue = (decltype(ZwContinue))GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwContinue");

		if(!AddVectoredExceptionHandler(1, &exception_handler))
			throw "Unable to register vectored exception handler";

		hooked_address = result + sizeof(pattern) - 4;

		CreateBreakpointInThread(main_thread, hooked_address, BreakpointCode, BreakpointByte);
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
