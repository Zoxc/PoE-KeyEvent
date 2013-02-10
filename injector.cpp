#pragma once
#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tchar.h>
#include <shellapi.h>
#include <string>
#include <sstream>
#include <functional>
#include <iostream>
#include <Winternl.h>

static PROCESS_INFORMATION pi;

typedef ULONG (NTAPI *RtlNtStatusToDosErrorType)(NTSTATUS Status);
typedef VOID (NTAPI *RtlInitAnsiStringType)(PANSI_STRING DestinationString, PCSZ SourceString);
typedef VOID (NTAPI *RtlInitUnicodeStringType)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

static RtlNtStatusToDosErrorType RtlNtStatusToDosErrorFunc;
static RtlInitAnsiStringType RtlInitAnsiStringFunc;
static RtlInitUnicodeStringType RtlInitUnicodeStringFunc;

#ifdef _UNICODE
	typedef std::wstring string;
	typedef std::wstringstream stringstream;
#else
	typedef std::string string;
	typedef std::stringstream stringstream;
#endif

void raise_error_num(const string &message, DWORD err_no)
{
	TCHAR *msg_buffer;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |	FORMAT_MESSAGE_IGNORE_INSERTS, 0, err_no, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&msg_buffer, 0, 0);

	stringstream msg;

	msg << message << _T("\nError #") << err_no << ": " << string(msg_buffer);

	LocalFree(msg_buffer);

	throw msg.str();
}

void raise_last_error(const string &message)
{
	raise_error_num(message, GetLastError());
}

struct External
{
	void *data;

	External(const void *input, size_t size)
	{
		data = VirtualAllocEx(pi.hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if(!data)
			raise_last_error(_T("Unable to allocate external memory"));

		if(!WriteProcessMemory(pi.hProcess, data, input, size, 0))
			raise_last_error(_T("Unable to write to external memory"));
	}

	void read(void *output, size_t size)
	{
		if(!ReadProcessMemory(pi.hProcess, data, output, size, 0))
			raise_last_error(_T("Unable to read from external memory"));
	}

	~External()
	{
		VirtualFreeEx(pi.hProcess, data, 0, MEM_RELEASE);
	}
};

struct HandleScope
{
	HANDLE handle;

	HandleScope(HANDLE handle) : handle(handle)	{}

	~HandleScope()
	{
		CloseHandle(handle);
	}
};

struct Finally
{
	std::function<void()> func;
	bool execute;

	template<typename F> Finally(F func) : func(func), execute(true) {}

	~Finally()
	{
		if(execute)
			func();
	}
};

enum ErrorType
{
	IE_ERROR_NONE,
	IE_ERROR_LOAD_LIBRARY,
	IE_ERROR_GET_PROC_ADDRESS,
	IE_ERROR_CALLBACK
};

struct Data
{
	ErrorType error;
	NTSTATUS err_num;
	UNICODE_STRING dll;
	ANSI_STRING func;
	NTSTATUS (NTAPI *LdrLoadDll)(PWCHAR PathToFile, ULONG *Flags, UNICODE_STRING *ModuleFileName, HMODULE *ModuleHandle); 
	NTSTATUS (NTAPI *LdrGetProcedureAddress)(HMODULE ModuleHandle, PANSI_STRING FunctionName, WORD Oridinal, PVOID *FunctionAddress);
	
#ifndef REMOTE_THREAD
	HANDLE event;
	NTSTATUS (NTAPI *NtSetEvent)(HANDLE EventHandle, PLONG PreviousState);
#endif
};

typedef DWORD (_cdecl *after_injection_t)(HMODULE module);

#pragma code_seg(push, ".cave")
#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(push, off) 
#ifdef REMOTE_THREAD
extern "C" static DWORD WINAPI code_cave(Data &data)
#else
extern "C" static void _fastcall code_cave(Data &data)
#endif
{
	HMODULE module; 
	ULONG flags = LOAD_WITH_ALTERED_SEARCH_PATH;
	
	NTSTATUS error = data.LdrLoadDll(NULL, &flags, &data.dll, &module);

	if(!NT_SUCCESS(error))
	{
		data.error = IE_ERROR_LOAD_LIBRARY;
		data.err_num = error;
		goto exit;
	}

	after_injection_t func;
	
	error = data.LdrGetProcedureAddress(module, &data.func, 0, (PVOID *)&func);

	if(!NT_SUCCESS(error))
	{
		data.error = IE_ERROR_GET_PROC_ADDRESS;
		data.err_num = error;
		goto exit;
	}

	auto result = func(module);
	
	if(result != ERROR_SUCCESS)
	{
		data.error = IE_ERROR_CALLBACK;
		data.err_num = result;
		goto exit;
	}

exit:
#ifdef REMOTE_THREAD
	return 0;
#else
	data.NtSetEvent(data.event, NULL);
	while(true);
#endif
}

extern "C" static void code_cave_end()
{
}
#pragma strict_gs_check(pop)
#pragma code_seg(pop)

#define LOAD_ADDRESS_IMPL(var, module, name) do { \
		var = (decltype(var))GetProcAddress(module, #name); \
		if(var == NULL) \
			raise_last_error(_T("Unable to get the address of ") _T(#name)); \
	} while (0)

#define LOAD_ADDRESS(var, module, name) LOAD_ADDRESS_IMPL(var, module, name)

#define STORE_ADDRESS(data, module, name) LOAD_ADDRESS_IMPL(data.name, module, name)

void run_code_cave()
{
	Data data;

	External func(&code_cave, (size_t)&code_cave_end - (size_t)&code_cave);

	wchar_t exename[0x8000];

	auto exename_size = GetModuleFileNameW(NULL, exename, sizeof(exename) / sizeof(wchar_t));

	if(exename_size == 0)
			throw string(_T("Unable to get executable path"));

	auto dll_name = std::wstring(exename, exename_size);

	dll_name = dll_name.substr(0, dll_name.find_last_of(L".") + 1) + L"dll";

	const char *func_name = "after_injection";

	External dll_str(dll_name.c_str(), dll_name.length() * sizeof(wchar_t));
	External func_str(func_name, strlen(func_name) + 1);

	HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));

	if(ntdll == NULL)
		raise_last_error(_T("Unable to get the address of ntdll.dll"));
	
	LOAD_ADDRESS(RtlNtStatusToDosErrorFunc, ntdll, RtlNtStatusToDosError);
	LOAD_ADDRESS(RtlInitAnsiStringFunc, ntdll, RtlInitAnsiString);
	LOAD_ADDRESS(RtlInitUnicodeStringFunc, ntdll, RtlInitUnicodeString);

	data.error = IE_ERROR_NONE;

	RtlInitUnicodeStringFunc(&data.dll, dll_name.c_str());
	RtlInitAnsiStringFunc(&data.func, func_name);

	data.dll.Buffer = (PWSTR)dll_str.data;
	data.func.Buffer = (PCHAR)func_str.data;

	STORE_ADDRESS(data, ntdll, LdrLoadDll);
	STORE_ADDRESS(data, ntdll, LdrGetProcedureAddress);

#ifndef REMOTE_THREAD
	STORE_ADDRESS(data, ntdll, NtSetEvent);
	
	HANDLE event = CreateEvent(NULL, TRUE, FALSE, NULL);
	
	if(!event)
		raise_last_error(_T("Unable to create event"));
	
	HandleScope event_scope(event);

	if(!DuplicateHandle(GetCurrentProcess(), event, pi.hProcess, &data.event, 0, FALSE, DUPLICATE_SAME_ACCESS))
		raise_last_error(_T("Unable to duplicate event handle"));

	Finally close_remote_event([&] {
		DuplicateHandle(pi.hProcess, data.event, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
	});
#endif

	External info(&data, sizeof(Data));

#ifdef REMOTE_THREAD
	HANDLE thread = CreateRemoteThread(pi.hProcess, 0, 0, (LPTHREAD_START_ROUTINE)func.data, info.data, 0, 0);

	if(thread == NULL)
		raise_last_error(_T("Unable to create remote thread"));

	if(WaitForSingleObject(thread, INFINITE) == WAIT_FAILED)
		raise_last_error(_T("Unable to wait for remote thread"));
#else
	CONTEXT context;

	context.ContextFlags = CONTEXT_ALL;

	if(!GetThreadContext(pi.hThread, &context))
		raise_last_error(_T("Unable to get thread context"));
	
	CONTEXT new_context = context;
	
#ifdef _M_AMD64
	new_context.Rip = (size_t)func.data;
	new_context.Rcx = (size_t)info.data;

	new_context.Rsp -= 128; // Skip the redzone
	new_context.Rsp = new_context.Rsp & ~15; // Align to 16 byte boundary
#else
	new_context.Eip = (size_t)func.data;
	new_context.Ecx = (size_t)info.data;
#endif

	if(!SetThreadContext(pi.hThread, &new_context))
		raise_last_error(_T("Unable to set thread context"));
	
	if(ResumeThread(pi.hThread) == (DWORD)-1)
		raise_last_error(_T("Unable to start code cave"));

	if(WaitForSingleObject(event, INFINITE) == WAIT_FAILED)
		raise_last_error(_T("Unable to wait for code cave"));
#endif

	info.read(&data, sizeof(Data));
	
	switch(data.error)
	{
		case IE_ERROR_NONE:
			break;

		case IE_ERROR_LOAD_LIBRARY:
			raise_error_num(_T("Unable to load the library"), RtlNtStatusToDosErrorFunc(data.err_num));

		case IE_ERROR_GET_PROC_ADDRESS:
			raise_error_num(_T("Unable to find the address of the initialization routine"), RtlNtStatusToDosErrorFunc(data.err_num));

		case IE_ERROR_CALLBACK:
		{
			stringstream msg;

			msg << _T("The initialization routine failed to execute") << _T("\nError #") << data.err_num;

			throw msg.str();
		}
	}
	
#ifndef REMOTE_THREAD
	if(!SetThreadContext(pi.hThread, &context))
		raise_last_error(_T("Unable to restore thread context"));
#endif
}

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	try
	{
		LPWSTR *argv;
		int argc;
		STARTUPINFOW si;

		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);

		argv = CommandLineToArgvW(GetCommandLineW(), &argc);

		if(argc < 2)
			throw string(_T("No executable was specified"));

		if(CreateProcessW(argv[1], 0, 0, 0, false, CREATE_SUSPENDED, 0, 0, &si, &pi) == 0)
			raise_last_error(_T("Unable to create process"));
		
		HandleScope process_scope(pi.hProcess);
		HandleScope thread_scope(pi.hThread);

		{
			Finally process_exit([&] {
				TerminateProcess(pi.hProcess, 1);
			});
		
			run_code_cave();
			
			if(ResumeThread(pi.hThread) == (DWORD)-1)
				raise_last_error(_T("Unable to start the main thread"));

			process_exit.execute = false;
		}

		return 0;
	} catch(string error)
	{
		MessageBox(NULL, error.c_str(), _T("Injector"), MB_OK | MB_ICONERROR);
		return 1;
	}
}
