#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <thread>
#include <mutex>
#include <tchar.h>
#include <cstdio>

import Env;
import Invader;

void Invader::Debugger::intern_init(DWORD pid) noexcept {
	pid_ = pid;
	//prot_ = std::mutex();
	active_ = FALSE;
	dbg_loop_break_ = false;
	//dbg_loop_thread_ = std::thread();
	except_ = { 0 };
	wait_4_event_ = CreateEventEx(NULL, NULL, CREATE_EVENT_MANUAL_RESET, SYNCHRONIZE | DELETE | EVENT_MODIFY_STATE);
	mod_ready_ = CreateEventEx(NULL, NULL, CREATE_EVENT_MANUAL_RESET, SYNCHRONIZE | DELETE | EVENT_MODIFY_STATE);
}

Invader::Debugger::Debugger(DWORD pid) noexcept : prot_(), dbg_loop_thread_() {

	intern_init(pid);

}

BOOL 
Invader::Debugger::intern_attach(DWORD pid) noexcept {
	std::lock_guard<std::mutex> guard(prot_);
	return active_ = DebugActiveProcess(pid);
}

bool 
Invader::Debugger::intern_break() noexcept {
	std::lock_guard<std::mutex> guard(prot_);
	if (dbg_loop_break_ == true) {
		return true;
	}
	return false;
}

void 
Invader::Debugger::intern_loop(BOOL kill) noexcept {

	if (intern_attach(pid_) == FALSE) {
		return;
	}

	DebugSetProcessKillOnExit(kill);

	DEBUG_EVENT event = { 0 };
	DWORD status = DBG_CONTINUE;

	while (true) {

		if (intern_break()) {
			DebugActiveProcessStop(pid_);
			break;
		}

		WaitForDebugEvent(&event, INFINITE);
		
		switch (event.dwDebugEventCode) {
				case EXCEPTION_DEBUG_EVENT:
					switch (event.u.Exception.ExceptionRecord.ExceptionCode) {
					        case EXCEPTION_BREAKPOINT:
								
								prot_.lock();
								except_._exception_code = event.u.Exception.ExceptionRecord.ExceptionCode;
								except_.pid = event.dwProcessId;
								except_.tid = event.dwThreadId;
								except_.addr = event.u.Exception.ExceptionRecord.ExceptionAddress;
								prot_.unlock();

								SetEvent(wait_4_event_);
								WaitForSingleObject(mod_ready_, INFINITE);
								ResetEvent(mod_ready_);

							break;
							case EXCEPTION_ACCESS_VIOLATION:

								prot_.lock();
								except_._exception_code = event.u.Exception.ExceptionRecord.ExceptionCode;
								except_.pid = event.dwProcessId;
								except_.tid = event.dwThreadId;
								except_.addr = event.u.Exception.ExceptionRecord.ExceptionAddress;
								prot_.unlock();

								SetEvent(wait_4_event_);

							break;
							case CREATE_THREAD_DEBUG_EVENT:
							break;
							case LOAD_DLL_DEBUG_EVENT:
							break;
					}
				break;
		}

		//SetEvent(wait_4_event_);
		ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status);   

	}

}

void 
Invader::Debugger::debug(BOOL kill) noexcept {
	dbg_loop_thread_ = std::move(std::thread(&Debugger::intern_loop, this, kill));
}

BOOL Invader::Debugger::active() noexcept {
	 Sleep(2000);
	 std::lock_guard<std::mutex> guard(prot_);
	 return active_;
}

BOOL Invader::Debugger::stop() noexcept {
	if (active_ == TRUE) {
		prot_.lock();
		dbg_loop_break_ = true;
		prot_.unlock();
		dbg_loop_thread_.join();
		active_ = FALSE;
	}
	return TRUE;
}

bool
Invader::Debugger::wait(DWORD time) const noexcept {
	unsigned char MAX_ERROR = 4;
	for (unsigned char i = 0; i < MAX_ERROR; i++) {
		DWORD res = WaitForSingleObject(wait_4_event_, time);
		if (res == WAIT_OBJECT_0) {
			ResetEvent(wait_4_event_);
			return true;
		}
	}
	return false;
}

Invader::Dbg_exception_info
Invader::Debugger::except_info() const noexcept {
	std::lock_guard<std::mutex> guard(prot_);
	return except_;
}

/// 
/// 
/// 

BOOL Invader::Invader2::open(DWORD pid) noexcept  {
	proc_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	pid_ = pid;
	return (proc_ != NULL) ? TRUE : FALSE;
}

Invader::Invader2::Invader2(DWORD pid,  bool is_x64) noexcept : x64(is_x64), creation_flag_(0), pid_(pid), tid_(0), thread_(NULL),
                            stub_(nullptr), trampoline_(nullptr), LdrLoadDll_offset(0), Remote_LdrLoadDll_addr(nullptr), Remote_ntdll_base_addr(nullptr) {
	open(pid);
}

BOOL Invader::Invader2::create(const string_t& app_path, DWORD flag) noexcept {

	creation_flag_ = flag;

	STARTUPINFO start_info = { 0 };
	PROCESS_INFORMATION proc_info = { 0 };
	start_info.dwFlags = STARTF_USESHOWWINDOW;
	start_info.wShowWindow = SW_HIDE;

	if (CreateProcess(app_path.c_str(), NULL, NULL, NULL, FALSE, flag, NULL, NULL, &start_info, &proc_info)) {
		proc_ = proc_info.hProcess;
		pid_ = proc_info.dwProcessId;
		thread_ = proc_info.hThread;
		tid_ = proc_info.dwThreadId;
		return TRUE;
	}

	return FALSE;

}

Invader::Invader2::Invader2(const string_t& app_path, DWORD flag, bool is_x64) noexcept : x64(is_x64), proc_(NULL), creation_flag_(flag),
                            stub_(nullptr), trampoline_(nullptr), LdrLoadDll_offset(0), Remote_LdrLoadDll_addr(nullptr), Remote_ntdll_base_addr(nullptr) {

	create(app_path, flag);

}

bool 
Invader::Invader2::intern_alloc_trampoline(size_t size) noexcept(false) {
	if (trampoline_ != nullptr) {
		delete[] trampoline_;
	}

	trampoline_ = new unsigned char[size];
	if (trampoline_ == nullptr) {
		return false;
	}

	return true;
}

bool 
Invader::Invader2::intern_alloc_stub(size_t size) noexcept(false) {
	if (stub_ != nullptr) {
		delete[] stub_;
	}

	stub_ = new unsigned char[size];
	if (stub_ == nullptr) {
		return false;
	}

	return true;
}

unsigned long long 
Invader::Invader2::intern_LdrLoadDll_offset() noexcept {

	HMODULE ntdll = LoadLibrary(_T("ntdll.dll"));
	if (ntdll == nullptr) {
		return 0;
	}

	char* LdrLoadDll_p = reinterpret_cast<char*>(GetProcAddress(ntdll, "LdrLoadDll"));
	LdrLoadDll_offset = LdrLoadDll_p - reinterpret_cast<char*>(ntdll);
	return LdrLoadDll_offset;

}

bool Invader::Invader2::remote_addresses(const void* proc_addr) noexcept {

	HMODULE ntdll = LoadLibrary(_T("ntdll.dll"));
	if (ntdll == nullptr) {
		return false;
	}

	char* DbgBreakPoint_proc = reinterpret_cast<char*>(GetProcAddress(ntdll, "DbgBreakPoint"));
	if (DbgBreakPoint_proc == nullptr) {
		return false;
	}

	INT64 DbgBreakPoint_offset = DbgBreakPoint_proc - reinterpret_cast<char*>(ntdll);
	Remote_ntdll_base_addr = reinterpret_cast<void*>(reinterpret_cast<INT64>(proc_addr) - DbgBreakPoint_offset);
	Remote_LdrLoadDll_addr = reinterpret_cast<void*>(reinterpret_cast<INT64>(Remote_ntdll_base_addr) + intern_LdrLoadDll_offset());

	return true;

}

int Invader::Invader2::read_memory_tarmpoline(HANDLE proc, LPCVOID addr, SIZE_T size) noexcept {
	if (!intern_alloc_trampoline(size)) {
		return -1;
	}

	SIZE_T num_bytes;
	if (ReadProcessMemory(proc, addr, trampoline_, size, &num_bytes) == FALSE) {
		return 0;
	}

	if (num_bytes > INT_MAX) {
		return -1;
	}

	return static_cast<int>(num_bytes);
}

int Invader::Invader2::read_memory_stub(HANDLE proc, LPCVOID addr, SIZE_T size) noexcept {
	if (!intern_alloc_stub(size)) {
		return -1;
	}

	SIZE_T num_bytes;
	if (ReadProcessMemory(proc, addr, stub_, size, &num_bytes) == FALSE) {
		return 0;
	}

	if (num_bytes > INT_MAX) {
		return -1;
	}

	return static_cast<int>(num_bytes);
}

SIZE_T Invader::Invader2::write_memory(HANDLE proc, LPVOID addr, const unsigned char* data, size_t data_size) noexcept {
	SIZE_T num_bytes;
	if (WriteProcessMemory(proc, addr, data, data_size, &num_bytes) == FALSE) {
		return 0;
	}
	return num_bytes;
}

///
///
///

int
Invader::prepare_stub(const WCHAR* dll_path, VOID* LdrLoadDll_addr, unsigned char* stub, size_t stub_size,void* DbgBreakPoint, bool trampoline) noexcept {
	
	size_t len = wcslen(dll_path);
	if ((len + 1) * sizeof(WCHAR) >= 160) {//0x7ffe) {
		return -1;
	}

	USHORT path_len = static_cast<USHORT>(len * sizeof(WCHAR));
	USHORT max_path_len = static_cast<USHORT>((len + 1) * sizeof(WCHAR));

	USHORT* in_stub_len_ptr = reinterpret_cast<USHORT*>(memchr(stub, 0x1111, stub_size));
	if (in_stub_len_ptr == nullptr) {
		return 0;
	}
	*in_stub_len_ptr = path_len;

	in_stub_len_ptr = reinterpret_cast<USHORT*>(memchr(stub, 0x2222, stub_size));
	if (in_stub_len_ptr == nullptr) {
		return 0;
	}
	*in_stub_len_ptr = max_path_len;
	INT64 LdrLoadDll_addr_le = _byteswap_uint64(reinterpret_cast<INT64>(LdrLoadDll_addr));

	//*(in_stub_len_ptr + 1) = path_len;
	//*(in_stub_len_ptr + 2) = max_path_len;

	INT64* in_stub_proc_addr_ptr = reinterpret_cast<INT64*>(memchr(stub, 0x77777777, stub_size));
	if (in_stub_proc_addr_ptr == nullptr) {
		return 0;
	}

	*in_stub_proc_addr_ptr = reinterpret_cast<INT64>(const_cast<void*>(LdrLoadDll_addr));

	char* in_stub_path_ptr = (char*)memchr(stub, 0x66666666, stub_size);
	if (in_stub_path_ptr == nullptr) {
		return 0;
	}

	in_stub_path_ptr += sizeof(void*);

	memcpy(reinterpret_cast<void*>(in_stub_path_ptr), dll_path, len * sizeof(WCHAR));
	unsigned char* epilog = &stub[stub_size - 14];

	if (trampoline == false) {

		epilog[0] = 0xE9;
		epilog[1] = 0xE1;
		epilog[2] = 0xFE;
		epilog[3] = 0xFF;
		epilog[4] = 0xFF;

	}
	else {

		stub[0] = 0x90;

		epilog[0] = 0xCC;

		epilog[1] = 0x90;
		epilog[2] = 0x48;   
		epilog[3] = 0xB8;

		INT64* jmp_ptr =  reinterpret_cast<INT64*>(&epilog[4]);   //dzia³a nie trza psuæ
		*jmp_ptr = reinterpret_cast<INT64>(DbgBreakPoint); 
		epilog[12] = 0xFF;
	    epilog[13] = 0xE0;
		epilog[14] = 0x90;


	}

	return 1;

}

Invader::Invader2::~Invader2() {
	if (stub_ != nullptr) {
		delete[] stub_;
	}

	if (trampoline_ != nullptr) {
		delete[] trampoline_;
	}

	if (thread_ != NULL) {
		CloseHandle(thread_);
	}
	if (proc_ != NULL) {
		CloseHandle(proc_);
	}
}

Invader::Debugger::~Debugger() {
	if (mod_ready_ != NULL) {
		CloseHandle(mod_ready_);
	}
	if (wait_4_event_ != NULL) {
		CloseHandle(wait_4_event_);
	}
}

unsigned long long
Invader::Invader2::remote_base_addr_main_module() noexcept {  

	ULONG ret_len;
	PROCESS_BASIC_INFORMATION proc_inf = { 0 };
	if (!NT_SUCCESS(NtQueryInformationProcess(proc_, ProcessBasicInformation, &proc_inf, sizeof(PROCESS_BASIC_INFORMATION), &ret_len))) {
		return 0;
	}
	const unsigned char* peb = reinterpret_cast<const unsigned char*>(proc_inf.PebBaseAddress) + 0x10;
	const void* image_base = nullptr;
	if (!ReadProcessMemory(proc_, peb, &image_base, sizeof(const void*), NULL)) {
		return 0;
	}
	return reinterpret_cast<unsigned long long>(image_base);

}

unsigned long long
Invader::Invader2::remote_entry_point() noexcept {

	unsigned long long image_base = remote_base_addr_main_module();
	if (image_base == 0) {
		return 0;
	}

	constexpr size_t head_size = sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_DOS_HEADER);
	unsigned char head[head_size] = { 0 };
	if (!ReadProcessMemory(proc_, reinterpret_cast<LPCVOID>(image_base), head, head_size, NULL)) {
		return 0;
	}

	IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(head);
	IMAGE_OPTIONAL_HEADER64* opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(head + dos->e_lfanew + sizeof(IMAGE_FILE_HEADER) +sizeof(DWORD));

	unsigned long long entry_point = image_base + opt->AddressOfEntryPoint;

	return entry_point;

}