#include <Windows.h>
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
	suspended_ = { 0,0 };
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
		_tprintf(_T("DUUUUUUUUUUUPA error:0x%x\r\n"),GetLastError());
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
							break;
					}
				break;
		}

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
		if (suspended_.count > 0) {
			HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, suspended_.tid);
			if (th != NULL) {
				ResumeThread(th);
			}
		}
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

BOOL Invader::Invader2::open(DWORD pid) noexcept {
	proc_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	return (proc_ != NULL) ? TRUE : FALSE;
}

Invader::Invader2::Invader2(DWORD pid) noexcept : creation_flag_(0), pid_(pid), tid_(0), thread_(NULL),
                            memory_(nullptr), LdrLoadDll_offset(0), Remote_LdrLoadDll_addr(nullptr), Remote_ntdll_base_addr(nullptr) {
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

Invader::Invader2::Invader2(const string_t& app_path, DWORD flag) noexcept : proc_(NULL), creation_flag_(flag),
                            memory_(nullptr), LdrLoadDll_offset(0), Remote_LdrLoadDll_addr(nullptr), Remote_ntdll_base_addr(nullptr) {

	create(app_path, flag);

}

bool 
Invader::Invader2::intern_alloc(size_t size) noexcept(false) {
	if (memory_ != nullptr) {
		delete[] memory_;
	}

	memory_ = new unsigned char[size];
	if (memory_ == nullptr) {
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

	//if (DbgBreakPoint_proc != proc_addr) { //"DbgBreakPointWithStatus"  //trzeba zmieniæ z bezwzglêdnego na przesuniêcie 
		//DbgBreakPoint_proc = reinterpret_cast<char*>(const_cast<void*>(proc_addr));    //little bit lame -> NtQueryProcessInformation
	//}

	INT64 DbgBreakPoint_offset = DbgBreakPoint_proc - reinterpret_cast<char*>(ntdll);
	Remote_ntdll_base_addr = reinterpret_cast<void*>(reinterpret_cast<INT64>(proc_addr) - DbgBreakPoint_offset);
	Remote_LdrLoadDll_addr = reinterpret_cast<void*>(reinterpret_cast<INT64>(Remote_ntdll_base_addr) + intern_LdrLoadDll_offset());

	return true;

}

int Invader::Invader2::read_memory(HANDLE proc, LPCVOID addr, SIZE_T size) noexcept {
	if (!intern_alloc(size)) {
		return -1;
	}

	SIZE_T num_bytes;
	if (ReadProcessMemory(proc, addr, memory_, size, &num_bytes) == FALSE) {
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
Invader::prepare_stub(const WCHAR* dll_path, VOID* LdrLoadDll_addr, unsigned char* stub, size_t stub_size) noexcept {

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

	return 1;

}

bool 
Invader::Invader2::do_i_have_privilege() noexcept {

	//
	return false;

}