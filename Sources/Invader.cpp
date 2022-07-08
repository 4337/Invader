/////////////////////
/// Invader (x64 PoC)
/// 06/07/2022 07:03
/// Author: echo
/////////////////////

#include <Windows.h>
#include <psapi.h>
#include <thread>
#include <mutex>
#include <tchar.h>
#include <cstdio>

#include "Environment.h"

import Invader;

bool 
Invader::Process::set_app_path() noexcept {

	TCHAR buff[MAX_PATH + 1];
	if (GetModuleFileNameEx(proc_hnd_, NULL, &buff[0], MAX_PATH)) {
		app_path_ = buff;
		return true;
	}
	return false;

}

bool 
Invader::Process::set_mitigation_info() noexcept {

	if (!GetProcessMitigationPolicy(proc_hnd_, ProcessDynamicCodePolicy, &mitigations_.acg, sizeof(mitigations_.acg))) {
		return false;
	}
	if (!GetProcessMitigationPolicy(proc_hnd_, ProcessSignaturePolicy, &mitigations_.cig, sizeof(mitigations_.cig))) {
		return false;
	}
	mitigations_.init = true;

	return true;
}

Invader::Process::Process(HANDLE proc, BOOL inherit) noexcept : thread_hnd_(NULL), proc_hnd_(proc), inherit_handle_(inherit) {


	if (proc_hnd_ != NULL) {
		set_app_path();
		set_mitigation_info();
		pid_ = GetProcessId(proc_hnd_);
		tid_ = GetCurrentThreadId();
		thread_hnd_ = OpenThread(THREAD_ALL_ACCESS, inherit, tid_);
		ProcessIdToSessionId(pid_, &session_id_);
	} else {
		app_path_ = TEXT("");
		pid_ = tid_ = session_id_ = -1;
		mitigations_ = { false, {0}, {0} };
	}

}

int
Invader::Process::create(const string_t& path, DWORD flags) noexcept {

	STARTUPINFO start_info = { 0 };
	PROCESS_INFORMATION proc_info = { 0 };
	start_info.dwFlags = STARTF_USESHOWWINDOW;
	start_info.wShowWindow = SW_HIDE;
	if (CreateProcess(path.c_str(), NULL, NULL, NULL, inherit_handle_, flags, NULL, NULL, &start_info, &proc_info)) {
		proc_hnd_ = proc_info.hProcess;
		thread_hnd_ = proc_info.hThread;
		pid_ = proc_info.dwProcessId;
		tid_ = proc_info.dwThreadId;
		if (!set_app_path()) {
			return -1;
		}
		return 1;
	}
	return 0;

}

bool
Invader::Process::open(DWORD ipid, DWORD access, BOOL inherit) noexcept(false) {

	if (proc_hnd_ != NULL && pid_ == ipid) {
		return true;
	}

	proc_hnd_ = OpenProcess(access, inherit, ipid);
	if (proc_hnd_ == NULL) {
		return false;
	}

	pid_ = ipid;
	inherit_handle_ = inherit;

	if (!ProcessIdToSessionId(pid_, &session_id_)) {
		session_id_ = -1;
	}

	set_app_path();
	set_mitigation_info();

	return true;

}

Invader::Process::Process(const Process& copy) noexcept {

	*this = copy;

}

Invader::Process&
Invader::Process::operator=(const Process& copy) noexcept {  //todo: test

	if (this != &copy) {

		pid_ = copy.pid_;
		tid_ = copy.tid_;
		session_id_ = copy.session_id_;
		inherit_handle_ = copy.inherit_handle_;

		memcpy(&mitigations_, &copy.mitigations_, sizeof(mitigations_));

		app_path_ = copy.app_path_;

		if (copy.proc_hnd_ == NULL || copy.proc_hnd_ == INVALID_HANDLE_VALUE) {
			proc_hnd_ = copy.proc_hnd_;
			thread_hnd_ = copy.thread_hnd_;
		} else {
			HANDLE current_proc = GetCurrentProcess();
			DuplicateHandle(current_proc, copy.proc_hnd_,
				current_proc, &proc_hnd_, 0,
				inherit_handle_, DUPLICATE_SAME_ACCESS);
			thread_hnd_ = OpenThread(THREAD_ALL_ACCESS, copy.inherit_handle_, copy.tid_);

		}

	}

	return *this;

}

void 
Invader::Process::close(bool terminate) noexcept {
	
	if (terminate) {
		ResumeThread(thread_hnd_);
		TerminateProcess(proc_hnd_, 0);
	}

	if (proc_hnd_ != NULL && proc_hnd_ != INVALID_HANDLE_VALUE) {

		CloseHandle(proc_hnd_);
		proc_hnd_ = NULL;
		pid_ = -1;

	}

	if (thread_hnd_ != NULL && thread_hnd_ != INVALID_HANDLE_VALUE) {

		CloseHandle(thread_hnd_);
		thread_hnd_ = NULL;
		tid_ = -1;

	}

}

Invader::Process::Process(Process&& other) noexcept {

	*this = std::move(other);

}


Invader::Process&
Invader::Process::operator=(Process&& other) noexcept {

	if (this != &other) {

		proc_hnd_ = other.proc_hnd_;
		other.proc_hnd_ = NULL;

		thread_hnd_ = other.thread_hnd_;
		other.thread_hnd_ = NULL;

		inherit_handle_ = other.inherit_handle_;
		pid_ = other.pid_;
		tid_ = other.tid_;
		app_path_ = other.app_path_;
		session_id_ = other.session_id_;

		memcpy(&mitigations_, &other.mitigations_, sizeof(mitigations_));

	}

	return *this;

}

Invader::Process::~Process() {

	close();

}


Invader::Debugger::Debugger(DWORD pid) noexcept(false) : dbg_loop_thread_(), pid_(pid), dbg_loop_break_(false), prot_() {

	except_ = { 0 };
	wait_4_event_ = CreateEventEx(NULL, NULL, CREATE_EVENT_MANUAL_RESET, SYNCHRONIZE | DELETE | EVENT_MODIFY_STATE);
	mod_ready_    = CreateEventEx(NULL, NULL, CREATE_EVENT_MANUAL_RESET, SYNCHRONIZE | DELETE | EVENT_MODIFY_STATE);

	/// <summary>
    /// We must wait a while to system complete creation of a process othrewise debugg event will occur in DbgBreakPointWithStatus
    /// If we wait debug event will occur in DbgBreakPoint.
    /// </summary>
	Sleep(2000);

}

void
Invader::Debugger::debug(BOOL kill) noexcept {
	dbg_loop_thread_ = std::move(std::thread(&Debugger::_loop, this, kill));
}

BOOL Invader::Debugger::_attach(DWORD pid) noexcept {
	
	std::lock_guard<std::mutex> guard(prot_);
	active_ = DebugActiveProcess(pid);
	return active_;

}

bool 
Invader::Debugger::_break() noexcept {
	std::lock_guard<std::mutex> guard(prot_);
	if (dbg_loop_break_ == true) {
		return true;
	}
	return false;
}

Invader::Dbg_exception_info 
Invader::Debugger::except_info() const noexcept {
	std::lock_guard<std::mutex> guard(prot_);
	return except_;
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

void
Invader::Debugger::_loop(BOOL kill) noexcept {

	if (_attach(pid_) == FALSE) {
		return;
	}

	DebugSetProcessKillOnExit(kill);

	DEBUG_EVENT event = { 0 };
	DWORD status = DBG_CONTINUE;

	while (true) {

		  if (_break()) {
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
			  }
			  break;

		  }

		  ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status);

	}

}

BOOL 
Invader::Debugger::active() noexcept {

	Sleep(2000);
	std::lock_guard<std::mutex> guard(prot_);
	return active_;

}

BOOL 
Invader::Debugger::stop() noexcept {
	if (active_ == TRUE) {
		//SetEvent(ready_);
		prot_.lock();
		dbg_loop_break_ = true;
		prot_.unlock();
		dbg_loop_thread_.join();
		active_ = FALSE;
	}
	return TRUE;
}


bool 
Invader::Invader::_alloc(size_t size) noexcept(false) {

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
Invader::Invader::_LdrLoadDll_offset() noexcept {

	HMODULE ntdll = LoadLibrary(_T("ntdll.dll"));
	if (ntdll == nullptr) {
		return 0;
	}

	char* LdrLoadDll_p = reinterpret_cast<char*>(GetProcAddress(ntdll, "LdrLoadDll"));
	LdrLoadDll_offset = LdrLoadDll_p - reinterpret_cast<char*>(ntdll);
	return LdrLoadDll_offset;

}

bool 
Invader::Invader::remote_addresses(const void* proc_addr) noexcept {

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
	Remote_LdrLoadDll_addr = reinterpret_cast<void*>(reinterpret_cast<INT64>(Remote_ntdll_base_addr) + _LdrLoadDll_offset());

	return true;

}

int 
Invader::Invader::read_memory(HANDLE proc, LPCVOID addr, SIZE_T size) noexcept(false) {

	if (!_alloc(size)) {
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

SIZE_T 
Invader::Invader::write_memory(HANDLE proc, LPVOID addr, const unsigned char* data, size_t data_size) noexcept(false) {

	SIZE_T num_bytes;
	if (WriteProcessMemory(proc, addr, data, data_size, &num_bytes) == FALSE) {
		return 0;
	}
	return num_bytes;

}

int 
Invader::prepare_stub(const WCHAR* dll_path, VOID* LdrLoadDll_addr, unsigned char* stub, size_t stub_size) noexcept {

	size_t len = wcslen(dll_path);
	if ((len + 1) * sizeof(WCHAR) >= 88) {//0x7ffe) {
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