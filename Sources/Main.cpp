//TODO: psujemy wewnętrzne metody obsługi sterty, musimy zaimplementować -trampoline

#include <Windows.h>
#include <tchar.h>
#include <string>
#include <filesystem>
#include <fstream>
#include <memory>

import Env;
import Invader;

namespace Invader {

	WCHAR* A2U(const CHAR* a_str) noexcept(false);

	WCHAR* A2U(const CHAR* a_str) noexcept(false) {

		int need_size = MultiByteToWideChar(CP_ACP, 0, a_str, -1, nullptr, 0);
		if (need_size <= 0) {
			return nullptr;
		}

		WCHAR* wide_str = new WCHAR[(need_size + 1)];
		if (wide_str == nullptr) {
			return wide_str;
		}

		ZeroMemory(wide_str, (need_size + 1) * sizeof(WCHAR));

		int res = MultiByteToWideChar(CP_ACP, 0, a_str, -1, wide_str, need_size);
		if (res == 0) {
			delete[] wide_str;
			return nullptr;
		}

		return wide_str;

	}

	void banner() noexcept;

	void banner() noexcept {
		_tprintf(_T(
                 "Invader x64 (poc)\r\n"
			     "----------------------------------------------------------------------\r\n"
			     "*use:\r\n"
			     "-app path - path to target application, can't be used with -pid option\r\n"
			     "-dll path - path to dll to inject\r\n"
			     "-pid PID  - target process ID, can't be used with -app option\r\n"
			     "-dontdie  - do not let the attacked process die\r\n"
			     "-freeze   - freeze thread that caused accesss violation\r\n"
			     "-trampoline - write stub at _IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint and replace ntdll!DbgBreakPoint by jmp/call instruction\r\n"
			     "-cave - put stub in the ntdll.dll code cave\r\n"
			     "----------------------------------------------------------------------\r\n"
		         ));
	}

	enum : int {
		NOT_A_x64_FILE = -1,
		NO_A_ERROR,
		DLL_FILE_NOT_EXISTS,
		NOT_ENOUGH_ARGS,
		SIMULTANEOUSLY_OPT,
		CONVERSION_ERROR,
		DLL_PATH_2_LONG,
	    OPT_UNIMPLEMENTED
	};

	class Options {

		bool dontdie_;
		bool freeze_;
		bool trampoline_;
		bool cave_;
		int error_;
		DWORD pid_;
		Invader::string_t app_;
		std::wstring dll_;

	public:
		Options() noexcept : error_(NO_A_ERROR), pid_(-1), app_(_T("")), dll_(L""), dontdie_(false), freeze_(false), trampoline_(false) {
		}

		inline const bool cave() const noexcept {
			return cave_;
		}

		inline void
		set_cave() noexcept {
			cave_ = true;
		}


		inline const bool freeze() const noexcept {
			return freeze_;
		}

		inline void set_freeze() noexcept {
			freeze_ = true;
		}

		const bool trampoline() const noexcept {
			return trampoline_;
		}

		inline void 
		set_trampoline() noexcept {
			trampoline_ = true;
		}

		inline void
		error(int code) noexcept {
			error_ = code;
		}

		inline const
		int error() const noexcept {
			return error_;
		}

		inline void
		pid(DWORD pid) noexcept {
			pid_ = pid;
		}

		inline const
		DWORD pid() const noexcept {
			return pid_;
		}

		inline const
		Invader::string_t app() const noexcept {
			return app_;
		}

		inline void 
		app(Invader::string_t app_path) noexcept {
			app_ = app_path;
		}

		inline void
		dll(std::wstring path) noexcept {
			dll_ = path;
		}

		inline const
		std::wstring dll() const noexcept {
			return dll_;
		}

		inline const bool dontdie() const noexcept {
			return dontdie_;
		}

		inline void set_dontdie() noexcept {
			dontdie_ = true;
		}

	};

	int is_x64_bin(const Invader::string_t& file_path) noexcept;

	int is_x64_bin(const Invader::string_t& file_path) noexcept { //cos jest zjebane

		std::ifstream file(file_path, std::ios_base::binary);
		if (!file.is_open()) {
			return -1;
		}
		unsigned char head[sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_DOS_HEADER)];
		file.read(reinterpret_cast<char*>(head), sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_DOS_HEADER));
		if (!file) {
			return -1;
		}

		IMAGE_DOS_HEADER* dos_head = reinterpret_cast<IMAGE_DOS_HEADER*>(head);
		IMAGE_NT_HEADERS64* nt_head = reinterpret_cast<IMAGE_NT_HEADERS64*>(head + dos_head->e_lfanew);
		if (nt_head->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 && nt_head->FileHeader.Machine != IMAGE_FILE_MACHINE_IA64) {
			return 0;
		}
		return 1;

	}

	Invader::Options parse_command_line(int argc_, const TCHAR** argv_);

	Invader::Options parse_command_line(int argc_, const TCHAR** argv_) {

		Invader::Options opt;

		if (argc_ < 5) {
			opt.error(NOT_ENOUGH_ARGS);
			return opt;
		}

		namespace fs = std::filesystem;

		for (int i = 1; i < argc_; i++) {

			if (_tcscmp(argv_[i], _T("-cave")) == 0) {
				_tprintf(_T("[!]. Option -cave is not impleneted yet :(."));
				opt.error(OPT_UNIMPLEMENTED);
				//opt.set_cave();
				break;
			}

			if (_tcscmp(argv_[i], _T("-trampoline")) == 0) {
				opt.set_trampoline();
			}

			if (_tcscmp(argv_[i], _T("-freeze")) == 0) {
				opt.set_freeze();
			}

			if (_tcscmp(argv_[i], _T("-dontdie")) == 0) { //-dontdie
				opt.set_dontdie();
			}

			if (_tcscmp(argv_[i], _T("-dll")) == 0) {  //-dll
				if (i + 1 >= argc_) {
					opt.error(NOT_ENOUGH_ARGS);
					break;
				}

				if (!fs::exists(argv_[++i])) {
					opt.error(DLL_FILE_NOT_EXISTS);
					break;
				}

				if (_tcslen(argv_[i]) * 2 >= 160) {
					opt.error(DLL_PATH_2_LONG);
					break;
				}

#ifndef UNICODE 
				std::unique_ptr<WCHAR[]> w_tmp(A2U(argv_[i]));
				if (!w_tmp) {
					opt.error(CONVERSION_ERROR);
					break;
				}
				const WCHAR* dllpath_w = w_tmp.get();
#else 
				const WCHAR* dllpath_w = argv_[i];
#endif

				opt.dll(dllpath_w);

				if (is_x64_bin(argv_[i]) != 1) {
					opt.error(Invader::NOT_A_x64_FILE);
					break;
				}
			}

			if (_tcscmp(argv_[i], _T("-pid")) == 0) { //-pid
				if (i + 1 >= argc_) {
					opt.error(NOT_ENOUGH_ARGS);
					break;
				}
				if (!opt.app().empty()) {            //app && pid || pid && app
					opt.error(SIMULTANEOUSLY_OPT);
					break;
				}
				opt.pid(std::stoul(argv_[++i],nullptr,0));
			}
			
			if (_tcscmp(argv_[i], _T("-app")) == 0) {//-app
				if (i + 1 >= argc_) {
					opt.error(NOT_ENOUGH_ARGS);
					break;
				}
				if (opt.pid() != -1) {            //app && pid || pid && app
					opt.error(SIMULTANEOUSLY_OPT);
					break;
				}
				opt.app(argv_[++i]);
			}

		}

		return opt;

	}

}

/// <summary>
/// -pid 
/// -app 
/// -dll
/// </summary>
int _tmain(int argc, const TCHAR** argv) {

	Invader::banner();

	Invader::Options opt = Invader::parse_command_line(argc, argv);
	int cmd_error = opt.error();
	if (cmd_error != Invader::NO_A_ERROR) {
		switch (cmd_error) {
		        case Invader::NOT_ENOUGH_ARGS:
					_tprintf(_T("[!]. Not enough args (%d)\r\n"),argc);
				break;
				case Invader::NOT_A_x64_FILE:
					wprintf(L"[!]. Dll file: %s is not x64\r\n",opt.dll().c_str());
				break;
				case Invader::DLL_FILE_NOT_EXISTS:
					_tprintf(_T("[!]. Dll file does not exist\r\n"));
				break;
		}

		return -1;
	}

	wprintf(
		     L"[+]. Dll: %s\r\n"
			 , opt.dll().c_str()
	);

	if (opt.dontdie() == true) {
		_tprintf(
_T("[+]. Target application wont die.\r\n")
);
	}

	Invader::Debugger dbg;
	Invader::Invader2 inv;

	if (!opt.app().empty()) {     //-app
		_tprintf(
			_T(
				"[+]. Application: %s\r\n"
			), opt.app().c_str()
		);
		inv.create(opt.app(), CREATE_SUSPENDED);
		if (inv.process() == NULL) {
			_tprintf(_T("[+]. Create process fail with error: 0x%x\r\n"), GetLastError());
			return -1;
		}
		_tprintf(_T("[+]. Process %s created with PID: %d\r\n"), opt.app().c_str(), inv.pid());

	}

	if (opt.pid() != -1) {  //-pid  TODO: FIX ACCESS_DENIED dbg.debug(TRUE); && test
		_tprintf(
			_T(
				"[+]. Process PID: %d\r\n"
			), opt.pid()
		);

		if (inv.open(opt.pid()) == FALSE) {
			_tprintf(_T("[-]. Open processs with pid:%d fail error: 0x%x.\r\n"), opt.pid(), GetLastError());
			return -1;
		}
		_tprintf(_T("[+]. Process with pid:%d opened.\r\n"), opt.pid());

	}

	dbg.attach(inv.pid());

	dbg.debug(TRUE);

	if (dbg.active() == FALSE) {
		_tprintf(_T("[+]. Unable to attach to the process. error:0x%x\r\n"), GetLastError());
		return -1;
	}

	if (inv.creation_flag() & CREATE_SUSPENDED) {
		_tprintf(_T("[+]. Resume main thread - process was created with CREATE_SUSPENDED value\r\n"));
		inv.resume_main_thread();
	}

	bool loop = true;
	void* addr = nullptr;
	unsigned char bp = 0;
	unsigned char max_bp = 2;
	Invader::Dbg_exception_info exc = { 0 };
	const void* remote_LdrLoadDll_addr = nullptr;

	bool use_trampoline = opt.trampoline();

	if (opt.dontdie()) {
		_tprintf(_T("[+]. Option -dontdie is set, attacked process will not die! (not on my watch :D)\r\n"));
		inv.suspend_main_thread();
	}

	while (bp <= max_bp) {

		dbg.wait();

		exc = dbg.except_info();
		
		if (exc._exception_code == EXCEPTION_ACCESS_VIOLATION) {
			_tprintf(_T("[+]. Someting goes wrong, Access Violation at address: 0x%p exc.code:0x%x tid:%d\r\n"),
				     exc.addr, exc._exception_code, exc.tid);
			if (opt.freeze() == true) {
				_tprintf(_T("[+]. I'll try to freeze corrupted thread.\r\n"));
				HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, exc.tid);
				if (th == NULL) {
					_tprintf(_T("[+]. Unfortunately in can't open thread.\r\n"));
					break;
				}
				SuspendThread(th);
				_tprintf(_T("[+]. Thread with id:%d is now frozen.\r\n"), exc.tid);
				DebugBreakProcess(inv.process());
				continue;
			} 
			dbg.ready();
			break;
		}

		switch (bp) {
		case 0:
			_tprintf(_T(
				"[+]. Breakpoint has been reached.\r\n"
				"[-]. address: 0x%p\r\n"
				"[-]. bp counter: %d\r\n"
			), exc.addr, bp + 1);
			DebugBreakProcess(inv.process());
			break;

		case 1:
			addr = exc.addr;
			inv.remote_addresses(exc.addr);
			remote_LdrLoadDll_addr = inv.remote_LdrLoadDll_addr();

			_tprintf(_T("[+]. Correct breakpoint has been reached.\r\n"
				"[-]. address: 0x%p\r\n"
				"[-]. bp counter: %d\r\n"
				"[-]. pid: %d\r\n"
				"[-]. tid: %d\r\n"
				"[-]. base of ntdll.dll: 0x%p\r\n"
				"[-]. address of LdrLoadDll: 0x%p\r\n"
			), exc.addr, bp + 1, exc.pid, exc.tid, inv.remote_ntdll_base(), remote_LdrLoadDll_addr);

			if (Invader::prepare_stub(opt.dll().c_str(), const_cast<VOID*>(remote_LdrLoadDll_addr), &Invader::x64_stub[0],
				sizeof(Invader::x64_stub), addr, use_trampoline) != 1) {
				_tprintf(_T("[+]. Preparing stub fail.\r\n"));
				break;
			}

			/*
			[+]. Restore original code at: 0x00007FFEC00E7C40 (trampoline) exc.addr:0x00007FF7CF18E5FE
            [+]. Restore original code at: 0x00007FF7CF18E4E8 (entry point) exc.addr:0x00007FF7CF18E5FE <- źle, tak jakby powrót/skok powrotny do DbgBreakPoint nie został wykonany
			*/

			//Invader::stub_test(opt.dll().c_str(), const_cast<VOID*>(remote_LdrLoadDll_addr), &Invader::x64_stub[0], sizeof(Invader::x64_stub), addr);


			if (use_trampoline) {

				unsigned long long remote_entry_addr = inv.remote_entry_point();
				if (remote_entry_addr == 0) {
					_tprintf(_T("[+]. Gaining remote entry point address fail.\r\n"));
					break;
				}
				_tprintf(_T("[+]. remote entry point address: 0x%I64X\r\n"), remote_entry_addr);
				if (Invader::prepare_trampoline(reinterpret_cast<const void*>(remote_entry_addr), Invader::x64_trampoline,
					sizeof(Invader::x64_trampoline)) != 1) {
					_tprintf(_T("[+]. Preparing trampoline fail.\r\n"));
					break;
				}
				if (inv.read_memory_stub(inv.process(), reinterpret_cast<const void*>(remote_entry_addr),
					sizeof(Invader::x64_stub)) != sizeof(Invader::x64_stub)) {
					_tprintf(_T("[+]. Read process memory (entry_point) fail.\r\n"));
					break;
				}
				if (inv.read_memory_tarmpoline(inv.process(), exc.addr, sizeof(Invader::x64_trampoline)) != sizeof(Invader::x64_trampoline)) {
					_tprintf(_T("[+]. Read process memory (ntdll!DbgBreakPoint) fail.\r\n"));
					break;
				}
				DWORD old_protection;
				if (inv.protection(inv.process(), reinterpret_cast<void*>(remote_entry_addr), sizeof(Invader::x64_stub),
					PAGE_EXECUTE_READWRITE, &old_protection) == FALSE) {
					_tprintf(_T("[+]. Change memory protection fail error: 0x%x.\r\n"), GetLastError());
					break;
				}
				if (inv.protection(inv.process(), exc.addr, sizeof(Invader::x64_trampoline),
					PAGE_EXECUTE_READWRITE, &old_protection) == FALSE) {
					_tprintf(_T("[+]. Change memory protection fail error: 0x%x.\r\n"), GetLastError());
					break;
				}
				if (inv.write_memory(inv.process(), exc.addr, Invader::x64_trampoline,
					sizeof(Invader::x64_trampoline)) != sizeof(Invader::x64_trampoline)) {
					_tprintf(_T("[+]. Replacing code (trampoline) fail error: 0x%x.\r\n"), GetLastError());
					break;
				}
				if (inv.write_memory(inv.process(), reinterpret_cast<void*>(remote_entry_addr),
					Invader::x64_stub, sizeof(Invader::x64_stub)) != sizeof(Invader::x64_stub)) {
					_tprintf(_T("[+]. Replacing code (stub) fail error: 0x%x.\r\n"), GetLastError());
					break;
				}
				FlushInstructionCache(inv.process(), exc.addr, sizeof(Invader::x64_trampoline));
				FlushInstructionCache(inv.process(), reinterpret_cast<void*>(remote_entry_addr), sizeof(Invader::x64_stub));
			}
			else {
				if (inv.read_memory_stub(inv.process(), exc.addr, sizeof(Invader::x64_stub)) != sizeof(Invader::x64_stub)) {
					_tprintf(_T("[+]. Read process memory (ntdll!DbgBreakPoint) fail.\r\n"));
					break;
				}

				DWORD old_protection;
				if (inv.protection(inv.process(), exc.addr, sizeof(Invader::x64_stub), PAGE_EXECUTE_READWRITE, &old_protection) == FALSE) {
					_tprintf(_T("[+]. Change memory protection fail error: 0x%x.\r\n"), GetLastError());
					break;
				}
				if (inv.write_memory(inv.process(), exc.addr, Invader::x64_stub, sizeof(Invader::x64_stub)) != sizeof(Invader::x64_stub)) {
					_tprintf(_T("[+]. Replacing code fail error: 0x%x.\r\n"), GetLastError());
					break;
				}
				FlushInstructionCache(inv.process(), exc.addr, sizeof(Invader::x64_stub));
			}

			break;

		case 2:

			_tprintf(_T("[+]. Code should be injected.\r\n"
			            "[+]. bp counter: %d\r\n"), bp + 1);
			if (use_trampoline) {
				max_bp++;
				//restore trampoline at DbgBreakPoint
				_tprintf(_T("[+]. Restore original code at: 0x%p (trampoline) exc.addr:0x%p\r\n"), addr, exc.addr);
				/*
				unsigned char fake_tramp[sizeof(Invader::x64_trampoline)] = { 0x66 };
				inv.write_memory(inv.process(), addr, &fake_tramp[0], sizeof(Invader::x64_trampoline));
				*/
				
				if (inv.write_memory(inv.process(), addr, inv.trampoline(), 
					                 sizeof(Invader::x64_trampoline)) != sizeof(Invader::x64_trampoline)) {
				   _tprintf(_T("[!]. Restoring original code fail.\r\n"));
				   break;
				}
				FlushInstructionCache(inv.process(), addr, sizeof(Invader::x64_trampoline));
				
				//DebugBreakProcess(inv.process());
			}
			else {
			    //restore stub at DbgBreakPoint
				_tprintf(_T("[+]. Restore original code at: 0x%p (stub) exc.addr:0x%p\r\n"), addr, exc.addr);

				if (inv.write_memory(inv.process(), addr, inv.stub(), sizeof(Invader::x64_stub)) != sizeof(Invader::x64_stub)) {
					_tprintf(_T("[!]. Restoring original code fail.\r\n"));
					break;
				}
				FlushInstructionCache(inv.process(), addr, sizeof(Invader::x64_stub));
				bp++;            //do analizy byc moze do usuniecie

			}
			break;

		case 3:  //if trampoline && restore entry_point && continue
			_tprintf(_T("[+]. Restore original code at: 0x%p (entry point) exc.addr:0x%p\r\n"
			            "[+]. bp counter: %d\r\n"), inv.remote_entry_point(), exc.addr, bp + 1); // dbg.except_info().addr); //exc.addr);
			 
			 if (inv.write_memory(inv.process(), reinterpret_cast<void*>(inv.remote_entry_point()), 
				                  inv.stub(), sizeof(Invader::x64_stub)) != sizeof(Invader::x64_stub)) {
                 _tprintf(_T("[!]. Restoring original code fail.\r\n"));
       	         break;
             }
			 FlushInstructionCache(inv.process(), reinterpret_cast<void*>(inv.remote_entry_point()), sizeof(Invader::x64_stub));
			 
			 break;
		}

		if (exc._exception_code == 0x80000003) {
			bp++;
		}

		dbg.ready();
		

	}

	dbg.stop();

	if (exc._exception_code != EXCEPTION_ACCESS_VIOLATION || opt.freeze()) {
		_tprintf(_T("[+]. Code injection done with SUSCCESS.\r\n"
			        "[+]. Detaching process from debugger is done, process should be still alive.\r\n"
		));
	}
	//while (true);

	return 0;

}