// Invader.cpp : Ten plik zawiera funkcję „main”. W nim rozpoczyna się i kończy wykonywanie programu.
//

#include <Windows.h>
#include <cstdio>
#include <tchar.h>
#include <stdexcept>
#include <filesystem>
#include <fstream>

#include "Environment.h"

import Invader;

inline void banner(const string_t& msg = _T("")) noexcept {
	UNREFERENCED_PARAMETER(msg);
	_tprintf(_T(
		        "_________________________________\r\n"
		        "Invader x64 code/dll injection poc\r\n"
		        "[_tmain]. Invalid arguments, \r\n"
		        "use:\r\n"
		        "-dll path\\to\\dll\\file (x64)\r\n"
		        "-app path\\to\\target\\apliaction\r\n"
		        "-pid process id (not implemented)\r\n"
	));
}

bool is_x64_bin(const string_t& file_path) noexcept {
	
	bool ret = true;

	VOID* redirect_val;
	Wow64DisableWow64FsRedirection(&redirect_val);

	std::ifstream file(file_path, std::ios_base::binary);
	if (file.is_open()) {
		unsigned char head[sizeof(IMAGE_NT_HEADERS64)];
		file.read(reinterpret_cast<char*>(head), sizeof(IMAGE_NT_HEADERS64));
		if (!file) {
			ret = false;
		} else {
			IMAGE_DOS_HEADER* dos_head = reinterpret_cast<IMAGE_DOS_HEADER*>(head);
			IMAGE_NT_HEADERS64* nt_head = reinterpret_cast<IMAGE_NT_HEADERS64*>(head + dos_head->e_lfanew);
			if (nt_head->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 && nt_head->FileHeader.Machine != IMAGE_FILE_MACHINE_IA64) {
				ret = false;
			}
		}
	}

	Wow64RevertWow64FsRedirection(redirect_val);

	return ret;

}

bool is_x64_sys() noexcept {

	SYSTEM_INFO sys;
	GetSystemInfo(&sys);

	if (sys.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 && sys.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_IA64) {
		return false;
	}

	return true;

}


class Input_parameters {
	  
	  string_t path_;
	  string_t dll_path_;
	  string_t app_path_;
	  DWORD    pid_;

	  int argc_;
	  TCHAR** argv_;

public:

	Input_parameters(int argc, TCHAR** argv) noexcept : path_(argv[0]), dll_path_(_T("")), app_path_(_T("")) {

		argc_ = argc;
		argv_ = argv;

	}

	int parse() noexcept {

		namespace fs = std::filesystem;
		
		for (int i = 1; i < argc_; i++) {
			if (_tcscmp(argv_[i],_T("-dll")) == 0) {
			    if(i + 1 < argc_) {
					if (fs::exists(argv_[++i])) {
						if (!is_x64_bin(argv_[i])) { 
							_tprintf(_T("[Input_parameters::parse]. dll file is not x64, this is x64 poc !\r\n"));
							return 0;
						}
						dll_path_ = argv_[i];
					}
				}		
			}
			if (_tcscmp(argv_[i], _T("-app")) == 0) {
				if (i + 1 < argc_) {
					if (fs::exists(argv_[++i])) {

						if (!is_x64_bin(argv_[i]) && !is_x64_sys()) {
							_tprintf(_T("[Input_parameters::parse]. app and system is not x64 bit version, this is x64 poc !\r\n"));
							return 0;
						}
						app_path_ = argv_[i];
					}
				} 
			} 
			if (_tcscmp(argv_[i], _T("-app")) == 0) {
				if (!app_path_.empty()) {
					_tprintf(_T("[Input_parameters::parse]. You should not use -app and -pid simultaneously !\r\n"));
				}
				//...
			}

		}
		path_ = argv_[0];

		return 1;

	}

	inline string_t path() const noexcept {
		return path_;
	}

	inline string_t dll_path() const noexcept {
		return dll_path_;
	}

	inline string_t app_path() const noexcept {
		return app_path_;
	}

};

/// <summary>
/// -dll path/to/dll
/// -app (optional)path/to/target/apllication
/// </summary>
int _tmain(int argc, TCHAR** argv)
{
	if (argc < 5) {
		banner();
	} else {

		Input_parameters app_params(argc, argv);
		if (app_params.parse() != 1) {
			banner();
		} else {
			if (app_params.app_path().empty() || app_params.dll_path().empty()) { //wybierz apke z regul firewall-a
				banner(_T("Invalid parameters !\r\n"));
			}
			else {
				Invader::Invader inv;
				if (inv.x64() != 1) {
					_tprintf(_T("[Invader::Invader]. Process is not 64bit, this is x64 POC! \r\n"));
					return -1;
				}

				Invader::Process proc;

				int ret = proc.create(app_params.app_path().c_str(), 0);//CREATE_SUSPENDED); //0);
				if (ret != 1) {
					_tprintf(_T("[Invader::Process::create]. Process creation fail error:(0x%x) result:%d\r\n"), GetLastError(), ret);
					return -1;
				}

				//HANDLE suspend_thread = proc.main_thread_handler();

				_tprintf(_T("[_tmain::Invader::Process::create]. Process creation success.\r\n"
					"[Process::pid]: %d hex(0x%x)\r\n"
					"[Process::tid]: %d hex(0x%x)\r\n"
					"[Process::path]: %s\r\n"
					"[Dll::path]: %s\r\n"
					"[Process::CIG]: 0x%x\r\n"
					"[Process::ACG]: 0x%x\r\n"
					"[Invader::Debugger]: Create debugger session.\r\n"
				),
					proc.pid(),
					proc.pid(),
					proc.tid(),
					proc.tid(),
					proc.path().c_str(),
					app_params.dll_path().c_str(),
					proc.mitigations().cig.Flags,
					proc.mitigations().acg.Flags
				);

				Invader::Debugger dbg(proc.pid());

				dbg.debug(FALSE);

				if (dbg.active() == FALSE) {
					_tprintf(_T("[Invader::Debugger]: debug fail err:0x%x.\r\n"),GetLastError());
				} else {

					
					if (dbg.wait()) {

						_tprintf(_T("[Invader::Debugger]: application break.\r\n"));
						Invader::Dbg_exception_info exc = dbg.except_info();
						inv.remote_addresses(exc.addr);
						_tprintf(_T(
							"   RIP/EIP address: 0x%p\r\n"
							"   PID: %d\r\n"
							"   TID: %d\r\n"
							"   Exception code: 0x%x\r\n"
							"   Remote ntdll.dll base: 0x%p\r\n"
							"   Remote LdrLoadDll addr: 0x%p\r\n"
						), exc.addr, exc.pid, exc.tid, exc._exception_code,
							inv.remote_ntdll_base(), inv.remote_LdrLoadDll_addr()
						);

						if (inv.read_memory(proc.handler(), exc.addr, sizeof(Invader::x64_stub)) != sizeof(Invader::x64_stub)) {
							_tprintf(_T("[Invader::Invader]. read_memory fail!\r\n"));
						} else {

							const void* remote_LdrLoadDll_addr = inv.remote_LdrLoadDll_addr();

							_tprintf(_T("[Invader::Invader]. read_memory size(%zd) OK.\r\n"
								"[Invader::Invader]. change memory protection to RWX at remote address:0x%p\r\n"
							), sizeof(Invader::x64_stub), exc.addr);

							if (Invader::prepare_stub(app_params.dll_path().c_str(), const_cast<VOID*>(remote_LdrLoadDll_addr), &Invader::x64_stub[0], sizeof(Invader::x64_stub)) == 1) {

								void* exc_addr = exc.addr;
								_tprintf(_T("[Invader::Invader]. prepare stub code done.\r\n"));

								DWORD old_protection;
								inv.protection(proc.handler(), exc.addr, sizeof(Invader::x64_stub), PAGE_EXECUTE_READWRITE, &old_protection);

								inv.write_memory(proc.handler(), exc.addr, Invader::x64_stub, sizeof(Invader::x64_stub));
								FlushInstructionCache(proc.handler(), exc.addr, sizeof(Invader::x64_stub));

								_tprintf(_T("[Invader::Invader]. Code injection done.\r\n"));

								//ResumeThread(suspend_thread);
								dbg.ready();

								if (dbg.wait()) {
									_tprintf(_T("[Invader::Invader]. Injected code was executed in target process.\r\n"
										"[Invader::Invader]. Time to clean up.\r\n"));
									inv.write_memory(proc.handler(), exc_addr, inv.memory(), sizeof(Invader::x64_stub));
									FlushInstructionCache(proc.handler(), exc_addr, sizeof(Invader::x64_stub));
									//DebugBreakProcess(proc.handler());
									dbg.ready();
									//suspend one thread 
								}

								while (true);
							}

						}
					}

					dbg.stop();
				}
				proc.close();

				return 0;
			}
		}
	}

	return -1;

}

// Uruchomienie programu: Ctrl + F5 lub menu Debugowanie > Uruchom bez debugowania
// Debugowanie programu: F5 lub menu Debugowanie > Rozpocznij debugowanie

// Porady dotyczące rozpoczynania pracy:
//   1. Użyj okna Eksploratora rozwiązań, aby dodać pliki i zarządzać nimi
//   2. Użyj okna programu Team Explorer, aby nawiązać połączenie z kontrolą źródła
//   3. Użyj okna Dane wyjściowe, aby sprawdzić dane wyjściowe kompilacji i inne komunikaty
//   4. Użyj okna Lista błędów, aby zobaczyć błędy
//   5. Wybierz pozycję Projekt > Dodaj nowy element, aby utworzyć nowe pliki kodu, lub wybierz pozycję Projekt > Dodaj istniejący element, aby dodać istniejące pliku kodu do projektu
//   6. Aby w przyszłości ponownie otworzyć ten projekt, przejdź do pozycji Plik > Otwórz > Projekt i wybierz plik sln
