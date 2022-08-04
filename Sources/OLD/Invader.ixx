/////////////////////
/// Invader (x64 PoC)
/// 06/07/2022 07:03
/// Author: echo
/////////////////////
module;

#include <Windows.h>
#include <thread>
#include <mutex>

#include "Environment.h"

export module Invader;

namespace Invader {

	export {

		struct MitigationInfo {
			bool init;
			PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY cig;
			PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg;
			/*PP*/
			/*PPL*/
		};

		class Process {

			BOOL inherit_handle_;
			
			HANDLE proc_hnd_;

			HANDLE thread_hnd_;

			DWORD pid_;
			DWORD tid_;
			string_t app_path_;

			DWORD session_id_;

			/*
			ProcessArchitecture architecture_;
			*/

			MitigationInfo mitigations_;

			bool set_mitigation_info() noexcept;

			bool set_app_path() noexcept;

		public:


			Process(const Process& copy) noexcept;
			Process& operator=(const Process& copy) noexcept;

			Process(Process&& other) noexcept;
			Process& operator=(Process&& other) noexcept;

			explicit Process(HANDLE proc = NULL, BOOL inherit = FALSE) noexcept;

		    int create(const string_t& path, DWORD flags = CREATE_SUSPENDED) noexcept;
			
			bool open(DWORD ipid, DWORD access = PROCESS_QUERY_INFORMATION, BOOL inherit = FALSE) noexcept(false);
			
			void close(bool terminate = true) noexcept;

			inline MitigationInfo mitigations() const noexcept {
				return mitigations_;
			}

			/*
			int resume(DWORD tid) const noexcept;
			
			int suspend(DWORD tid) const noexcept;
			*/

			inline string_t path() const noexcept {
				return app_path_;
			}

			inline HANDLE handler() const noexcept {
				return proc_hnd_;
			}

			inline HANDLE main_thread_handler() const noexcept {
				return thread_hnd_;
			}

			inline DWORD sessionid() const noexcept {
				return session_id_;
			}

			inline DWORD tid() const noexcept {
				return tid_;
			}

			inline DWORD pid() const noexcept {
				return pid_;
			}

			~Process();

		};

		extern unsigned char x86_stub[] = {
			0x90, 0x90, 0x90, 0x90, 0xcc, 0x90, 0xcc
		};
		
		extern unsigned char x64_stub[] = { 

			0x90,0x90,0x90,0x90,
			0x9C,0x50,0x53,0x51,0x52,0x55,0x54,0x56,
			0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,
			0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,
			0x57,0xE8,0xB4,0x00,0x00,0x00,
			0x11,0x11,0x22,0x22,
			0x90,0x90,0x90,0x90,
			0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0xD2,
			0x90,0x90,0x90,
			0x41,0x58,                                //POP REG
			0x49,0x8D,0x40,0x10,
			0x49,0x89,0x40,0x08,                      //0x00007FF9DBC27C06 : offset 0xE6 = ACCESS_VIOLATION 0xc0000005 | $+E6 | +d8  mov qword ptr ds:[r8+8],rax 
			0xE8,0x10,0x00,0x00,0x00,
			0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,
			0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
			0x41, 
			0x5A,0x4D,0x8B,0x12,0x48,0x83,0xEC,0x10,
			0x4C,0x8B,0xCC,0x48,0x33,0xC9,0x48,0x33,
			0xD2,0x41,0xFF,0xD2,0x48,0x83,0xC4,0x10,
			0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,
			0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,
			0x5C,0x5D,0x5A,0x59,0x5B,0x58,0x9D,
		    
			0xCC

		};
		
		
		int prepare_stub(const WCHAR* dll_path, VOID* LdrLoadDll_addr, unsigned char* stub, size_t stub_size) noexcept;

		void stub_test(const WCHAR* dll_path, VOID* LdrLoadDll_addr, unsigned char* stub, size_t stub_size) noexcept {

			prepare_stub(dll_path, LdrLoadDll_addr, stub, stub_size);
			
			DWORD old_prot;
			VirtualProtectEx(GetCurrentProcess(), stub, stub_size, PAGE_EXECUTE_READWRITE, &old_prot);

			void(*p)() = (void(*)()) & x64_stub[0];
			p();

		}

		/// 
		/// //////////
		/// 

		struct Dbg_exception_info {
			PVOID addr;
			DWORD pid;
			DWORD tid;
			DWORD exception_code;
		};

		/// <summary>
		/// 
		/// </summary>

		class Debugger {

			bool dbg_loop_break_;

			BOOL active_;

			DWORD pid_;

			HANDLE wait_4_event_;
			HANDLE mod_ready_;

			Dbg_exception_info except_;

			mutable std::mutex prot_;

			std::thread dbg_loop_thread_;

			/// <summary>
			///  Helpers.
			/// </summary>

			BOOL _attach(DWORD pid) noexcept;
	
			void _loop(BOOL kill = FALSE) noexcept;

			bool _break() noexcept;

		public:

			explicit Debugger(DWORD pid) noexcept(false);

			void debug(BOOL kill = FALSE) noexcept;

			BOOL active() noexcept;

			BOOL stop() noexcept;

			bool wait(DWORD time = INFINITE) const noexcept;

			Dbg_exception_info except_info() const noexcept;

			BOOL ready() noexcept {
				return SetEvent(mod_ready_);
			}

		};
		
		/// <summary>
		/// 
		/// </summary>

		class Invader {

			void* Remote_LdrLoadDll_addr;
			void* Remote_ntdll_base_addr;
			unsigned long long LdrLoadDll_offset;

			unsigned char* memory_;


			/// <summary>
			/// Helpers.
			/// </summary>

			bool _alloc(size_t size) noexcept(false);

			unsigned long long _LdrLoadDll_offset() noexcept;

		public:

			Invader() noexcept : memory_(nullptr), LdrLoadDll_offset(0), Remote_LdrLoadDll_addr(nullptr), Remote_ntdll_base_addr(nullptr) {

			}
			
			inline unsigned char* memory() const noexcept {
				return memory_;
			}

			int read_memory(HANDLE proc, LPCVOID addr, SIZE_T size) noexcept(false);

			SIZE_T write_memory(HANDLE proc, LPVOID addr, const unsigned char* data, size_t data_size) noexcept(false);

			bool remote_addresses(const void* proc_addr) noexcept;

			inline
		    const void* remote_ntdll_base() const noexcept {
				return Remote_ntdll_base_addr;
			}

			inline
			const void* remote_LdrLoadDll_addr() const noexcept {
				return Remote_LdrLoadDll_addr;
			}

			int x64() const noexcept {

				BOOL wow;
				if (IsWow64Process(GetCurrentProcess(), &wow) == FALSE) {
					return -1;
				}

				return (wow != TRUE) ? 1 : 0;

			}

			inline BOOL protection(HANDLE proc, LPVOID addr, SIZE_T size, DWORD prot, PDWORD old_prot) noexcept {
				return VirtualProtectEx(proc, addr, size, prot, old_prot);
			}

			~Invader() {
				if (memory_ != nullptr) {
					delete[] memory_;
				}
			}
			
		};

	}

}