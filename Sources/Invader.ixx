module;

#include <Windows.h>
#include <thread>
#include <mutex>

export module Invader;

import Env;

export {

	namespace Invader {

		struct Dbg_exception_info {
			PVOID addr;
			DWORD pid;
			DWORD tid;
			DWORD exception_code;
		};

		class Debugger {

			/// <summary>
			/// Debugger session is avtive.
			/// </summary>
			BOOL active_;

			bool dbg_loop_break_;

			/// <summary>
			/// 
			/// </summary>
			HANDLE wait_4_event_;

			/// <summary>
			/// Signalizing to the debugger that code in attacked process is
			/// successfully modificatedand debugger can continue execution.
			/// </summary>
			HANDLE mod_ready_;

			DWORD pid_;

			Dbg_exception_info except_;

			/// <summary>
			/// Synchronizing access to a member of a class. 
			/// </summary>
			mutable std::mutex prot_;

			/// <summary>
			/// Debugger main loop thread.
			/// </summary>
			std::thread dbg_loop_thread_;

		/// <summary>
		/// Helpers.
		/// </summary>
		

		/// <summary>
		/// Debugger main loop.
		/// </summary>
		/// <param name="kill">
		/// Specifies that the process cannot be terminated after debugger deattached.
		/// </param>
		/// <returns>void</returns>
		void intern_loop(BOOL kill = FALSE) noexcept;

		/// <summary>
		/// Attach debugger to the process.
		/// </summary>
		/// <param name="pid">Process ID</param>
		/// <returns>TRUE = OK, FALSE = ERROR</returns>
		BOOL intern_attach(DWORD pid) noexcept;

		bool intern_break() noexcept;

		void intern_init(DWORD pid) noexcept;

		public:

			   Debugger() noexcept : prot_(), dbg_loop_thread_() {
				   intern_init(-1);
			   }

			   explicit Debugger(DWORD pid) noexcept;

			   inline void attach(DWORD pid) noexcept {
				   intern_init(pid);
			   }

			   void debug(BOOL kill = FALSE) noexcept;

			   BOOL active() noexcept;

			   BOOL stop() noexcept;

			   bool wait(DWORD time = INFINITE) const noexcept;

			   Dbg_exception_info except_info() const noexcept;

			   BOOL ready() noexcept {
				   return SetEvent(mod_ready_);
			   }

		};

		/// 
		/// //////////
		/// 
		
		extern unsigned char x64_stub[] = {
		
		0xCC,

		0x9C,
		0x56,
		0x50,0x53,0x51,0x52,0x55,
		0x56,0x57,
		0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,
		0x54,0x41,0x55,0x41,0x56,0x41,0x57,
		0xE8,0xB0,
		0x00,0x00,0x00,
		0x11,0x11,
		0x22,0x22,
		0x90,0x90,
		0x90,0x90,
		0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
		0x41,0x58,0x49,0x8D,0x40,0x10,0x49,0x89,0x40,
		0x08,0xE8,0x08,0x00,0x00,0x00,
		0x77,0x77,0x77,0x77,0x77,0x77,0x77,0x77,
		0x41,0x5A,0x4D,0x8B,
		0x12,0x48,0x83,0xEC,0x10,0x4C,0x8B,0xCC,0x48,
		0x33,0xC9,0x48,0x33,0xD2,0x41,0xFF,0xD2,0x48,
		0x83,0xC4,0x10,
		0x41,0x5F,
		0x41,0x5E,0x41,0x5D,
		0x41,0x5C,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,
		0x5E,
		0x5D,0x5A,0x59,0x5B,0x58,
		0x5E,
		0x9D,
		0xE9,0xE5,0xFE,0xFF,0xFF
	     
		};

		int prepare_stub(const WCHAR* dll_path, VOID* LdrLoadDll_addr, unsigned char* stub, size_t stub_size) noexcept;

		void stub_test(const WCHAR* dll_path, VOID* LdrLoadDll_addr, unsigned char* stub, size_t stub_size) noexcept {

			prepare_stub(dll_path, LdrLoadDll_addr, stub, stub_size);

			DWORD old_prot;
			VirtualProtectEx(GetCurrentProcess(), stub, stub_size, PAGE_EXECUTE_READWRITE, &old_prot);

			void(*p)() = (void(*)()) &stub[0];
			p();

		}

		/// 
		/// //////////
		/// 

		class Invader2 {
			
			HANDLE proc_;
			DWORD  pid_;

			HANDLE thread_;
			DWORD  tid_;

			DWORD  creation_flag_;

			void* Remote_LdrLoadDll_addr;
			void* Remote_ntdll_base_addr;
			unsigned long long LdrLoadDll_offset;

			unsigned char* memory_;

		    /// <summary>
		    /// Helpers.
	  	    /// </summary>
		
			bool intern_alloc(size_t size) noexcept(false);

			unsigned long long intern_LdrLoadDll_offset() noexcept;

		public:

			/// <summary>
			/// 
			/// </summary>
			/// <returns>bool</returns>
			bool do_i_have_privilege() noexcept;

			Invader2() noexcept : memory_(nullptr), LdrLoadDll_offset(0), Remote_LdrLoadDll_addr(nullptr), Remote_ntdll_base_addr(nullptr)  {
				proc_ = NULL;
				pid_ = -1;
				thread_ = NULL;
				tid_ = -1;
				creation_flag_ = 0;
			}

			inline unsigned char* memory() const noexcept {
				return memory_;
			}

			bool remote_addresses(const void* proc_addr) noexcept;

			inline
			const void* remote_ntdll_base() const noexcept {
				return Remote_ntdll_base_addr;
			}

			inline
			const void* remote_LdrLoadDll_addr() const noexcept {
				return Remote_LdrLoadDll_addr;
			}

			int read_memory(HANDLE proc, LPCVOID addr, SIZE_T size) noexcept;

			SIZE_T write_memory(HANDLE proc, LPVOID addr, const unsigned char* data, size_t data_size) noexcept;

			BOOL create(const string_t& app_path, DWORD flag) noexcept;

			BOOL open(DWORD pid) noexcept;

			/// <summary>
			/// Existing proccess.
			/// </summary>
			/// <param name="pid">Process ID.</param>
			/// <returns>none</returns>
			explicit Invader2(DWORD pid) noexcept;

			/// <summary>
			/// New process.
			/// </summary>
			/// <param name="app_path">Application path.</param>
			/// <returns>none</returns>
			explicit Invader2(const string_t& app_path, DWORD flag) noexcept;
   
			inline HANDLE process() const noexcept {
				return proc_;
			}

			inline DWORD pid() const noexcept {
				return pid_;
			}

			inline void kill_process() const noexcept {
				TerminateProcess(proc_, 0);
			}

			inline DWORD creation_flag() const noexcept {
				return creation_flag_;
			}

			inline BOOL protection(HANDLE proc, LPVOID addr, SIZE_T size, DWORD prot, PDWORD old_prot) noexcept {
				return VirtualProtectEx(proc, addr, size, prot, old_prot);
			}

			/// <summary>
			/// If u use CREATE_SUSPENDED, u should call resume_main_thread() && 
			/// (optional) DebugBreakProcess(Invader2.process());
			/// </summary>
			/// <returns>void</returns>
			inline void resume_main_thread() const noexcept {  
				ResumeThread(thread_);
			}

			inline void suspend_main_thread() const noexcept {
				SuspendThread(thread_);
			}

		};
		
	}

}