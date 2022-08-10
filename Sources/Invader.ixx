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

			  ~Debugger();

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
		

		
		/// <summary>
		/// po powrocie ACCESS VIOLATION AT: 0x00000000      84 1F 0F C3
		/// 0x00000000                                       84 1F 0F C3
		///                                                           
		/// orignal: 0xcc 0xc3 0xcc 0xcc 0xcc 0xcc 0xcc 0xcc 0xf 0x1f 0x84 0x0 0x0 0x0 ;//skok jest zjebany 
		///0xf7 0x7f 0x0 0x0 0xff 0xe0 0xc3 0x0 0x0 0x0 0xcc 0xc3 0xcc 0xcc 0xcc 0xc
		/// 
		///                                    |---------------------<---------Tu trafia powrót ze stuba
		/// $-A              00007 | 6666:0F1F8400 00000000               | nop word ptr ds:[rax+rax],ax                                                     |
		//$ ==> 00007 | CC | int3 |
			//$ + 1              00007 | C3 | ret |
		/*
		JEST:
		Notepad+0x3e5fe:
        00007ff7`28cee5fe cc              int     3
        00007ff7`28cee5ff 90              nop
        00007ff7`28cee600 48 b8 407cec32fa7f0000 mov rax,offset ntdll!DbgBreakPoint (00007ffa`32ec7c40)
        00007ff7`28cee60a ff60c7          jmp     qword ptr [rax-39h]       <-- !!!!!!!!!!!  powinien byæ jmp rax 
        00007ff7`28cee60d 442450          and     al,50h 
        00007ff7`28cee610 15000040c7      adc     eax,0C7400000h
        00007ff7`28cee615 442454          and     al,54h
        00007ff7`28cee618 0100            add     dword ptr [rax],eax
		*/
		/// </summary>
		extern unsigned char x64_trampoline[] = {

		 0x90,
		 0x48,0xB8,
		 0x77,0x77,0x77,0x77,
		 0x77,0x77,0x77,0x77,
		 0xFF,0xE0,
		 0xC3

		};

		int prepare_trampoline(const void* addr, unsigned char* trampoline, size_t trampoline_size) {

			INT64* in_stub_proc_addr_ptr = reinterpret_cast<INT64*>(memchr(trampoline, 0x77777777, trampoline_size));
			if (in_stub_proc_addr_ptr == nullptr) {
				return 0;
			}
			//INT64 entry_le = _byteswap_uint64(reinterpret_cast<INT64>(addr));
			*in_stub_proc_addr_ptr = reinterpret_cast<INT64>(addr); // entry_le;
			return 1;

		}

		void trampoline_test(unsigned char* trampoline, size_t trampoline_size, void* entry_addr) noexcept {

			prepare_trampoline(entry_addr, trampoline, trampoline_size);

			DWORD old_prot;
			VirtualProtectEx(GetCurrentProcess(), trampoline, trampoline_size, PAGE_EXECUTE_READWRITE, &old_prot);

			void(*p)() = (void(*)()) & trampoline[0];
			p();

		}
		
		extern unsigned char x64_stub[] = {        
												   
		0xCC,

		0x9C,
		0x56,0x50,0x53,0x51,0x52,0x55,0x56,0x57,
		0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,
		0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
		0xE8,0xB0,0x00,0x00,0x00,
		0x11,0x11,
		0x22,0x22,
		0x90,0x90,
		0x90,0x90,
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
		0x41,0x58,0x49,0x8D,0x40,0x10,0x49,0x89,
		0x40,0x08,0xE8,0x08,0x00,0x00,0x00,
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

        0x90,
	    0x90,0x90,0x90,0x90,
		0x90,0x90,0x90,0x90,
	    0x90,0x90,0x90,0x90

		};

		int prepare_stub(const WCHAR* dll_path, VOID* LdrLoadDll_addr, unsigned char* stub, size_t stub_size, void* DbgBreakPoint, bool trampoline = false) noexcept;

		void stub_test(const WCHAR* dll_path, VOID* LdrLoadDll_addr, unsigned char* stub, size_t stub_size, void* DbgBreakPoint) noexcept {

			prepare_stub(dll_path, LdrLoadDll_addr, stub, stub_size, DbgBreakPoint);

			DWORD old_prot;
			VirtualProtectEx(GetCurrentProcess(), stub, stub_size, PAGE_EXECUTE_READWRITE, &old_prot);

			void(*p)() = (void(*)()) &stub[0];
			p();

		}

		/// 
		/// //////////
		/// 

		class Invader2 {
			
			bool x64;

			HANDLE proc_;
			DWORD  pid_;

			HANDLE thread_;
			DWORD  tid_;

			DWORD  creation_flag_;

			void* Remote_LdrLoadDll_addr;
			void* Remote_ntdll_base_addr;

			unsigned long long LdrLoadDll_offset;

			unsigned char* stub_;
			unsigned char* trampoline_;

		    /// <summary>
		    /// Helpers.
	  	    /// </summary>
		
			bool intern_alloc_stub(size_t size) noexcept(false);
			bool intern_alloc_trampoline(size_t size) noexcept(false);

			unsigned long long intern_LdrLoadDll_offset() noexcept;

			unsigned long long remote_base_addr_main_module() noexcept;

		public:

			~Invader2();

			Invader2(bool is_x64 = true) noexcept : x64(is_x64), stub_(nullptr), trampoline_(nullptr), LdrLoadDll_offset(0), Remote_LdrLoadDll_addr(nullptr), Remote_ntdll_base_addr(nullptr)  {
				proc_ = NULL;
				pid_ = -1;
				thread_ = NULL;
				tid_ = -1;
				creation_flag_ = 0;
			}

			unsigned long long remote_entry_point() noexcept;

			inline unsigned char* stub() const noexcept {
				return stub_;
			}

			inline unsigned char* trampoline() const noexcept {
				return trampoline_;
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

			int read_memory_stub(HANDLE proc, LPCVOID addr, SIZE_T size) noexcept;

			int read_memory_tarmpoline(HANDLE proc, LPCVOID addr, SIZE_T size) noexcept;

			SIZE_T write_memory(HANDLE proc, LPVOID addr, const unsigned char* data, size_t data_size) noexcept;

			BOOL create(const string_t& app_path, DWORD flag) noexcept;

			BOOL open(DWORD pid) noexcept;

			/// <summary>
			/// Existing proccess.
			/// </summary>
			/// <param name="pid">Process ID.</param>
			/// <returns>none</returns>
			explicit Invader2(DWORD pid, bool is_x64 = true) noexcept;

			/// <summary>
			/// New process.
			/// </summary>
			/// <param name="app_path">Application path.</param>
			/// <returns>none</returns>
			explicit Invader2(const string_t& app_path, DWORD flag, bool is_x64 = true) noexcept;
   
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