#include "hook.hpp"
#include "utils.hpp"

/*
 * Microsoft Official Document Definition
 * https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header
 */
typedef struct _WNODE_HEADER
{
	ULONG BufferSize;
	ULONG ProviderId;
	union {
		ULONG64 HistoricalContext;
		struct s {
			ULONG Version;
			ULONG Linkage;
		};
	};
	union {
		HANDLE KernelHandle;
		LARGE_INTEGER TimeStamp;
	};
	GUID Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER, * PWNODE_HEADER;

/*
 * Microsoft Official Document Definition
 * https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
 */
typedef struct _EVENT_TRACE_PROPERTIES
{
	WNODE_HEADER Wnode;
	ULONG BufferSize;
	ULONG MinimumBuffers;
	ULONG MaximumBuffers;
	ULONG MaximumFileSize;
	ULONG LogFileMode;
	ULONG FlushTimer;
	ULONG EnableFlags;
	union {
		LONG AgeLimit;
		LONG FlushThreshold;
	} DUMMYUNIONNAME;
	ULONG NumberOfBuffers;
	ULONG FreeBuffers;
	ULONG EventsLost;
	ULONG BuffersWritten;
	ULONG LogBuffersLost;
	ULONG RealTimeBuffersLost;
	HANDLE LoggerThreadId;
	ULONG LogFileNameOffset;
	ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

/* 
 * This struct is copied from original infinity hook
 */
typedef struct _CKCL_TRACE_PROPERTIES : EVENT_TRACE_PROPERTIES
{
	ULONG64 Unknown[3];
	UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

/* 
 * Trace operation type
 */
typedef enum _trace_type
{
	start_trace = 1,
	stop_trace = 2,
	query_trace = 3,
	update_trace = 4,
	flush_trace = 5
} trace_type;

namespace k_hook
{
	fssdt_call_back m_ssdt_call_back = nullptr; 
	unsigned long m_build_number = 0;
	void* m_syscall_table = nullptr;
	bool m_routine_status = true;

	void* m_EtwpDebuggerData = nullptr; 
	void* m_CkclWmiLoggerContext = nullptr;
	
	void** m_EtwpDebuggerDataSilo = nullptr;
	void** m_GetCpuClock_ptr = nullptr;

	unsigned long long m_original_GetCpuClock = 0;
	unsigned long long m_HvlpReferenceTscPage = 0;
	unsigned long long m_HvlGetQpcBias_ptr = 0;

	typedef __int64 (*FHvlGetQpcBias)();
	FHvlGetQpcBias m_original_HvlGetQpcBias = nullptr;

	// Modify trace setting
	NTSTATUS modify_trace_settings(trace_type type)
	{
		const unsigned long tag = 'VMON';

		// Allocate structure space
		CKCL_TRACE_PROPERTIES* property = (CKCL_TRACE_PROPERTIES*)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, tag);
		if (!property)
		{
			DbgPrintEx(0, 0, "[%s] allocate ckcl trace propertice struct fail \n", __FUNCTION__);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		// Allocate space to save name
		wchar_t* provider_name = (wchar_t*)ExAllocatePool2(POOL_FLAG_NON_PAGED, 256 * sizeof(wchar_t), tag);
		if (!provider_name)
		{
			DbgPrintEx(0, 0, "[%s] allocate provider name fail \n", __FUNCTION__);
			ExFreePoolWithTag(property, tag);
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		// Clear memory
		RtlZeroMemory(property, PAGE_SIZE);
		RtlZeroMemory(provider_name, 256 * sizeof(wchar_t));

		// Give name to the ckcl trace session
		RtlCopyMemory(provider_name, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
		RtlInitUnicodeString(&property->ProviderName, (const wchar_t*)provider_name);

		// Identical session ID
		GUID ckcl_session_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

		// Fill the property struct
		property->Wnode.BufferSize = PAGE_SIZE;
		property->Wnode.Flags = 0x00020000;
		property->Wnode.Guid = ckcl_session_guid;
		property->Wnode.ClientContext = 3;
		property->BufferSize = sizeof(unsigned long);
		property->MinimumBuffers = 2;
		property->MaximumBuffers = 2;
		property->LogFileMode = 0x00000400;

		// Do the operation
		unsigned long length = 0;
		if (type == trace_type::update_trace) property->EnableFlags = 0x00000080; // EVENT_TRACE_FLAG_SYSTEMCALL
		NTSTATUS status = NtTraceControl(type, property, PAGE_SIZE, property, PAGE_SIZE, &length);

		// Free allocated space
		ExFreePoolWithTag(provider_name, tag);
		ExFreePoolWithTag(property, tag);

		return status;
	}

	// Our replacement function, targeting systems from Win7 to Win10 1909
	unsigned long long self_get_cpu_clock()
	{
		// Let the kernel mode call pass
		if (ExGetPreviousMode() == KernelMode) return __rdtsc();

		// Get the current thread
		PKTHREAD current_thread = (PKTHREAD)__readgsqword(0x188);

		// Different versions have different offsets
		unsigned int call_index = 0;
		if (m_build_number <= 7601) call_index = *(unsigned int*)((unsigned long long)current_thread + 0x1f8);
		else call_index = *(unsigned int*)((unsigned long long)current_thread + 0x80);

		// Get the current stack bottom and current stack frame/top (relatively)
		void** stack_bottom = (void**)__readgsqword(0x1a8);
		void** stack_frame = (void**)_AddressOfReturnAddress();

		// Start looking for ssdt calls in the current stack
		for (void** stack_current = stack_bottom; stack_current > stack_frame; --stack_current)
		{
			/*
			 * The characteristics of ssdt calls in the stack are
			 *   mov [rsp+48h+var_20], 501802h
			 *   mov r9d, 0F33h
			 */
#define INFINITYHOOK_MAGIC_1 ((unsigned long)0x501802)
#define INFINITYHOOK_MAGIC_2 ((unsigned short)0xF33)

			// The first check
			unsigned long* l_value = (unsigned long*)stack_current;
			if (*l_value != INFINITYHOOK_MAGIC_1) continue;

			--stack_current;

			// The second check
			unsigned short* s_value = (unsigned short*)stack_current;
			if (*s_value != INFINITYHOOK_MAGIC_2) continue;

			// The value matches successfully, and then look back
			for (; stack_current < stack_bottom; ++stack_current)
			{
				// Check if it is in the ssdt table
				unsigned long long* ull_value = (unsigned long long*)stack_current;
				if (!(PAGE_ALIGN(*ull_value) >= m_syscall_table && PAGE_ALIGN(*ull_value) < (void*)((unsigned long long)m_syscall_table + (PAGE_SIZE * 2)))) continue;

				// Now it has been determined that it is an ssdt function call, here is to
				// find KiSystemServiceExit
				void** system_call_function = &stack_current[9];

				// Call back function
				if (m_ssdt_call_back) m_ssdt_call_back(call_index, system_call_function);

				// Jump out of the loop
				break;
			}

			// Jump out of the loop
			break;
		}

		// Call the original function
		return __rdtsc();
	}

	// Our replacement function, targeting systems from Win 1919 and above
	EXTERN_C __int64 self_hvl_get_qpc_bias()
	{
		// Our filter function
		self_get_cpu_clock();

		// Here is what HvlGetQpcBias really does
		return *((unsigned long long*)(*((unsigned long long*)m_HvlpReferenceTscPage)) + 3);
	}

	// Detection routine
	void detect_routine(void*)
	{
		while (m_routine_status)
		{
			k_utils::sleep(4000);

			// If GetCpuClock is a function pointer
			if (m_build_number <= 18363)
			{
				DbgPrintEx(0, 0, "[%s] fix 0x%p 0x%p \n", __FUNCTION__, m_GetCpuClock_ptr, MmIsAddressValid(m_GetCpuClock_ptr) ? *m_GetCpuClock_ptr : 0);

				if (MmIsAddressValid(m_GetCpuClock_ptr) && MmIsAddressValid(*m_GetCpuClock_ptr))
				{
					// If the value is different, re-hook it
					if (self_get_cpu_clock != *m_GetCpuClock_ptr)
					{
						if (initialize(m_ssdt_call_back)) start();
					}
				}
				else initialize(m_ssdt_call_back); // GetCpuClock is invalid and needs to be reacquired
			}
		}

		DbgPrintEx(0, 0, "[%s] detect routine thread terminated \n", __FUNCTION__);
		PsTerminateSystemThread(STATUS_SUCCESS);
	}

	bool initialize(fssdt_call_back ssdt_call_back)
	{
		if (!m_routine_status) return false;

		// Callback function pointer check
		DbgPrintEx(0, 0, "[%s] ssdt call back ptr is 0x%p \n", __FUNCTION__, ssdt_call_back);
		if (!MmIsAddressValid(ssdt_call_back)) return false;
		else m_ssdt_call_back = ssdt_call_back;

		// Try to hook first
		if (!NT_SUCCESS(modify_trace_settings(update_trace)))
		{
			// Unable to turn on CKCL
			if (!NT_SUCCESS(modify_trace_settings(start_trace)))
			{
				DbgPrintEx(0, 0, "[%s] start ckcl fail \n", __FUNCTION__);
				return false;
			}

			// Try to hook again
			if (!NT_SUCCESS(modify_trace_settings(update_trace)))
			{
				DbgPrintEx(0, 0, "[%s] syscall ckcl fail \n", __FUNCTION__);
				return false;
			}
		}

		// Get the system build number
		m_build_number = k_utils::get_system_build_number();
		DbgPrintEx(0, 0, "[%s] build number is %ld \n", __FUNCTION__, m_build_number);
		if (!m_build_number) return false;

		// Get the system base address
		unsigned long long ntoskrnl = k_utils::get_module_address("ntoskrnl.exe", nullptr);
		DbgPrintEx(0, 0, "[%s] ntoskrnl address is 0x%llX \n", __FUNCTION__, ntoskrnl);
		if (!ntoskrnl) return false;

		// Different pattern here for different systems
		unsigned long long EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
		if (!EtwpDebuggerData) EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".data");
		if (!EtwpDebuggerData) EtwpDebuggerData = k_utils::find_pattern_image(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".rdata");
		DbgPrintEx(0, 0, "[%s] etwp debugger data is 0x%llX \n", __FUNCTION__, EtwpDebuggerData);
		if (!EtwpDebuggerData) return false;
		m_EtwpDebuggerData = (void*)EtwpDebuggerData;

		// The offset 0x10 is the same in all systems
		m_EtwpDebuggerDataSilo = *(void***)((unsigned long long)m_EtwpDebuggerData + 0x10);
		DbgPrintEx(0, 0, "[%s] etwp debugger data silo is 0x%p \n", __FUNCTION__, m_EtwpDebuggerDataSilo);
		if (!m_EtwpDebuggerDataSilo) return false;

		// The offset 0x2 is the same in all systems
		m_CkclWmiLoggerContext = m_EtwpDebuggerDataSilo[0x2];
		DbgPrintEx(0, 0, "[%s] ckcl wmi logger context is 0x%p \n", __FUNCTION__, m_CkclWmiLoggerContext);
		if (!m_CkclWmiLoggerContext) return false;

		// Win7 and Win11 have offset 0x18, others are 0x28
		if (m_build_number <= 7601 || m_build_number >= 22000) m_GetCpuClock_ptr = (void**)((unsigned long long)m_CkclWmiLoggerContext + 0x18); // Win7版本以及更旧, Win11也是
		else m_GetCpuClock_ptr = (void**)((unsigned long long)m_CkclWmiLoggerContext + 0x28); // Win8 -> Win10全系统
		if (!MmIsAddressValid(m_GetCpuClock_ptr)) return false;
		DbgPrintEx(0, 0, "[%s] get cpu clock is 0x%p \n", __FUNCTION__, *m_GetCpuClock_ptr);

		// Get the ssdt pointer
		m_syscall_table = PAGE_ALIGN(k_utils::get_syscall_entry(ntoskrnl));
		DbgPrintEx(0, 0, "[%s] syscall table is 0x%p \n", __FUNCTION__, m_syscall_table);
		if (!m_syscall_table) return false;

		if (m_build_number > 18363)
		{
			/* 
			 * HvlGetQpcBias function needs to use this structure internally
			 * So we manually locate this structure
			 */
			unsigned long long address = k_utils::find_pattern_image(ntoskrnl,
				"\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\x40\x00\x48\x8b\x0d\x00\x00\x00\x00\x48\xf7\xe2",
				"xxx????xxx?xxx????xxx");
			if (!address) return false;
			m_HvlpReferenceTscPage = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(address) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 3));
			DbgPrintEx(0, 0, "[%s] hvlp reference tsc page is 0x%llX \n", __FUNCTION__, m_HvlpReferenceTscPage);
			if (!m_HvlpReferenceTscPage) return false;

			/*
			 * Here we find the pointer of HvlGetQpcBias
			 * For more details, please refer to https://www.freebuf.com/articles/system/278857.html
			 */
			address = k_utils::find_pattern_image(ntoskrnl,
				"\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x48\x83\x3d\x00\x00\x00\x00\x00\x74",
				"xxx????xxxx?xxx?????x");
			/*
			 * For Win10 21h2.2130, after install the KB5018410 patch, you need to use a new pattern code
			 * For more details, please refer to https://github.com/FiYHer/InfinityHookPro/issues/17
			 * Thanks @LYingSiMon
			 */
			if (!address) 
				address = k_utils::find_pattern_image(ntoskrnl, 
				"\x48\x8b\x05\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x48\x03\xd8\x48\x89\x1f",
				"xxx????x????xxxxxx");
			if (!address) return false;
			m_HvlGetQpcBias_ptr = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(address) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 3));
			DbgPrintEx(0, 0, "[%s] hvl get qpc bias is 0x%llX \n", __FUNCTION__, m_HvlGetQpcBias_ptr);
			if (!m_HvlGetQpcBias_ptr) return false;
		}

		return true;
	}

	bool start()
	{
		if (!m_ssdt_call_back) return false;

		// Invalid pointer
		if (!MmIsAddressValid(m_GetCpuClock_ptr))
		{
			DbgPrintEx(0, 0, "[%s] get cpu clock vaild \n", __FUNCTION__);
			return false;
		}

		/*
		 * Here we distinguish the system version
		 * From Win7 to Win10 1909, g_GetCpuClock is a function, and later versions are a value
		 * Greater than 3 throws an exception
		 * Equal to 3 use rdtsc
		 * Equal to 2 use a function pointer (off_140C00A30)
		 * Equal to 1 use KeQueryPerformanceCounter
		 * Equal to 0 use RtlGetSystemTimePrecise
		 * Our approach refers to the website https://www.freebuf.com/articles/system/278857.html
		 * We do it on 2
		 */
		if (m_build_number <= 18363)
		{
			// Directly modify the function pointer
			DbgPrintEx(0, 0, "[%s] get cpu clock is 0x%p\n", __FUNCTION__, *m_GetCpuClock_ptr);
			*m_GetCpuClock_ptr = self_get_cpu_clock;
			DbgPrintEx(0, 0, "[%s] update get cpu clock is 0x%p\n", __FUNCTION__, *m_GetCpuClock_ptr);
		}
		else
		{
			// Save the original value of GetCpuClock, and restore it when exiting
			m_original_GetCpuClock = (unsigned long long)(*m_GetCpuClock_ptr);

			/*
			 * Here we set it to 2, so that we can call the off_140C00A30 function
			 * In fact, this pointer is the HalpTimerQueryHostPerformanceCounter function
			 * There are two function pointers in this function, the first is 
			 * HvlGetQpcBias, which is our goal
			 */
			*m_GetCpuClock_ptr = (void*)2;
			DbgPrintEx(0, 0, "[%s] update get cpu clock is %p \n", __FUNCTION__, *m_GetCpuClock_ptr);

			// Save the old HvlGetQpcBias address for easy restoration of the environment later
			m_original_HvlGetQpcBias = (FHvlGetQpcBias)(*((unsigned long long*)m_HvlGetQpcBias_ptr));

			// Set the hook
			*((unsigned long long*)m_HvlGetQpcBias_ptr) = (unsigned long long)self_hvl_get_qpc_bias;
			DbgPrintEx(0, 0, "[%s] update hvl get qpc bias is %p \n", __FUNCTION__, self_hvl_get_qpc_bias);
		}

		// Create GetCpuClock value detection thread
		static bool is_create_thread = false;
		if (!is_create_thread)
		{
			is_create_thread = true;
			HANDLE h_thread = NULL;
			CLIENT_ID client{ 0 };
			OBJECT_ATTRIBUTES att{ 0 };
			InitializeObjectAttributes(&att, 0, OBJ_KERNEL_HANDLE, 0, 0);
			NTSTATUS status = PsCreateSystemThread(&h_thread, THREAD_ALL_ACCESS, &att, 0, &client, detect_routine, 0);
			if (NT_SUCCESS(status)) ZwClose(h_thread);
			DbgPrintEx(0, 0, "[%s] detect routine thread id is %d \n", __FUNCTION__, (int)(UINT_PTR)client.UniqueThread);
		}

		return true;
	}

	bool stop()
	{
		// Stop the detection thread
		m_routine_status = false;

		bool result = NT_SUCCESS(modify_trace_settings(stop_trace)) && NT_SUCCESS(modify_trace_settings(start_trace));

		// Win10 1909 and above systems need to restore the environment
		if (m_build_number > 18363)
		{
			*((unsigned long long*)m_HvlGetQpcBias_ptr) = (unsigned long long)m_original_HvlGetQpcBias;
			*m_GetCpuClock_ptr = (void*)m_original_GetCpuClock;
		}

		return result;
	}
}
