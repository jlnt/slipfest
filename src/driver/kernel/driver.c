/* SLIPFEST                                 / \/  \ \/    \                    *
 *                                            /   \   \/\                      *
 *											      /\  /                        *
 * (C) 2005 Yoann GUILLOT                    o      ||   o                     *
 *          Julien TINNES                   -U-     ||  /V\                    *
 *                                          / \     ||  / \                    *
 *                                                                             *
 * System Level Intrusion Prevention Framework Evaluation Suite and Toolkit    *
 *                                                                             *
 *        "c'est la fête du slip!"                                             *
 *                                                                             *
 * SLIPFEST is a Windows 32bits HIPS evaluation suite.                         *
 * Copyright (C) 2005 Y. Guillot & J. Tinnes                                   *
 *                                                                             *
 * This program is free software; you can redistribute it and/or               *
 * modify it under the terms of the GNU General Public License                 *
 * as published by the Free Software Foundation; either version 2              *
 * of the License, or (at your option) any later version.                      *
 *                                                                             *
 * This program is distributed in the hope that it will be useful,             *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               *
 * GNU General Public License for more details.                                *
 *                                                                             *
 * You should have received a copy of the GNU General Public License           *
 * along with this program; if not, write to the                               *
 * Free Software Foundation, Inc.,                                             *
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.               *
 *                                                                             *
 */

#include "ntddk.h"

#if 0
#if 0
NTSTATUS DriverEntry(IN PDRIVER_OBJECT drv, IN PUNICODE_STRING regPath) {
	// reboot
	_asm {
		mov edx, 0x64
		mov eax, 0xfe
		_emit 0xee
	}
	return 0;
}
#else
	// beep
NTSTATUS DriverEntry(IN PDRIVER_OBJECT drv, IN PUNICODE_STRING regPath) {
	DbgPrint("makebeep");
	_asm {
		push ebx
		push ecx
		mov ebx, HalMakeBeep
		push 0x420
		call ebx
		mov ecx, 0x20000000
blabite:
		loop blabite
		push 0
		call ebx
		mov eax, 0xC0000120 // STATUS_CANCELLED
		pop ecx
		pop ebx
	}
}
#endif
#else

//
// System Information Classes.
//

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemUnused1,
    SystemPerformanceTraceInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemUnused3,
    SystemUnused4,
    SystemUnused5,
    SystemUnused6,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION {//Information Class 11
	ULONG Reserved [2];
	PCHAR Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName [256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_MODULE_LIST {
	ULONG module_cnt;
	SYSTEM_MODULE_INFORMATION module[0];
} SYSTEM_MODULE_LIST, *PSYSTEM_MODULE_LIST;

typedef struct ServiceDescriptorEntry {
    unsigned int *ServiceTableBase;
    unsigned int *ServiceCounterTableBase; //Used only in checked build
    unsigned int NumberOfServices;
    unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;

extern PServiceDescriptorTableEntry KeServiceDescriptorTable; 

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation (
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

PSYSTEM_MODULE_LIST all_modules = NULL;

void read_exportname(char *base, unsigned target, char *buf, unsigned buf_len)
{
	unsigned opth;
	unsigned exp_nn;
	unsigned *exptbl;
	unsigned *expname;
	unsigned *expfn;
	unsigned short *expord;
	unsigned i;

	*buf = 0;

	opth =  *(unsigned*)(base + 0x3c);
	exptbl = (unsigned*)(base + opth + 4 + 0x14 + 0x60);
	if (!exptbl[1])
		return;

	exptbl = (unsigned*)(base + exptbl[0]);
	exp_nn = exptbl[6];
	expfn = (unsigned*)(base + exptbl[7]);
	expname = (unsigned*)(base + exptbl[8]);
	expord = (unsigned short*)(base + exptbl[9]);

	for (i=0 ; i<exp_nn ; i++) {
		if (expfn[expord[i]] == target) {
			strncpy(buf, base + expname[i], buf_len);
			buf[buf_len - 1] = 0;
			break;
		}
	}
}

int fillreadbuff(char *buf, unsigned len)
{
	unsigned buf_off;
	char *fptr;
	unsigned *dwbuf = (unsigned *)buf;
	unsigned i;
	unsigned *addr;


	buf_off = 4;
	if (len < 4)
		return 0;
	
	/* returns the number of services in the main SDT */
	if (dwbuf[0] == (unsigned)-1) {
		dwbuf[0] = KeServiceDescriptorTable->NumberOfServices;
		return buf_off;
	}
#if 1
	/* allow arbitrary read */
	if (dwbuf[0] == (unsigned)-2) {
		if (len < 8)
				return 0;
		addr = (unsigned *)dwbuf[1];
		dwbuf[0] = *addr;
		return 4;
	}
#endif
#if 1
	/* allow arbitrary write */
	if (dwbuf[0] == (unsigned)-3) {
		if (len < 12)
				return 0;
		addr = (unsigned *)dwbuf[1];
		dwbuf[0] = *addr;
		*addr = dwbuf[2];
		return 4;
	}	
#endif
	if (dwbuf[0] < KeServiceDescriptorTable->NumberOfServices)
		dwbuf[0] = (unsigned)fptr = KeServiceDescriptorTable->ServiceTableBase[dwbuf[0]];

	if (len == buf_off)
		return buf_off;

	if (!all_modules) {
		unsigned sz;
		ZwQuerySystemInformation(SystemModuleInformation, &sz, 0, &sz);
		all_modules = ExAllocatePool(PagedPool, sz);
		if (!all_modules)
			return buf_off;
		if (ZwQuerySystemInformation(SystemModuleInformation, all_modules, sz, 0) != STATUS_SUCCESS) {
			ExFreePool(all_modules);
			all_modules = NULL;
			return buf_off;
		}
	}

	buf[len-1] = 1;
	for (i = 0 ; i < all_modules->module_cnt ; i++) {
		if ((all_modules->module[i].Base <= fptr) &&
			(all_modules->module[i].Base + all_modules->module[i].Size > fptr)) {
			strncpy(buf+buf_off, all_modules->module[i].ImageName, len - buf_off);
			buf[len-1] = 0;
			buf_off += strlen(buf+buf_off);
			break;
		}
	}
	if (!buf[len-1]) {
		if (buf_off < len - 2) {
			buf[buf_off++] = '!';
			read_exportname(all_modules->module[i].Base, (char*)fptr - all_modules->module[i].Base, buf+buf_off, len-buf_off);
			buf_off += strlen(buf+buf_off) + 1;
		}
		if (buf_off < len-sizeof(unsigned)) {
			*(unsigned*)(buf+buf_off) = (char *)fptr - all_modules->module[i].Base;
			buf_off += sizeof(unsigned);
		}
	} else {
		buf[buf_off++] = 0;
		*(char**)(buf+buf_off) = fptr;
		buf_off += sizeof(unsigned);
	}
	return buf_off;
}

NTSTATUS FuncDispatcher(IN PDEVICE_OBJECT dev, IN PIRP irp) {
	PIO_STACK_LOCATION irpst;
	ULONG code;
	PUCHAR userbuffer;
	char *str;

	irp->IoStatus.Status = STATUS_INVALID_PARAMETER;

	irpst = IoGetCurrentIrpStackLocation(irp);
	switch (irpst->MajorFunction) {
	case IRP_MJ_CREATE:
		str = "Device create";
		irp->IoStatus.Status = STATUS_SUCCESS;
		break;

	case IRP_MJ_READ:
		str = "Device read";
		if (irpst->Parameters.Read.ByteOffset.LowPart == 0) {
			userbuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
			if (userbuffer) {
				irp->IoStatus.Information = fillreadbuff(userbuffer, irpst->Parameters.Read.Length);
				irp->IoStatus.Status = STATUS_SUCCESS;
			} else
				str = "Device read / Invalid user buffer";
		} else
			DbgPrint("Invalid read param: offset = %d, len = %d", irpst->Parameters.Read.ByteOffset.LowPart, irpst->Parameters.Read.Length);
		break;

	case IRP_MJ_WRITE:
		str = "Device write";
/*		if (irpst->Parameters.Write.ByteOffset.LowPart == 0 && irpst->Parameters.Write.Length == 1) {
			userbuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
			if (userbuffer) {
				DbgPrint("the user sent the char %c (%d)", userbuffer[0], userbuffer[0]);
				irp->IoStatus.Status = STATUS_SUCCESS;
				irp->IoStatus.Information = 1;
			} else
				str = "Device write / Invalid user buffer";
		} else
			DbgPrint("Invalid write param: offset = %d, len = %d", irpst->Parameters.Write.ByteOffset.LowPart, irpst->Parameters.Write.Length);
*/		break;

	case IRP_MJ_CLOSE:
		str = "Device close";
		irp->IoStatus.Status = STATUS_SUCCESS;
		break;

	case IRP_MJ_DEVICE_CONTROL:
		str = "Device ioctl";
		irp->IoStatus.Status = STATUS_SUCCESS;
//		code = irpst->Parameters.DeviceIoControl.IoControlCode;
		break;

	default:
		str = "Device received unknown function code";
		break;
	}

	if (str)
		DbgPrint(str);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void OnUnload(IN PDRIVER_OBJECT dev)
{
	PDEVICE_OBJECT tmp, tmp2;
	UNICODE_STRING shortcutname;

    RtlInitUnicodeString(&shortcutname, L"\\??\\jj"); 
	IoDeleteSymbolicLink(&shortcutname);

	for (tmp2 = dev->DeviceObject ; tmp = tmp2 ; tmp2 = tmp->NextDevice)
		IoDeleteDevice(tmp);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT drv, IN PUNICODE_STRING regPath) {
	UNICODE_STRING devicename;
	UNICODE_STRING shortcutname;
	PDEVICE_OBJECT pdev = 0;
	NTSTATUS ret = STATUS_SUCCESS;

/* PsSetCreateProcessNotifyRoutine() */

	drv->DriverUnload = (PDRIVER_UNLOAD)OnUnload;

#if 0
	/* beep (to test systemloadandcallimage) */
	HalMakeBeep(0x60);
	for (i=0 ; i<0x100000 ; i++) {
		j += i;
	}
	HalMakeBeep(0);
#endif
	RtlInitUnicodeString(&devicename, L"\\Device\\jjdevice");
    RtlInitUnicodeString(&shortcutname, L"\\DosDevices\\jj"); 

	ret = IoCreateDevice(drv, 0,
		&devicename, 
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, 
		FALSE,
		&pdev);
	if (!NT_SUCCESS(ret)) {
		DbgPrint("iocreatedevice: ret %X", ret);
		goto err;
	}

	pdev->Flags |= DO_DIRECT_IO;
	pdev->Flags &= (~DO_DEVICE_INITIALIZING);

	ret = IoCreateSymbolicLink(&shortcutname, &devicename);

	if (!NT_SUCCESS(ret)) {
		DbgPrint("iocreatesymlink: ret %X", ret);
		goto err2;
	}

	drv->MajorFunction[IRP_MJ_CREATE] = FuncDispatcher;
	drv->MajorFunction[IRP_MJ_READ] = FuncDispatcher;
	drv->MajorFunction[IRP_MJ_WRITE] = FuncDispatcher;
	drv->MajorFunction[IRP_MJ_CLOSE] = FuncDispatcher;
	drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FuncDispatcher;

	return STATUS_SUCCESS;

err2:
	IoDeleteDevice(pdev);
err:
	return ret;
}

#endif