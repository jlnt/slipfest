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


#include "stdafx.h"
#include "system.h"

#define showlastsyserror(base) do { getnativeprocaddress(RtlNtStatusToDosError); SetLastError(RtlNtStatusToDosError(ntstatus)); showlasterror(base); } while (0)

void listmodules(HANDLE phandle, int newtarget)
{
#define MODLISTSZ 200
	HMODULE hMods[MODLISTSZ];
	DWORD max;
	DWORD i;
	for (i=0 ; i<MODLISTSZ ; i++)
		hMods[i] = 0;

	if (!EnumProcessModules(phandle, hMods, sizeof(hMods), &max)) {
		showlasterror("enumprocmodules");
		return;
	}

	max /= sizeof(*hMods);
	if (max > MODLISTSZ) {
		addbacklog("Module list: (more available)");
		max = MODLISTSZ;
	} else
		addbacklog("Module list: ");

	if (newtarget)
		PEbase = hMods[0];

	char buf[1024];
	for (i = 0 ; i < max ; i++) {

		DWORD modmemsz = 0;
		DWORD ret;
		ReadProcessMemory(phandle, (void *)((DWORD)hMods[i] + 0x3c), &modmemsz, 4, &ret);
		ReadProcessMemory(phandle, (void *)((DWORD)hMods[i] + modmemsz + 4 + 0x14 + 0x38), &modmemsz, 4, &ret);

		_snprintf(buf, 1024, " %.8lX (%.6lX): ", hMods[i], modmemsz);
		if (!GetModuleFileNameExA(phandle, hMods[i], buf+strlen(buf), 1024-strlen(buf)))
			showlasterror("getmodulefilename");
		addbacklog(buf);
	}
}

void showusername(HANDLE phandle)
{
	PSID psid;
	PSECURITY_DESCRIPTOR psec;
	if (GetSecurityInfo(phandle, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &psid, 0, 0, 0, &psec)) {
		showlasterror("getsecurityinfo");
		return;
	}

	char buf1[512];
	DWORD len1 = 512;
	char buf[512];
	DWORD len = 512;
	SID_NAME_USE bla;

	strcpy(buf, "user: ");

	if (!LookupAccountSid(0, psid, buf1, &len1, buf+strlen(buf), &len, &bla))
		showlasterror("lookupaccountsid");
	else {
		strncat(buf, "\\", 512);
		buf[511] = 0;
		strncat(buf, buf1, 512);
		buf[511] = 0;
		addbacklog(buf);
	}

	LocalFree(psec);
}

void listprocesses(void)
{
    DWORD proclist[256], ret, nproc;
	char modname[512];
    unsigned int i;

    if (!EnumProcesses(proclist, sizeof(proclist), &ret))
        return;

    // Calculate how many process identifiers were returned
    nproc = ret/sizeof(*proclist);

	for (i=0 ; i<nproc ; i++) {
		// Get a handle to the process
		HMODULE hMod;
		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proclist[i]);

		_snprintf(modname, sizeof(modname), "pid %u: ", proclist[i]);

		if (hProc && EnumProcessModules(hProc, &hMod, sizeof(hMod), &ret))
			GetModuleBaseName(hProc, hMod, modname+strlen(modname), 412);
		else
			strcpy(modname+strlen(modname), "unknown");
		addbacklog(modname);
		CloseHandle(hProc);
	}
}

HMODULE PEbase;

void openpid(int pid)
{
	HANDLE h;
	int changetarget = 0;

	/* try to open the process */
	h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h) {
		showlasterror("openprocess with all_access");
	} else {
		addbacklog("openprocess with all_access successful");
		CloseHandle(hRemoteProc);
		/* got it */
		hRemoteProc = h;
		changetarget = 1;
	}

	h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL, FALSE, pid);
	if (!h) {
		showlasterror("openprocess_vm_read");
		return;
	}

	/* show information, but keep hRemoteProc as target */
	listmodules(h, changetarget);
	showusername(h);
	CloseHandle(h);
}

/* there is a race here, if we change hRemoteProc while injecting a shellcode.. */
void CALLBACK waitandchangetarget(void)
{
	DWORD pid, sleeptime;
	char buf[128];
    
	GetDlgItemText(hDlg, IDC_EDIT2, buf, 128);
	sleeptime = strtoul(buf, 0, 0);
	if (!sleeptime)
		sleeptime = 1000;
	Sleep(sleeptime);
	/* move mouse */

	/* retrieve the window under the cursor */
	POINT pt;
	if (!GetCursorPos(&pt)) {
		showlasterror("getcursorpos");
		return;
	}

	HWND target;
	target = WindowFromPoint(pt);
	if (!target) {
		showlasterror("windowfrompoint");
		return;
	}

	/* retrieve window info */
	if (!GetClassName(target, buf, 128)) {
		showlasterror("getclassname");
		return;
	}
	addbacklog(buf);

	if (GetWindowText(target, buf, 128))
		addbacklog(buf);

	DWORD tid;
	tid = GetWindowThreadProcessId(target, &pid);
	if (!tid || !pid) {
		showlasterror("getwindowthreadpid");
		return;
	}

	openpid(pid);
}

void changetarget(int method)
{
	char buf[512];
	DWORD pid = 0;
	static DWORD tid = 0;
	HANDLE h;

	switch (method) {
	case 0:
		GetDlgItemText(hDlg, IDC_EDIT1, buf, 512);
		pid = strtoul(buf, 0, 0);
		if (!pid) {
			listprocesses();
			return;
		}
		openpid(pid);
		break;

	case 1:
		if (tid) {
			h = OpenThread(THREAD_ALL_ACCESS, 0, tid);
			TerminateThread(h, 0);
			CloseHandle(h);
			tid = 0;
		}
		h = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)waitandchangetarget, 0, 0, &tid);
		CloseHandle(h);
	}
}


void get_dbgpriv(void)
{
	// SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, "", SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);

	_asm nop

	HANDLE hToken;
	LUID Val;
	TOKEN_PRIVILEGES tp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		showlasterror("openproctoken");
		return;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Val)) {
		showlasterror("lookupprivilegevalue");
		return;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = Val;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof (tp), NULL, NULL)) {
		showlasterror("adjusttokenprivileges");
		return;
	}

	CloseHandle(hToken);

	addbacklog("privilege successfully enabled");
}

void listhooks(char *dll_name, int restore)
{
	/*
	// list loaded modules in current process (name, len, basename)
	PTEB teb = 0;
	PLDR_MODULE ldr, *headldr;
	_asm {
		mov eax, dword ptr fs:[0x18]
		mov teb, eax
	}
	headldr = &teb->Peb->Ldr->InLoadOrderModuleList;
	ldr = *headldr;
	addbacklog("current process module list (from peb->ldr):");
	do {
		char buf[512];
		_snprintf(buf, 512, " %.8lX->%.8lX: %.*ws", ldr->BaseAddress, (DWORD)ldr->BaseAddress+ldr->SizeOfImage, ldr->BaseDllName.Length/2, ldr->BaseDllName.Buffer);
		addbacklog(buf);
		ldr = ldr->InLoadOrderModuleList;
	} while (ldr != (PLDR_MODULE)headldr);
	*/

	/*
	 * compares each entry point of each exported function of the dll,
	 * in the memory image and in the disk file
	 *
	 * only exports pointing in the .text section are checked
	 *
	 * relocated offsets are ignored
	 */
	char buf[1024];

	HANDLE hFile;
	HANDLE hFileMap;
	u8  *f_ptr = 0;
	struct exe_header f;

	HMODULE hDll;
	u8  *m_ptr = 0;
	struct exe_header m;

	u32 NR_CMP;

	GetDlgItemText(hDlg, IDC_EDIT2, buf, 512);
	NR_CMP = strtoul(buf, 0, 0);
	if (!NR_CMP)
		NR_CMP = 5;

	/* build library full path */
	if (dll_name[0] != '\\' && dll_name[1] != '\\') {
		strncpy(buf, getenv("SystemRoot"), 500);
		buf[500] = 0;
		strcat(buf, "\\system32\\");
		strncat(buf, dll_name, 1024);
	} else
		strncpy(buf, dll_name, 1024);
    
	buf[1023] = 0;

	addbacklog(dll_name);

	/* open file */
	hFile = CreateFile(buf, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		showlasterror("open library");
		goto err_out;
	}
	hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);
	if (hFileMap == INVALID_HANDLE_VALUE) {
		showlasterror("mmap library");
		goto err_close1;
	}

	f_ptr = (u8*)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
	if (!f_ptr) {
		showlasterror("mapview library");
		goto err_close1;
	}

	if (!loadpe(&f, f_ptr, 1)) {
		addbacklog("Invalid PE file !");
		goto err_close1;
	}

	/* open image */
	hDll = GetModuleHandle(dll_name);
	if (!hDll)
		hDll = LoadLibrary(dll_name);
	if (!hDll) {
		showlasterror("loadlibrary");
		goto err_close1;
	}
	m_ptr = (u8 *)hDll;

	if (!loadpe(&m, m_ptr, 0)) {
		addbacklog("Invalid PE memory image !");
		goto err_close2;
	}

	/* compare */
	if (m.exports.directory->base != f.exports.directory->base) {
		addbacklog("ord_base differs !");
		goto err_close2;
	}
	if (m.exports.directory->number_of_functions != f.exports.directory->number_of_functions) {
		addbacklog("not the same number of exports !");
		goto err_close2;
	}
	if (m.exports.directory->number_of_names != f.exports.directory->number_of_names) {
		addbacklog("not the same number of exports2 !");
		goto err_close2;
	}

	char *f_exportname,  *m_exportname;
	u32   f_exportord,    m_exportord;
	u8   *f_exportentry, *m_exportentry;

	u32 i, j;
	for (i=0 ; i<m.exports.directory->number_of_names ; i++) {
		f_exportname = (char *)(f_ptr + rva2va(&f, f.exports.names[i], 4));
		m_exportname = (char *)(m_ptr + m.exports.names[i]);

		if (strcmp(f_exportname, m_exportname)) {
			_snprintf(buf, 1024, "not the same exported function name: f '%s', m '%s'", f_exportname, m_exportname);
			addbacklog(buf);
		}

		f_exportord = f.exports.ordinals[i] + f.exports.directory->base;
		m_exportord = m.exports.ordinals[i] + m.exports.directory->base;
		if (f_exportord != m_exportord) {
			_snprintf(buf, 1024, "not the same exported ordinal for %s: f %u, m %u", m_exportname, f_exportord, m_exportord);
			addbacklog(buf);
		}

		f_exportentry = f_ptr + rva2va_text(&f, f.exports.functions[f.exports.ordinals[i]], 1);
		if (f_exportentry == f_ptr) {
			// the exported object is not in .text section
			continue;
		}
		m_exportentry = m_ptr + m.exports.functions[m.exports.ordinals[i]];
		
		int same = 1;
		unsigned char *lastrelocdiff = 0;
		if (memcmp(f_exportentry, m_exportentry, NR_CMP)) {

			// check relocs
			for (j=0 ; j<NR_CMP ; j++) {
				if (f_exportentry[j] != m_exportentry[j]) {

					if (isrelocated(&f, f_exportentry + j - f_ptr)) {
						if (lastrelocdiff + 1 != m_exportentry + j) {
							_snprintf(buf, 1024, "  difference at relocated offset %8X in %s", m_exportentry + j, m_exportname);
							addbacklog(buf);
						}
						lastrelocdiff = m_exportentry + j;
						continue;
					}

					same = 0;
					break;
				}
			}
		}

		if (!same) {
			// XXX bof..
			int len;
			_snprintf(buf, 1024, "%s hooked", m_exportname);
			len = strlen(buf);
			if (m_exportentry[0] == 0xE9) {
				long offset = *(long*)(m_exportentry+1);
				unsigned char *dst = m_exportentry + 5 + offset;
				_snprintf(buf+len, 1024-len, ", jump to %.8lX", dst);
				same = 1;
				len = strlen(buf);
			} else if (m_exportentry[0] == 0xE8) {
				long offset = *(long*)(m_exportentry+1);
				unsigned char *dst = m_exportentry + 5 + offset;
				_snprintf(buf+len, 1024-len, ", call to %.8lX", dst);
				same = 1;
				len = strlen(buf);
			}
			
			if (!same || NR_CMP != 5) {
				_snprintf(buf+len, 1010-len-4*NR_CMP, ": f=");
				len = strlen(buf);

				for (j=0 ; j<NR_CMP ; j++)
					_snprintf(buf+(len+=2)-2, 3, "%.2X", f_exportentry[j]);

				_snprintf(buf+len, 1010-len-2*NR_CMP, ", m=");
				len = strlen(buf);
				for (j=0 ; j<NR_CMP ; j++)
					_snprintf(buf+len+2*j, 3, "%.2X", m_exportentry[j]);
			}

			addbacklog(buf);

			if (restore == 1) {
				/* restore opcodes from the file */
				DWORD oldprot = 0;
				if (!VirtualProtect(m_exportentry, NR_CMP, PAGE_EXECUTE_READWRITE, &oldprot))
						showlasterror("virtualprotect");
				else {
					memcpy(m_exportentry, f_exportentry, NR_CMP);

					if (!VirtualProtect(m_exportentry, NR_CMP, oldprot, &oldprot))
						showlasterror("virtualprotect restore");
				}
			}
			if (restore == 2) {
				/* restore opcodes from the file */
				DWORD oldprot = 0;
				if (!VirtualProtectEx(GetCurrentProcess(), m_exportentry, NR_CMP, PAGE_EXECUTE_READWRITE, &oldprot))
						showlasterror("virtualprotect");
				else {
					memcpy(m_exportentry, f_exportentry, NR_CMP);

					if (!VirtualProtectEx(GetCurrentProcess(), m_exportentry, NR_CMP, oldprot, &oldprot))
						showlasterror("virtualprotect restore");
				}
			}
		}
	}
	addbacklog("Terminé");

err_close2:

err_close1:
	UnmapViewOfFile(f_ptr);
	CloseHandle(hFileMap);
	CloseHandle(hFile);
err_out:;
}

void listhookslib(int flag)
{
	char buf[256];
    GetDlgItemText(hDlg, IDC_EDIT1, buf, 256);
	if (buf[strlen(buf)-4] != '.') {
		strncat(buf, ".dll", 256);
		buf[255] = 0;
	}
	listhooks(buf, flag);
}

void listallhooks(void)
{
	char *dlls[] = { "ntdll.dll", "kernel32.dll", "user32.dll", "ws2_32.dll", "psapi.dll", "advapi32.dll", "ole32.dll", 0 };
	for (int i=0 ; dlls[i] ; i++)
		listhooks(dlls[i], 0);
}



void listkmods(void)
{
	DWORD sz, i;
	NTSTATUS ntstatus;
	struct sysinfo *buf;
	char sbuf[128];

	getnativeprocaddress(NtQuerySystemInformation);

	NtQuerySystemInformation(SystemModuleInformation, &sz, 0, &sz);
	buf = (struct sysinfo *)HeapAlloc(GetProcessHeap(), 0, sz);
	if (!buf) {
		showlasterror("HeapAlloc");
		return;
	}
	ntstatus = NtQuerySystemInformation(SystemModuleInformation, buf, sz, 0);
	if (!NT_SUCCESS(ntstatus))
		showlastsyserror("ntquerysysteminformation");
	else {
		addbacklog("currently loaded module list:");
		for(i=0; i<buf->size; i++) {
			_snprintf(sbuf, 128, " %.8X %s", buf->tab[i].Base, buf->tab[i].ImageName);
			addbacklog(sbuf);
		}
	}
	HeapFree(GetProcessHeap(), 0, buf);
}

/* physical memory testing */
wchar_t *curdevpathname = 0;

#define D_D		L"\\Device"
#define D_PM	L"\\PhysicalMemory"
#define D_GG	L"\\??\\GLOBALROOT"
#define D_HD	L"\\Harddisk0"
#define D_HDP	L"\\Partition0"
#define D_L1	L"\\lnk1"
#define D_LPM	L"\\lnkpm"
#define D_L3	L"\\lnk3"
#define D_L4	L"\\lnk4"
#define D_L5	L"\\lnk5"
#define D_LHD	L"\\lnk6"
#define D_LHDP	L"\\lnk7"

void initdevlnk(u32 id)
{
/*
	/lnk1 -> /Device
	/lnkpm -> /Device/PhysicalMemory
	/Device/lnk3 -> /Device
	/Device/lnk4 -> /
	/Device/lnk5 -> /Device/lnk4/lnk1/PhysicalMemory
	/lnk6 -> /Device/Harddisk0
	/lnk7 -> /Device/Harddisk0/Partition0
*/
	static HANDLE l1 = INVALID_HANDLE_VALUE, l2 = INVALID_HANDLE_VALUE, l3 = INVALID_HANDLE_VALUE;
	static HANDLE l4 = INVALID_HANDLE_VALUE, l5 = INVALID_HANDLE_VALUE, l6 = INVALID_HANDLE_VALUE;
	static HANDLE l7 = INVALID_HANDLE_VALUE;
	HANDLE *ph;

	NTSTATUS ntstatus;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING linkpath;
	UNICODE_STRING target;

	getnativeprocaddress(NtCreateSymbolicLinkObject);
	getnativeprocaddress(NtClose);
	getnativeprocaddress(RtlInitUnicodeString);

	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.RootDirectory = 0;
	oa.Attributes = 0;			// OBJ_CASE_INSENSITIVE
	oa.ObjectName = &linkpath;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	switch (id) {
	case 50:
		EnableMenuItem(GetMenu(hDlg), ID_DEV_CLEANLINKS, MF_GRAYED);

#define myclose(h) if (h != INVALID_HANDLE_VALUE) { NtClose(h); h = INVALID_HANDLE_VALUE; }

		myclose(l1)
		myclose(l2)
		myclose(l3)
		myclose(l4)
		myclose(l5)
		myclose(l6)
		myclose(l7)
		return;

	case 1:
		ph = &l1;
		RtlInitUnicodeString(&target, D_D);
		RtlInitUnicodeString(&linkpath, D_L1);
		break;

	case 2:
		ph = &l2;
		RtlInitUnicodeString(&target, D_D D_PM);
		RtlInitUnicodeString(&linkpath, D_LPM);
		break;

	case 3:
		ph = &l3;
		RtlInitUnicodeString(&target, D_D);
		RtlInitUnicodeString(&linkpath, D_D D_L3);
		break;

	case 4:
		ph = &l4;
		RtlInitUnicodeString(&target, L"\\");
		RtlInitUnicodeString(&linkpath, D_D D_L4);
		break;

	case 5:
		ph = &l5;
		RtlInitUnicodeString(&target, D_D D_L4 D_L1 D_PM);
		RtlInitUnicodeString(&linkpath, D_D D_L5);
		break;

	case 6:
		ph = &l6;
		RtlInitUnicodeString(&target, D_D D_HD);
		RtlInitUnicodeString(&linkpath, D_LHD);
		break;

	case 7:
		ph = &l7;
		RtlInitUnicodeString(&target, D_D D_HD D_HDP);
		RtlInitUnicodeString(&linkpath, D_LHDP);
		break;
	}

	if (*ph != INVALID_HANDLE_VALUE)
		return;

	EnableMenuItem(GetMenu(hDlg), ID_DEV_CLEANLINKS, MF_ENABLED);

	ntstatus = NtCreateSymbolicLinkObject(ph, OBJECT_TYPE_ALL_ACCESS, &oa, &target);
	if (!NT_SUCCESS(ntstatus))
		showlastsyserror("createsymlink");
}

void initdevpath(u32 id)
{
	if (id == ID_DEV_CLEANLINKS) {
		initdevlnk(50);
		id = ID_PM_D_PM;
	}

	CheckMenuRadioItem(GetMenu(hDlg), ID_PM_D_PM, ID_HD_GG_7, id, MF_BYCOMMAND);

	switch (id) {
	case ID_PM_D_PM:
		curdevpathname = D_D D_PM;
		break;

	case ID_PM_GG_D_PM:
		curdevpathname = D_GG D_D D_PM;
		break;

	case ID_PM_1_PM:
		initdevlnk(1);
		curdevpathname = D_L1 D_PM;
		break;

	case ID_PM_2:
		initdevlnk(2);
		curdevpathname = D_LPM;
		break;

	case ID_PM_D_3_PM:
		initdevlnk(3);
		curdevpathname = D_D D_L3 D_PM;
		break;

	case ID_PM_D_3_3_3_PM:
		initdevlnk(3);
		curdevpathname = D_D D_L3 D_L3 D_L3 D_PM;
		break;

	case ID_PM_D_4_1_PM:
		initdevlnk(4);
		initdevlnk(1);
		curdevpathname = D_D D_L4 D_L1 D_PM;
		break;

	case ID_PM_LD_4_1_PM:
		initdevlnk(5);
		initdevlnk(4);
		initdevlnk(1);
		curdevpathname = D_D D_L5;
		break;

	case ID_HD_D_HD_P:
		curdevpathname = D_D D_HD D_HDP;
		break;

	case ID_HD_6:
		initdevlnk(6);
		curdevpathname = D_LHD D_HDP;
		break;

	case ID_HD_7:
		initdevlnk(7);
		curdevpathname = D_LHDP;
		break;

	case ID_HD_GG_7:
		initdevlnk(7);
		curdevpathname = D_GG D_LHDP;
		break;
	}
}

int dev_setwriteable(const wchar_t *filename)
{
	HANDLE pmem;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING ufilename;
	NTSTATUS ntstatus;
	int ret = 0;

	getnativeprocaddress(RtlInitUnicodeString);
	getnativeprocaddress(NtClose);
	getnativeprocaddress(NtOpenSection);

	RtlInitUnicodeString(&ufilename, filename);

	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.RootDirectory = 0;
	oa.Attributes = 0;			// OBJ_CASE_INSENSITIVE
	oa.ObjectName = &ufilename;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	ntstatus = NtOpenSection(&pmem, READ_CONTROL | WRITE_DAC, &oa);
	if (!NT_SUCCESS(ntstatus))
		showlastsyserror("ntopensection dac");
	else {
		PACL dacl;
		PSECURITY_DESCRIPTOR sd;
		
		if(GetSecurityInfo(pmem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd))
			showlasterror("getsecurityinfo");
		else {
			EXPLICIT_ACCESS ea;
			char userName[MAX_PATH];
			DWORD userNameSize = MAX_PATH-1;

			GetUserName(userName, &userNameSize);

			ea.grfAccessPermissions = SECTION_MAP_WRITE;
			ea.grfAccessMode = GRANT_ACCESS;
			ea.grfInheritance = NO_INHERITANCE;
			ea.Trustee.pMultipleTrustee = NULL;
			ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
			ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
			ea.Trustee.ptstrName = userName;

			PACL newDacl;
			if(SetEntriesInAcl(1, &ea, dacl, &newDacl))
				showlasterror("setentriesinacl");
			else {
				if(SetSecurityInfo(pmem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, newDacl, NULL))
					showlasterror("setsecurityinfo");
				else
					ret = 1;
			}
		}
		NtClose(pmem);
	}
    return ret;
}

void testdevaccess(const wchar_t *filename, int write)
{
	HANDLE dev;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING ufilename;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK iostat;

	getnativeprocaddress(RtlInitUnicodeString);
	getnativeprocaddress(NtClose);
	getnativeprocaddress(NtOpenSection);
	getnativeprocaddress(NtOpenFile);

	RtlInitUnicodeString(&ufilename, filename);

	oa.Length = sizeof(OBJECT_ATTRIBUTES);
	oa.RootDirectory = 0;
	oa.Attributes = 0;			// OBJ_CASE_INSENSITIVE
	oa.ObjectName = &ufilename;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

//	ret = myNtCreateFile(&fh, GENERIC_READ|GENERIC_WRITE, &oa, &status, 0, 0, 0, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, 0, 0);

	if (!write) {
		// try opensection (for physmem)
		ntstatus = NtOpenSection(&dev, SECTION_MAP_READ, &oa);
		if (NT_SUCCESS(ntstatus)) {
			addbacklog("can opensection readonly");
			NtClose(dev);

		} else if (ntstatus == 0xc0000024) {
			// invalid device : try openfile (for hd)
			ntstatus = NtOpenFile(&dev, GENERIC_READ, &oa, &iostat, FILE_SHARE_READ|FILE_SHARE_WRITE, 0);
			if (NT_SUCCESS(ntstatus)) {
				addbacklog("can openfile readonly");
				NtClose(dev);
			} else
                showlastsyserror("openfile ro");

		} else
			showlastsyserror("opensection ro");

	} else {
		// test write access
		ntstatus = NtOpenSection(&dev, SECTION_MAP_READ | SECTION_MAP_WRITE, &oa);
		if (NT_SUCCESS(ntstatus)) {
			addbacklog("can opensection readwrite");
			NtClose(dev);

		} else if (ntstatus == 0xc0000024) {
			// invalid device : try openfile
			ntstatus = NtOpenFile(&dev, GENERIC_READ | GENERIC_WRITE, &oa, &iostat, FILE_SHARE_READ|FILE_SHARE_WRITE, 0);
			if (NT_SUCCESS(ntstatus)) {
				addbacklog("can openfile readwrite");
				NtClose(dev);
			} else
                showlastsyserror("openfile rw");

		} else if (dev_setwriteable(filename)) {
			// retry opensection after changing DAC
			ntstatus = NtOpenSection(&dev, SECTION_MAP_READ | SECTION_MAP_WRITE, &oa);
			if (NT_SUCCESS(ntstatus)) {
				addbacklog("can opensection readwrite after DAC override");
				NtClose(dev);
			} else 
				showlastsyserror("opensection rw");
		}
	}
}

/* put 0xCC at offset */
int breakthere(unsigned char *ptr, void *bla)
{
	char buf[1024];
	unsigned char patch[256];
	unsigned long patchlen;

	unsigned char op;

	GetDlgItemText(hDlg, IDC_EDIT1, buf, 24);
	if (buf[0] != '0') {
		*patch = 0xcc;
		patchlen = 1;
	} else {
		unsigned i=2;
		unsigned char c;
		patchlen = 0;
		while (buf[i] && buf[i+1]) {
			c = buf[i++];
			patch[patchlen] = (c <= '9' ? c - '0' : (c <= 'F' ? c - 'A' + 10 : c - 'a' + 10)) << 4;
			c = buf[i++];
			patch[patchlen++] |= (c <= '9' ? c - '0' : (c <= 'F' ? c - 'A' + 10 : c - 'a' + 10)) & 0xf;
		}
	}

	DWORD oldprot = 0;
	if (!VirtualProtectEx(hRemoteProc, ptr, patchlen, PAGE_EXECUTE_READWRITE, &oldprot)) {
		showlasterror("virtualprotectex");
		return 1;
	}

	if (buf[0] != '0') {
		if (!ReadProcessMemory(hRemoteProc, ptr, &op, 1, 0)) {
			showlasterror("readprocmemory");
			goto err;
		}

		_snprintf(buf, 1024, "Old opcode at 0x%8lX: %.2X", (DWORD)ptr, op);
		addbacklog(buf);
	}
	
	if (!WriteProcessMemory(hRemoteProc, ptr, patch, patchlen, 0))
		showlasterror("writeprocmemory");
	else
		addbacklog("patched");

err:
	if (!VirtualProtectEx(hRemoteProc, ptr, patchlen, oldprot, &oldprot))
		showlasterror("virtualprotectex restore");
	if (!FlushInstructionCache(hRemoteProc, ptr, patchlen))
		showlasterror("flushinstructioncache");

	return 0;
}

int readopcodes(unsigned char *op, void *len)
{
	char buf[1024];
	unsigned char srcbuf[1024];


	_snprintf(buf, 1024, "opcodes at %.8x:", op);

	if (!ReadProcessMemory(hRemoteProc, op, srcbuf, 1024, 0)) {
		showlasterror("readprocessmemory");
		return 1;
	}

	int i=0;
	while (i < (int)len)
		_snprintf(buf+strlen(buf), 1024-strlen(buf), " %.2X", srcbuf[i++]);

	addbacklog(buf);

	return 0;
}

int memoffset(int (*callback)(unsigned char *, void *), void *cb_arg)
{
	/* 
	 * calls callback to inspect the memory of the current target
	 * The offset passed to the callback is either the address in the "proc/addr" field
	 * or the address of the procedure of the library
	 * /!\ The procedure address resolution is done here, not in the remote process
	 */
	char dll[512];
	char proc[512];
	unsigned char *ptr;
	HMODULE hDll = 0;
	int ret = 0;

	GetDlgItemText(hDlg, IDC_EDIT2, proc, 512);
	ptr = (unsigned char*)strtoul(proc, 0, 0);

	if (!ptr) {
			GetDlgItemText(hDlg, IDC_EDIT1, dll, 512);
			hDll = GetModuleHandle(dll);
			if (!hDll)
				hDll = LoadLibrary(dll);
			if (!hDll) {
				showlasterror("loadlibrary");
				return ret;
			}
			ptr = (unsigned char *)GetProcAddress(hDll, proc);
	}

	if (!ptr)
		showlasterror("getprocaddr");
	else
		ret = callback(ptr, cb_arg);
	
	return ret;
}

void dumpmem(void)
{
	char file[128], addr[128], *p;
	unsigned char buf[0x1000];
	char *ptr;
	unsigned long len;
	HANDLE fd;
	DWORD ret;

	GetDlgItemText(hDlg, IDC_EDIT1, file, 128);
	GetDlgItemText(hDlg, IDC_EDIT2, addr, 128);
	ptr = (char *)strtoul(addr, &p, 0);
	while (*p == ',' || *p == ' ')
		p++;
	len = strtoul(p, 0, 0);
	if (!len)
		len = 0x1000;

	if (!ReadProcessMemory(hRemoteProc, ptr, buf, len, &ret)) {
		showlasterror("readprocessmemory");
		return;
	}


	fd = CreateFile(file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_NEW, 0, 0);
	if (fd == INVALID_HANDLE_VALUE) {
		showlasterror("createfile");
		return;
	}

	if (!WriteFile(fd, buf, ret, &ret, 0))
		showlasterror("writefile");

	CloseHandle(fd);

	addbacklog("dumped");
}

struct systable {
	unsigned short unused;
	unsigned short limit;
	unsigned long  base;
};
void show_proc_state(void)
{
	struct systable idt, gdt, ldt, tss;
	unsigned short _cs, _ds, _es, _fs, _gs;
	char buf[128];
	_asm {
		lea eax, idt
		mov dword ptr [eax], 0
		mov dword ptr [eax+4], 0
		add eax, 2
		sidt [eax]

		lea eax, gdt
		mov dword ptr [eax], 0
		mov dword ptr [eax+4], 0
		add eax, 2
		sgdt [eax]

		lea eax, ldt
		mov dword ptr [eax], 0
		mov dword ptr [eax+4], 0
		add eax, 2
		sldt [eax]

		lea eax, tss
		mov dword ptr [eax], 0
		mov dword ptr [eax+4], 0
		add eax, 2
		str [eax]

		mov ax, cs
		mov _cs, ax
		mov ax, ds
		mov _ds, ax
		mov ax, es
		mov _es, ax
		mov ax, fs
		mov _fs, ax
		mov ax, gs
		mov _gs, ax
	}
	_snprintf(buf, 128, "idt: %.4hX %.8X", idt.limit, idt.base);
	addbacklog(buf);
	_snprintf(buf, 128, "gdt: %.4hX %.8X", gdt.limit, gdt.base);
	addbacklog(buf);
	_snprintf(buf, 128, "ldt: %.4hX, tss: %.4hX", ldt.limit, tss.limit);
	addbacklog(buf);
	_snprintf(buf, 128, "cs: %.4hX, ds: %.4hX, es: %.4hX, fs: %.4hX, gs: %.4hX", _cs, _ds, _es, _fs, _gs);
	addbacklog(buf);
}


void CALLBACK benchaslr_server(void);
extern int srvtid;

int misc_handles(u32 id)
{
	switch (id) {
//	case ID_DISABLECSA_IOCTL:
//	case ID_DISABLECSA_SHATTER:

	case ID_TESTASLR:
		if (!srvtid)
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)benchaslr_server, 0, 0, (LPDWORD)&srvtid);
		else
			addbacklog("please wait");
		return TRUE;

	case ID_LISTKMODS:
		listkmods();
		return TRUE;

	case ID_DEV_OPENRO:
		testdevaccess(curdevpathname, 0);
		return TRUE;
	case ID_DEV_OPENRW:
		testdevaccess(curdevpathname, 1);
		return TRUE;

	case ID_PM_D_PM:
	case ID_PM_GG_D_PM:
	case ID_PM_1_PM:
	case ID_PM_2:
	case ID_PM_D_3_PM:
	case ID_PM_D_3_3_3_PM:
	case ID_PM_D_4_1_PM:
	case ID_PM_LD_4_1_PM:
	case ID_HD_D_HD_P:
	case ID_HD_6:
	case ID_HD_7:
	case ID_HD_GG_7:
	case ID_DEV_CLEANLINKS:
		initdevpath(id);
		return TRUE;

	case ID_DBGPRIV:
		get_dbgpriv();
		return TRUE;

	case ID_DBG_DUMPMEM:
		dumpmem();
		return TRUE;

	case ID_SHOWPROCSTATE:
		show_proc_state();
		return TRUE;

	case ID_DBG_LISTALLHOOKS:
		listallhooks();
		return TRUE;
	case ID_DBG_LISTHOOKSLIB:
		listhookslib(0);
		return TRUE;
	case ID_DBG_UNHOOKLIB:
		listhookslib(1);
		return TRUE;
	case ID_DBG_UNHOOKLIBEX:
		listhookslib(2);
		return TRUE;

	case ID_DBG_SHOWOPCODES:
		memoffset(readopcodes, (void *)8);
		return TRUE;
	case ID_DBG_INT3:
		memoffset(breakthere, 0);
		return TRUE;

	case ID_TARGET_BYPID:
		changetarget(0);
		return TRUE;
	case ID_TARGET_BYMOUSE:
		changetarget(1);
		return TRUE;
	}
	return FALSE;
}

void misc_init(void)
{
	srvtid = 0;
	PEbase = GetModuleHandle(0);
	initdevpath(ID_DEV_CLEANLINKS);
}
