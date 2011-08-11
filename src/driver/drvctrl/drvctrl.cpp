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

#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <stdio.h>

#include "Resource.h"
#if 0
#include "ntstatus.h"
#endif

HWND hDlg;
HINSTANCE hInstance;

#define DRVNAME "testdrv"

void log(char *str) {
	MessageBox(hDlg, str, "log", 0);
}

void log_err(char *str) {
	char buf[1024];
	strncpy(buf, str, 1021);
	buf[1021] = 0;
	strcat(buf, ": ");
	int bla = (int)strlen(buf);

	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, buf + bla, 1024 - bla, 0))
		log(buf);
	else
		log(str);
}


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef long NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define getnativeprocaddress(name) t_##name name = (t_##name)GetProcAddress(GetModuleHandle("ntdll.dll"), #name)
typedef ULONG    (__stdcall *t_RtlNtStatusToDosError)(NTSTATUS);
#define log_nterr(base) do { getnativeprocaddress(RtlNtStatusToDosError); SetLastError(RtlNtStatusToDosError(ntstatus)); log_err(base); } while (0)

int loaddriver_undoc(void)
{
	char path[512];
	char *ptr = path+4;
	memset(path, 0, 512);

	GetDlgItemText(hDlg, IDC_EDIT1, ptr, 508);

	if (*ptr != '\\') {
		ptr = path;
		path[0] = path[3] = '\\';
		path[1] = path[2] = '?';
	}

	typedef long(__stdcall *setinfo)(int, PUNICODE_STRING, int);
	setinfo fptr = (setinfo)GetProcAddress(LoadLibrary("ntdll"), "ZwSetSystemInformation");

	wchar_t ustr_buf[512];
	memset(ustr_buf, 0, sizeof(ustr_buf));

	UNICODE_STRING ustr;
	ustr.MaximumLength = sizeof(ustr_buf);
	ustr.Length = 0;
	ustr.Buffer = ustr_buf;
	int i;

	for (i=0 ; (i < (sizeof(ustr_buf)/sizeof(*ustr_buf)) && ptr[i]) ; i++)
		ustr_buf[i] = ptr[i];

	ustr.Length = 2*i;

	NTSTATUS ntstatus = 0;
	if (fptr) {
		ntstatus = fptr(38, &ustr, sizeof(ustr));
		if (!NT_SUCCESS(ntstatus)) {
			log_nterr("zwsetsysinfo thing");
		}
	}
	return ntstatus;
}

void createdriver_std(void)
{
	char path[500];
	GetDlgItemText(hDlg, IDC_EDIT1, path, 500);

	SC_HANDLE sh, rh;

	if (!(sh = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS))) {
		log_err("open SCM");
		goto err;
	}

	if (!(rh = CreateService(sh, DRVNAME, DRVNAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path, 0, 0, 0, 0, 0)))
		log_err("create service");

	CloseServiceHandle(rh);
err:
	CloseServiceHandle(sh);
}

void deletedriver_std()
{
	SC_HANDLE sh, rh;

	if (!(sh = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS))) {
		log_err("open SCM");
		goto err;
	}

	if (!(rh = OpenService(sh, DRVNAME, SERVICE_ALL_ACCESS))) {
		log_err("open service");
		goto err;
	}

	if (!DeleteService(rh))
		log_err("delete service");

	CloseServiceHandle(rh);
err:
	CloseServiceHandle(sh);
}

void loaddriver_std(void)
{
	char path[500];
	GetDlgItemText(hDlg, IDC_EDIT1, path, 500);

	SC_HANDLE sh, rh;

	if (!(sh = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS))) {
		log_err("open SCM");
		goto err;
	}

	if (!(rh = OpenService(sh, DRVNAME, SERVICE_ALL_ACCESS))) {
		log_err("open service");
		goto err;
	}

	if (!StartService(rh, 0, 0))
		log_err("start service");

	CloseServiceHandle(rh);
err:
	CloseServiceHandle(sh);
}

void unloaddriver_std()
{
	SC_HANDLE sh, rh;

	if (!(sh = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS))) {
		log_err("open SCM");
		goto err;
	}

	if (!(rh = OpenService(sh, DRVNAME, SERVICE_ALL_ACCESS))) {
		log_err("open service");
		goto err;
	}

	SERVICE_STATUS st;
	if (!ControlService(rh, SERVICE_CONTROL_STOP, &st))
		log_err("stop service");

	CloseServiceHandle(rh);
err:
	CloseServiceHandle(sh);
}

#include "imagehlp.h"
void fix_checksum()
{
	char path[500];
	unsigned long cksum, oldcksum;
	DWORD ret;
	HANDLE fd;
	unsigned long offset;
	HMODULE hDll;

	typedef DWORD (__stdcall *mapck)(PTSTR, PDWORD, PDWORD);
	mapck fptr;

	if (!(hDll = LoadLibrary("imagehlp"))) {
		log_err("loadlibrary imagehlp");
		return;
	}
	
	if (!(fptr = (mapck)GetProcAddress(hDll, "MapFileAndCheckSumA"))) {
		log_err("getprocaddr mapfileandchecksum");
		FreeLibrary(hDll);
		return;
	}

	GetDlgItemText(hDlg, IDC_EDIT1, path, 500);

	ret = fptr(path, &oldcksum, &cksum);

	FreeLibrary(hDll);

	switch (ret) {
	case CHECKSUM_SUCCESS:
		break;
	case CHECKSUM_MAP_FAILURE:
		log("Could not map the file");
		return;
	case CHECKSUM_MAPVIEW_FAILURE:
		log("Could not map a view of the file");
		return;
	case CHECKSUM_OPEN_FAILURE:
		log("Could not open the file");
		return;
	case CHECKSUM_UNICODE_FAILURE:
		log("Could not convert the file name to Unicode");
		return;
	}

	fd = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
		0, OPEN_EXISTING, 0, 0);
	if (fd == INVALID_HANDLE_VALUE) {
		log_err("createfile");
		return;
	}

	SetFilePointer(fd, 0x3c, 0, FILE_BEGIN);
	if (!ReadFile(fd, &offset, 4, &ret, 0)) {
		log_err("readfile pe offset");
		goto err;
	}
	offset += 0x58;

#if 1
	unsigned long curcksum = 0;
	SetFilePointer(fd, offset, 0, FILE_BEGIN);
	if (!ReadFile(fd, &curcksum, 4, &ret, 0)) {
		log_err("readfile cur ck");
		goto err;
	}

	if (curcksum != oldcksum) {
		log("the current checksum is not the one returned by imagehlp");
		goto err;
	}

	if (curcksum == cksum) {
		log("nothing to do");
		goto err;
	}
#endif

	char buf[128];
	_snprintf(buf, 128, "updating checksum from %.8lX to %.8lX", oldcksum, cksum);
	log(buf);

	SetFilePointer(fd, offset, 0, FILE_BEGIN);
	if (!WriteFile(fd, &cksum, 4, &ret, 0)) {
		log_err("writefile new ck");
		goto err;
	}

err:
	CloseHandle(fd);
}

void chosefile(void)
{
	OPENFILENAME ofn;
	char filter[80] = "drivers (*.sys)\0*.sys\0exe (*.exe, *.dll)\0*.exe;*.dll\0all files (*.*)\0*.*\0\0";
	char filename[500] = {0};

	memset(&ofn, 0, sizeof(ofn));

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hDlg;
	ofn.hInstance = hInstance;
	ofn.lpstrFilter = filter;
	ofn.lpstrFile = filename;
	ofn.nMaxFile = 500;
	ofn.Flags = OFN_DONTADDTORECENT | OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST |
		OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
	if (GetOpenFileName(&ofn))
		SetDlgItemText(hDlg, IDC_EDIT1, filename);
}

#include <stdio.h>

void log_syscallname(HANDLE logfd, unsigned sysnr)
{
	PUCHAR base = (PUCHAR)GetModuleHandle("ntdll.dll");
	if (!base)
		return;

	DWORD ret;

	unsigned *exptbl;
	unsigned exp_nn;
	unsigned *expname;
	unsigned *expfn;
	unsigned short *expord;
	unsigned i;

	exptbl = (unsigned*)(base + (*(unsigned*)(base+0x3c)) + 4 + 0x14 + 0x60);
	if (!exptbl[1])	// exportdir->size
		return;
	exptbl = (unsigned*)(base + exptbl[0]);

	exp_nn = exptbl[6];
	expfn = (unsigned*)(base+exptbl[7]);
	expname = (unsigned*)(base+exptbl[8]);
	expord = (unsigned short*)(base+exptbl[9]);

	for (i=0 ; i<exp_nn ; i++) {
		unsigned off = expfn[expord[i]];
		unsigned syscallnum;
		if (base[off] == 0xb8 && base[off+5] == 0xba && *(unsigned*)(base+off+6) == 0x7ffe0300) {
			syscallnum = *(unsigned*)(base+off+1);
			if (syscallnum == sysnr) {
				WriteFile(logfd, base+expname[i], strlen((char*)base+expname[i]), &ret, 0);
				WriteFile(logfd, ":\r\n", 3, &ret, 0);
			}
		}
	}
}

void interact_driver(void)
{
	HANDLE fd, logfd;
	unsigned blen = 256;
	unsigned char buffer[256];
	DWORD ret;

//	unsigned param;
//	param = GetDlgItemInt(hDlg, IDC_EDIT1, 0, 0);

	fd = CreateFile("\\\\.\\jj", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
	if (fd == INVALID_HANDLE_VALUE) {
		log_err("createfile");
		return;
	}

	logfd = CreateFile("SDTdump.txt", GENERIC_WRITE, 0, 0, OPEN_ALWAYS, 0, 0);
	if (logfd == INVALID_HANDLE_VALUE) {
		CloseHandle(fd);
		log_err("createlogfile");
		return;
	}

	unsigned i, sdt_nument;

	sdt_nument = -1;

	if (!ReadFile(fd, &sdt_nument, sizeof(unsigned), &ret, 0))
		log_err("readfile_numsdt");
	else

	for (i=0 ; i<sdt_nument ; i++) {
		memset(buffer, 0, blen);
		*(unsigned*)buffer = i;

		if (!ReadFile(fd, buffer, blen, &ret, 0)) {
			log_err("readfile");
			break;
		}
        
		char str[256];

		log_syscallname(logfd, i);

		_snprintf(str, 256, "sdt[%.3d] = %.8lX", i, *(unsigned*)buffer);
		if (buffer[4])
			_snprintf(str+strlen(str), 256-strlen(str), " => module %s @ %.8lX",
					buffer+4, *(unsigned*)(buffer+4+strlen((char*)buffer+4)+1));
		WriteFile(logfd, str, strlen(str), &ret, 0);
		WriteFile(logfd, "\r\n\r\n", 4, &ret, 0);
	}

	CloseHandle(logfd);
	CloseHandle(fd);
}

LRESULT CALLBACK WinProc(HWND hDlgx, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
	{
	case WM_INITDIALOG:
		hDlg = hDlgx;
		SetDlgItemText(hDlg, IDC_EDIT1, "C:\\jjdriver.sys");
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case 2:
		case IDC_QUIT:
			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;

		case IDC_OPEN:
			chosefile();
			return TRUE;

		case IDC_INSTALL:
			createdriver_std();
			return TRUE;
		case IDC_START:
			loaddriver_std();
			return TRUE;
		case IDC_STOP:
			unloaddriver_std();
			return TRUE;
		case IDC_UNINSTALL:
			deletedriver_std();
			return TRUE;

		case IDC_TEST:
			interact_driver();
			return TRUE;

		case IDC_HACK:
			loaddriver_undoc();
			return TRUE;

		case IDC_CKSUM:
			fix_checksum();
			return TRUE;
		}
	}
	return FALSE;
}

int APIENTRY WinMain(HINSTANCE hInstancex, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	hInstance = hInstancex;
	return (int)DialogBox(hInstance, (LPCSTR)IDD_WIN, 0, (DLGPROC)WinProc);
}
