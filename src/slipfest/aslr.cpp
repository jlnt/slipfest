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

/*
 * Address space randomization test module
 */
struct aslrinfo_thread {
	u32 teb;
	u32 stackbase;
};
#define NR_THREAD_MAX 64
struct aslrinfo {
	// process
	u32 peb;
	u32 stack;
	u32 heap;
	u32 base;
	u32 ntdll;
	u32 kernel;
	u32 dll;
	// thread
	struct aslrinfo_thread thread[NR_THREAD_MAX];
};

struct benchaslr_thread_struct {
	struct aslrinfo_thread *info;
	volatile u32 done;
	volatile u32 *canend;
};


/* testing thread in a testing process */
void benchaslr_client_thread(struct benchaslr_thread_struct *ti)
{
	PTEB teb;
	_asm {
		mov eax, fs:[0x18]
		mov [teb], eax
	}
	ti->info->teb = (u32)teb;
	ti->info->stackbase = (u32)teb->Tib.StackBase;
	if (ti->canend) {
		while (!*ti->canend)
			SwitchToThread();
	}
	ti->done = 1;
	ExitThread(0);
}

/* testing process */
void benchaslr_client(char *arg)
{
	struct aslrinfo i;
	HANDLE mystdout;
	PTEB teb;
	u32 stack;
	DWORD ret, max, cur, threadcount = 0;
	HMODULE ntdll, kernel, dll;
	char *dllname;

	while (*arg && *arg == ' ')
		arg++;
	threadcount = strtoul(arg, &arg, 0);
	if (!threadcount)
		threadcount = 4;
	if (threadcount > NR_THREAD_MAX)
		threadcount = NR_THREAD_MAX;

	while (*arg && *arg == ' ')
		arg++;
	if (*arg)
		dllname = arg;
	else
		dllname = "ws2_32";

	_asm {
		mov eax, fs:[0x18]
		mov [teb], eax
		mov [stack], esp
	}
	
	i.peb =		(u32)teb->Peb;
	i.stack =	stack;
	i.heap =	(u32)teb->Peb->ProcessHeap;
	i.base =	(u32)teb->Peb->ImageBaseAddress;

	ntdll = LoadLibrary("ntdll");
	kernel = LoadLibrary("kernel32");
	dll = LoadLibrary(dllname);

	i.ntdll =	(u32)ntdll;
	i.kernel =	(u32)kernel;
	i.dll =		(u32)dll;

	FreeLibrary(dll);
	FreeLibrary(kernel);
	FreeLibrary(ntdll);

	i.thread[0].teb =		(u32)teb->Tib.Self;
	i.thread[0].stackbase =	(u32)teb->Tib.StackBase;

	struct benchaslr_thread_struct ti[NR_THREAD_MAX];
	u32 tidx;
	
	for (tidx = 1 ; tidx < threadcount ; tidx++) {
		i.thread[tidx].teb = i.thread[tidx].stackbase = 0;
		ti[tidx].info = &i.thread[tidx];
		ti[tidx].done = 0;
		/* arrange for the threads to run in parallel */
		ti[tidx].canend = ((tidx == (threadcount-1)) ? 0 : &ti[tidx+1].done);
	}
	for (tidx = 1 ; tidx < threadcount ; tidx++)
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)benchaslr_client_thread, (void *)&ti[tidx], 0, 0);

	while (!ti[1].done)
		SwitchToThread();

	mystdout = GetStdHandle(STD_OUTPUT_HANDLE);
	max = sizeof(i);
	cur = 0;

	while (cur < max && WriteFile(mystdout, (char *)&i + cur, max-cur, &ret, 0))
		cur += ret;

	CloseHandle(mystdout);
}


/* master process, spawns one tester */
struct aslrinfo *benchaslr_1child(u32 nthreads, char *library)
{
	static struct aslrinfo i;
	PROCESS_INFORMATION pi;
	STARTUPINFO startupinfo;
	HANDLE mypipe, yourpipe;
	SECURITY_ATTRIBUTES saAttr; 
	char myname[1024], cmdline[1024];
	DWORD ret;

	/* create pipe */
	saAttr.nLength = sizeof(saAttr);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&mypipe, &yourpipe, &saAttr, 0)) {
		showlasterror("createpipe");
		return 0;
	}

	SetHandleInformation(mypipe, HANDLE_FLAG_INHERIT, 0);

	/* create child */
	memset(&startupinfo, 0, sizeof(startupinfo));
	startupinfo.cb = sizeof(startupinfo);
	startupinfo.dwFlags = STARTF_USESTDHANDLES;
	startupinfo.hStdOutput = yourpipe;

	if (!GetModuleFileName(0, myname, 1024)) {
		showlasterror("getmodulefilename");
		return 0;
	}
	_snprintf(cmdline, 1024, "slipfest benchaslr %lu %s", nthreads, library);

	if (!CreateProcess(myname, cmdline, 0, 0, 1, 0, 0, 0, &startupinfo, &pi)) {
		showlasterror("createprocess");
		return 0;
	}
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(yourpipe);

	/* read data */
	DWORD cur = 0;
	while (cur < sizeof(i) && ReadFile(mypipe, (char *)&i + cur, sizeof(i)-cur, &ret, 0) && ret)
		cur += ret;

	CloseHandle(mypipe);

	if (cur != sizeof(i)) {
		showlasterror("child read error");
		return 0;
	}
	return &i;
}

/* callback to update the status line */
int aslr_cur, aslr_tot;
void CALLBACK aslrtimerproc(HWND hWnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
	if (aslr_cur >= aslr_tot)
		return;
	char buf[128];
	_snprintf(buf, 128, "aslr: %d/%d...", aslr_cur, aslr_tot);
	SetDlgItemText(hDlg, IDC_STATUS, buf);
}


int srvtid;
/* master function, calls create_1child and process/show the results */
void CALLBACK benchaslr_server(void)
{
	u32 nproc, nthread;
	u32 i, j;
	struct aslrinfo *cur, base, mask, min, max;
	char library[128];
	char numbers[128], *n;

	GetDlgItemText(hDlg, IDC_EDIT1, library, 128);
	GetDlgItemText(hDlg, IDC_EDIT2, numbers, 128);
	n = numbers;

	nproc = strtoul(n, &n, 0);
	while (*n == ',' || *n == ' ')
		n++;
	nthread = strtoul(n, 0, 0);

	if (!strcmp(library, "kernel32") || !strcmp(library, "ntdll"))
		strcpy(library, "ws2_32");
	if (!nproc)
		nproc = 200;
	if (!nthread)
		nthread = 4;
	if (nthread > NR_THREAD_MAX)
		nthread = NR_THREAD_MAX;

	/* hail to the portability */
	u32 *baseu32 = (u32*)&base, *masku32 = (u32*)&mask, *minu32 = (u32*)&min, *maxu32 = (u32*)&max, *curu32;
	u32 max32;
	max32 = ((char*)&base.thread[nthread] - (char*)&base)/sizeof(u32);

	showstatuswindow();
	SetTimer(hDlg, 10, 200, aslrtimerproc);
	aslr_tot = nproc;

	for (i=0 ; i<nproc ; i++) {
		aslr_cur = i;

//		if (!(i&0xFF))
//			Sleep(200);			// may help detect time-based randomisation

		cur = benchaslr_1child(nthread, library);
		if (!cur || terminating)
			goto err;

		if (!i) {
			/* init */
			memcpy(&base, cur, sizeof(base));
			memset(&mask,   0, sizeof(mask));
			memcpy(&min, cur, sizeof(base));
			memcpy(&max, cur, sizeof(base));
		} else {
			/* update */
			curu32 = (u32*)cur;
			for (j=0 ; j<max32 ; j++) {
				masku32[j] |= (baseu32[j] & ~masku32[j]) ^ (curu32[j] & ~masku32[j]);
				if (minu32[j] > curu32[j])
					minu32[j] = curu32[j];
				if (maxu32[j] < curu32[j])
					maxu32[j] = curu32[j];
			}
		}
	}

	char buf[1024];

	_snprintf(buf, 1024, "ASLR test results, %d proc, %d threads, library %s:", nproc, nthread, library);
	addbacklog(buf);

	addbacklog(" values   " "  " " common " "   " "changing" "   " "  min   " "   " "  max   ");
	addbacklog("--");
#define SHOWDIFF(fld, name) \
	_snprintf(buf, 1024, name ": %.8lX | %.8lX | %.8lX | %.8lX ", \
	base.fld & ~mask.fld, mask.fld, min.fld, max.fld); \
	addbacklog(buf);
#define SHOWDIFF_T(idx, fld, name) \
	_snprintf(buf, 1024, "t%.2d " name ": %.8lX | %.8lX | %.8lX | %.8lX ", idx, \
	base.thread[idx].fld & ~mask.thread[idx].fld, mask.thread[idx].fld, min.thread[idx].fld, max.thread[idx].fld); \
	addbacklog(buf);

	SHOWDIFF(peb,    "PEB       ")
	SHOWDIFF(stack,  "stack     ")
	SHOWDIFF(heap,   "heap      ")
	SHOWDIFF(base,   "image     ")
	SHOWDIFF(ntdll,  "ntdll     ")
	SHOWDIFF(kernel, "kernel32  ")
	SHOWDIFF(dll,    "other dll ")
	addbacklog("--");
	for (i=0 ; i<nthread ; i++) {
		SHOWDIFF_T(i, teb,		 "teb   ")
		SHOWDIFF_T(i, stackbase, "stack ")

		mask.thread[0].teb |=  mask.thread[i].teb;
		if (min.thread[0].teb > min.thread[i].teb)
			min.thread[0].teb = min.thread[i].teb;
		if (max.thread[0].teb < max.thread[i].teb)
			max.thread[0].teb = max.thread[i].teb;

		mask.thread[0].stackbase |=  mask.thread[i].stackbase;
		if (min.thread[0].stackbase > min.thread[i].stackbase)
			min.thread[0].stackbase = min.thread[i].stackbase;
		if (max.thread[0].stackbase < max.thread[i].stackbase)
			max.thread[0].stackbase = max.thread[i].stackbase;
	}

	addbacklog("--");
	_snprintf(buf, 1024, "tot teb   : %.8lX | %.8lX | %.8lX | %.8lX ",
	base.thread[0].teb & ~mask.thread[0].teb, mask.thread[0].teb, min.thread[0].teb, max.thread[0].teb);
	addbacklog(buf);
	_snprintf(buf, 1024, "tot stack : %.8lX | %.8lX | %.8lX | %.8lX ",
	base.thread[0].stackbase & ~mask.thread[0].stackbase, mask.thread[0].stackbase, min.thread[0].stackbase, max.thread[0].stackbase);
	addbacklog(buf);

	for (j=0 ; j<max32 ; j++) {
	}

#undef SHOWDIFF_T
#undef SHOWDIFF

	addbacklog(" ");

err:
	KillTimer(hDlg, 10);
	hidestatuswindow();

	srvtid = 0;
}
