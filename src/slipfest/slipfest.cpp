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


/*
 * TODO: modularize (.dll)
 * make a real user interface
 * make something useable without patching the source
 */

#include "stdafx.h"

#define VERSION "1.05 beta"

HWND hDlg;
HANDLE hRemoteProc;
int terminating;

/*
 * log
 */
#define BK_LINE_SZ 256
#define BK_LINE_CNT 256
#define LOG_LINELEN 8192
char backlog[BK_LINE_CNT][BK_LINE_SZ];
int backlog_next;
int backlog_view = 256;

void initbacklog(void)
{
	int i;
	for (i=0 ; i<BK_LINE_CNT ; i++)
		backlog[i][0] = 0;
	backlog_next = 0;
}

void showbacklog(int nr) {
	static char buf[LOG_LINELEN];
	int start, end, bptr;

	if (nr <= 0)
		return;
	if (nr > BK_LINE_CNT)
		nr = BK_LINE_CNT;

	if (!backlog[0][0]) {
		SetWindowText(GetDlgItem(hDlg, IDC_LOG), "");
		return;
	}

	bptr = 0;
	start = backlog_next - 1;
	if (start < 0)
		start += BK_LINE_CNT;
	end = start - nr;
	if (end < 0)
		end += BK_LINE_CNT;

	do {
		if (!backlog[start][0])
			break;

		bptr += strlen(backlog[start--]) + 2;
		if (start < 0)
			start += BK_LINE_CNT;

		if (bptr >= LOG_LINELEN) {
			start = (start+1) % BK_LINE_CNT;
			break;
		}
	} while (start != end);
	start = (start+1) % BK_LINE_CNT;

	bptr = 0;
	end = backlog_next - 1;
	if (end < 0)
		end += BK_LINE_CNT;
	do {
		start %= BK_LINE_CNT;
		strcpy(buf+bptr, backlog[start]);
		bptr += strlen(buf+bptr);
		buf[bptr++] = '\r';
		buf[bptr++] = '\n';
		buf[bptr] = '\0';
	} while (start++ != end);

	if (bptr > LOG_LINELEN)
		bptr = bptr;

	void showlasterror(char *);
	if (!SetWindowText(GetDlgItem(hDlg, IDC_LOG), buf)) {
		backlog_next = 0;
		backlog[0][0] = 0;
		showlasterror("setwintext");
	}
}

void addbacklog(char *str) {
	strncpy(backlog[backlog_next], str, BK_LINE_SZ);
	backlog[backlog_next++][BK_LINE_SZ-1] = 0;
	backlog_next %= BK_LINE_CNT;

	showbacklog(backlog_view);
	SendMessage(GetDlgItem(hDlg, IDC_LOG), EM_LINESCROLL, 0, 500);
}

void showlasterror(char *title)
{
	char buf[1024];
	strncpy(buf, title, 1021);
	buf[1021] = 0;
	strcat(buf, ": ");
	int bla = (int)strlen(buf);

	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, buf + bla, 1024 - bla, 0))
		addbacklog(buf);
	else
		addbacklog("!! FormatMessage error :/");
}

void log_save(void)
{
	if (!backlog[0][0])
		return;

	char buf[512] = "";
	HANDLE fd;
	DWORD ret;

	OPENFILENAME ofn;
	char filter[] = "log files (*.log)\0*.log\0all files (*.*)\0*.*\0\0";

	memset(&ofn, 0, sizeof(ofn));

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hDlg;
	ofn.lpstrFilter = filter;
	ofn.lpstrFile = buf;
	ofn.nMaxFile = 512;
	ofn.Flags = OFN_DONTADDTORECENT | OFN_PATHMUSTEXIST |
		OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
	if (!GetSaveFileName(&ofn))
		return;

	fd = CreateFile(buf, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, 0, 0);
	if (fd == INVALID_HANDLE_VALUE) {
		showlasterror("createlog");
		return;
	}

	int i = backlog_next;
	if (!backlog[i][0])
		i = 0;
	do {
		WriteFile(fd, backlog[i], strlen(backlog[i]), &ret, 0);
		WriteFile(fd, "\r\n", 2, &ret, 0);
		i = (i+1) % BK_LINE_CNT;
	} while (i != backlog_next);

	CloseHandle(fd);
}


/*
 * PE Module exploration
 */
u32 rva2rva(struct exe_header *e, u32 rva, u32 size)
{
	(void)e;
	(void)size;
	return rva;
}

u32 rva2va(struct exe_header *e, u32 rva, u32 size)
{
	struct image_section_header *s = e->sect + e->ihdr->number_of_sections;

	// TODO [s->rva .... s->rva + s->sz ..[fall here = zero-padded space].. s->rva + s->vsz]
	while (s-- > e->sect)
		if (s->virtual_address <= rva && s->virtual_address + s->size_of_raw_data >= rva + size)
			return s->pointer_to_raw_data + rva - s->virtual_address;
	
	return 0;
}

u32 rva2va_text(struct exe_header *e, u32 rva, u32 size)
{
	char target[8] = ".text\0\0";
	struct image_section_header *s = e->sect, *end = e->sect + e->ihdr->number_of_sections;

	while (s < end)
		if (!memcmp(s->name, target, 8) && s->virtual_address <= rva && s->virtual_address +
				s->size_of_raw_data >= rva + size)
			return s->pointer_to_raw_data + rva - s->virtual_address;
		else
			s++;

	return 0;
}

/* checks if a rva may be subject to relocation based on the relocation table of the PE */
int isrelocated(struct exe_header *e, u32 rva)
{
	if (!e->relocs)
		return 0;

	int i, imax;
	struct image_base_relocation *reloc = e->relocs, *reloc_end = (struct image_base_relocation *)(
			(u8*)e->relocs + e->dir[5].size);

	while (reloc < reloc_end) {
		if (rva >= reloc->virtual_address && rva < reloc->virtual_address + 0xFFF) {
			imax = (reloc->size_of_block - 8) / 2;
			for (i=0 ; i<imax ; i++) {
				u32 offset = reloc->virtual_address + reloc->reloc[i].offset;
				switch (reloc->reloc[i].type) {
				case 11:
					/* 3-slot reloc, offset to 16 bits fields */
					i++;
				case 4:
					/* 2-slot reloc, offset to 16 bits fields */
					i++;
				case 1: case 2:
					/* offset points to 16 bits field */
					if (offset >= rva-1 && offset < rva+4)
						return 1;
					break;
				case 3:
					/* offset points to 32 bits field */
					/* may check that adding to the low word changes the high word... */
					if (offset >= rva-3 && offset < rva+4)
						return 1;
					break;
				case 10:
					/* offset points to 64 bits field */
					if (offset >= rva-7 && offset < rva+4)
						return 1;
				case 0:
					/* nop */
					break;
				default:
					addbacklog("invalid relocation type");
					return 0;
				}
			}
		}
		if (!reloc->size_of_block) {
			addbacklog("invalid reloc information");
			return 0;
		}
		reloc = (struct image_base_relocation *)(((u32)reloc + reloc->size_of_block + 3) & ~3);
	}
	return 0;
}

/* 
 * loads a PE structure
 * set file = 1 for a file,
 * set file = 0 for a memory image
 */
int loadpe(struct exe_header *e, u8 *mem, int file)
{
	u32 (*to_va)(struct exe_header *, u32, u32) = file ? rva2va : rva2rva;
	u32 num_rva;

	/* read PE */
	e->dhdr = (struct dos_header *)mem;
	if (e->dhdr->e_magic != IMAGE_MZ_SIGNATURE) {
		addbacklog("Invalid MZ signature");
		return 0;
	}

	e->pesig = (u32 *)(mem + e->dhdr->e_lfanew);
	if (*e->pesig != IMAGE_PE_SIGNATURE) {
		addbacklog("Invalid PE signature");
		return 0;
	}

	e->ihdr = (struct image_file_header *)(e->pesig + 1);
	e->ohdr = (struct image_optional_header *)(e->ihdr + 1);
	e->ohdr_plus = 0;
	e->dir  = (struct image_directory *)((u8 *)e->ohdr + sizeof(*e->ohdr));
	e->sect = (struct image_section_header *)((u8 *)e->ohdr + e->ihdr->size_of_optional_header);

	switch (e->ohdr->magic) {
	case IMAGE_OPTIONAL_HDR32_MAGIC_PLUS:
		e->ohdr_plus = (struct image_optional_header_plus *)e->ohdr;
		e->dir = (struct image_directory *)((u8 *)e->ohdr_plus + sizeof(*e->ohdr_plus));
	
	case IMAGE_OPTIONAL_HDR32_MAGIC:
	case IMAGE_OPTIONAL_HDR32_MAGIC_ROM:
		break;

	default:
		addbacklog("Invalid optional PE header signature");
		return 0;
	}

	if (e->ohdr_plus)
		num_rva = e->ohdr_plus->number_of_rva_and_sizes;
	else
		num_rva = e->ohdr->number_of_rva_and_sizes;

	/* get pointer to export directory */
	if (num_rva < 1 || !e->dir[0].size)
		e->exports.directory = 0;
	else {
		/* get pointers to exports */
		e->exports.directory = (struct image_export_directory *)(mem + to_va(e, e->dir[0].rva, e->dir[0].size));
		e->exports.name      = (char *)(mem + to_va(e, e->exports.directory->name, 4));
		e->exports.functions =  (u32 *)(mem + to_va(e, e->exports.directory->address_of_functions, 4));
		e->exports.names     =  (u32 *)(mem + to_va(e, e->exports.directory->address_of_names, 4));
		e->exports.ordinals  =  (u16 *)(mem + to_va(e, e->exports.directory->address_of_name_ordinals, 4));
	}

	/* get pointer to import data */
	if (num_rva < 2 || !e->dir[1].size)
		e->imports = 0;
	else {
		e->imports = (struct image_import_descriptor *)(mem + to_va(e, e->dir[1].rva, e->dir[1].size));
	}

	/* get pointer to reloc table */
	if (num_rva < 6 || !e->dir[5].size)
		e->relocs = 0;
	else
		e->relocs = (struct image_base_relocation *)(mem + to_va(e, e->dir[5].rva, e->dir[5].size));

	return 1;
}

int status_clients = 0;
void showstatuswindow(void)
{
	if (!status_clients++) {
		RECT rect;
		long status_height;
		HWND status = GetDlgItem(hDlg, IDC_STATUS);

		GetWindowRect(status, &rect);
		status_height = rect.bottom - rect.top;

		ShowWindow(status, SW_SHOW);

		GetWindowRect(hDlg, &rect);
		MoveWindow(hDlg, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top + status_height, TRUE);

	}
}

void hidestatuswindow(void)
{
	if (!--status_clients) {
		RECT rect;
		long status_height;
		HWND status = GetDlgItem(hDlg, IDC_STATUS);

		GetWindowRect(status, &rect);
		status_height = rect.bottom - rect.top;

		ShowWindow(status, SW_HIDE);

		GetWindowRect(hDlg, &rect);
		MoveWindow(hDlg, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top - status_height, TRUE);
	}
}

void about(void)
{
//	DWORD himage = 0;
//	SendMessage(0, STM_SETIMAGE, IMAGE_BITMAP, himage);
	static char *amsg =
		"HIPS evaluation framework for Windows IA32\n\n"
		"Version "VERSION"\n\n"
		"(C) 2005-2006 Yoann Guillot, Julien Tinnes\n\n"
		"SLIPFEST comes with ABSOLUTELY NO WARRANTY\n\n"
		"This is free software, and you are welcome to\n"
		"redistribute it under the conditions of the GPL v2\n" 
//		"Deposed under IDDN.FR.001.080034.000.S.P.2006.000.10800"
;
	MessageBox(hDlg, amsg, "SLIPFEST v" VERSION, MB_ICONINFORMATION);
}

void help(void)
{
	static char *hmsg =
" - ASLR:\n"
"Specify the additional library in 'dll' and the number of processes and threads in 'proc' (default: \"200, 4\").\n"
"\n"
" - Hooks:\n"
"Detected with a diff between the loaded PE and the dll file on disk. You can define the number of bytes to look at (for each exported entry) in 'proc' (default: \"5\").\n"
"Dump memory: dumps the len or 0x1000 bytes from the target process, starting at the address addr. 'proc' receives \"addr, len\", 'dll' receives the dump filename.\n"
"Patch memory: patches the target process's memory at addr 'dll!proc' or 'proc' if it is a number, with the binary string found in 'dll' (ex: \"0x123456789abcdef012\" - useful to remove hooks selectively) (default: \"0xCC\").\n"
"\n"
" - Shellcodes:\n"
"Select a target by pid (0 shows a list) or by mouse (timeout in 'proc' - default \"1000\"ms): put the cursor above a window owned by the desired target.\n"
"The selected shellcode will be copied into a buffer (VirtualAllocEx & WriteProcessMemory) and ran (CreateRemoteThread).\n"
"If ran from the stack, a loader is prepended to the shellcode, to copy it to the stack and run it.\n"
"The shellcodes will crash the target if they do not find the functions they need / if the target does not map kernel32.\n"
"The fake retaddr shellcode scans memory for the selected pattern from a base adress, and it will crash the target process if it does not find what it wants.\n"
"In a remote process, the base address is either k32 or the PE.\n"
"From the stack of the current process, the base address is chosen from the list, and the target zone is patched to ensure the opcodes are found.\n"
"CreateReplace will launch a new instance of internet explorer in suspended state, and replace the code at its entry point with the getcmdline shellcode. Useful to test if you can use iexplore when openprocess is blocked.\n"
"\n"
;

	MessageBox(hDlg, hmsg, "System Level Intrusion Prevention Framework Evaluation Suite and Toolkit", 0);
}

/*
 * Windows interface
 */
/*
void CALLBACK mousetimerproc(HWND hWnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
	static double x = -1, dx = 0, y = -1, dy = 0, cdx = 0, cdy = 0, ccnt = 0;
	double glue = 99;
	HDC hdc;
	POINT cpos;

	hdc = GetDC(hWnd);
	SetROP2(hdc, R2_NOT);

	MoveToEx(hdc, x, y, 0);
	LineTo(hdc, x + 1, y);
	GetCursorPos(&cpos);

	if (ccnt) {
		SetCursorPos(cpos.x + cdx/30, cpos.y + cdy/30);
		cdx *= 0.8;
		cdy *= 0.8;
		ccnt--;
		GetCursorPos(&cpos);
	}

	ScreenToClient(hDlg, &cpos);

	x += dx / 100;
	y += dy / 100;
	if (abs(x - cpos.x) < 2 && abs(y - cpos.y) < 2)
		if (abs(dx) > 2 || abs(dy) > 2) {
			cdx = dx;
			cdy = dy;
			ccnt = 6;
			dx = dy = 0;
		}

	dx = glue*dx/100 + (100-glue)*((cpos.x - x)) / 100;
	dy = glue*dy/100 + (100-glue)*((cpos.y - y)) / 100;

	MoveToEx(hdc, x, y, 0);
	LineTo(hdc, x + 1, y);

	ReleaseDC(hDlg, hdc);
}
*/
int misc_handles(u32);
int shellcode_handles(u32);
void misc_init(void);
void shellcode_init(void);

LRESULT CALLBACK WinProc(HWND hDlgx, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
	{
	case WM_INITDIALOG:
		hDlg = hDlgx;
		SetClassLong(hDlg, GCL_HICON, (LONG)LoadIcon(GetModuleHandle(0), (LPCSTR)IDI_SLIPFEST));
//		SetClassLong(hDlg, GCL_HICONSM, (LONG)LoadIcon(GetModuleHandle(0), (LPCSTR)IDI_SLIPFEST));
		SetDlgItemText(hDlg, IDC_EDIT1, "kernel32");
		SetDlgItemText(hDlg, IDC_EDIT2, "CreateFileA");
		CheckDlgButton(hDlg, IDC_CHK_RMTRUN, BST_CHECKED);
		CheckDlgButton(hDlg, IDC_CHK_STKRUN, BST_UNCHECKED);
		hRemoteProc = GetCurrentProcess();
		terminating = 0;
		CreateStatusWindow(WS_CHILD, 0, hDlg, IDC_STATUS);
		SendMessage(GetDlgItem(hDlg, IDC_LOG), WM_SETFONT, (WPARAM)GetStockObject(SYSTEM_FIXED_FONT), 0);
		misc_init();
		shellcode_init();
//		SetTimer(hDlg, 1, 30, mousetimerproc);
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDCANCEL:
		case ID_QUIT:
			addbacklog("adios");
			CloseHandle(hRemoteProc);
			hRemoteProc = GetCurrentProcess();
			terminating = 1;
			EndDialog(hDlg, LOWORD(wParam));
//			KillTimer(hDlg, 1);
			return TRUE;

		case ID_LOG_SAVE:
			log_save();
			return TRUE;

		case ID_LOG_FLUSH:
			initbacklog();
			showbacklog(2);
			return TRUE;

		case ID_HELP:
			help();
			return TRUE;

		case ID_ABOUT:
			about();
			return TRUE;

		default:
			if (misc_handles(LOWORD(wParam)) == TRUE)
				return TRUE;
			if (shellcode_handles(LOWORD(wParam)) == TRUE)
				return TRUE;
			if (LOWORD(wParam) > 32700 && LOWORD(wParam) < 32900) {
				addbacklog("Function not implemented yet");
				return TRUE;
			}
		}
		break;

	case WM_MOUSEWHEEL:
		// forward mouse roll to edit control
		PostMessage(GetDlgItem(hDlg, IDC_LOG), message, wParam, lParam);
		return 0;

	case WM_GETMINMAXINFO:
		// disallow too small window size 
		((MINMAXINFO*)lParam)->ptMinTrackSize.x = 420;
		((MINMAXINFO*)lParam)->ptMinTrackSize.y = 150;
		return TRUE;

	case WM_SIZE:
		// resize the edit control to fit in the new window size
		{
		RECT rect;
		long status_height = 0;

		HWND status = GetDlgItem(hDlg, IDC_STATUS);

		if (IsWindowVisible(status)) {
			GetWindowRect(status, &rect);
			rect.right -= rect.left;
			rect.bottom -= rect.top;
			ScreenToClient(hDlg, (LPPOINT)&rect);
			SetWindowPos(status, HWND_BOTTOM, 0, HIWORD(lParam) - rect.bottom, LOWORD(lParam), rect.bottom, 0);
			status_height = rect.bottom;
		}

		HWND log = GetDlgItem(hDlg, IDC_LOG);
		GetWindowRect(log, &rect);
		rect.right -= rect.left;
		rect.bottom -= rect.top;
		ScreenToClient(hDlg, (LPPOINT)&rect);
		SetWindowPos(log, HWND_BOTTOM, 0, rect.top, LOWORD(lParam), HIWORD(lParam) - rect.top - status_height, 0);

		return TRUE;
		}
	}

	return FALSE;
}

void benchaslr_client(char *);
int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	if (!strncmp(lpCmdLine, "benchaslr", 9)) {
		benchaslr_client(lpCmdLine + 9);
		ExitProcess(0);
	}

	return (int)DialogBox(hInstance, (LPCSTR)IDD_WIN, 0, (DLGPROC)WinProc);
}
