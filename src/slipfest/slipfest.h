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

#pragma once

extern HWND hDlg;
extern HANDLE hRemoteProc;
extern HWND targethwnd;


void addbacklog(char *);
void showlasterror(char *);

int loadpe(struct exe_header *, u8 *ptr, int isfile);
int isrelocated(struct exe_header *, u32 rva);
u32 rva2rva(struct exe_header *, u32 rva, u32 size);
u32 rva2va(struct exe_header *, u32 rva, u32 size);
u32 rva2va_text(struct exe_header *, u32 rva, u32 size);

void showstatuswindow(void);
void hidestatuswindow(void);

extern int terminating;
extern HMODULE PEbase;