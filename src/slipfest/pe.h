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

#ifndef PE_H
#define PE_H

#include "system.h"

#define u8  unsigned char
#define u16 unsigned short
#define u32 unsigned long
#define u64 unsigned long long

#define IMAGE_PE_SIGNATURE 0x00004550	// PE00
#define IMAGE_MZ_SIGNATURE 0x5A4D		// MZ

//
// DOS image header
//

struct dos_header 
{
  u16 e_magic;                     // 00h Magic number
  u16 e_cblp;                      // 02h Bytes on last page of file
  u16 e_cp;                        // 04h Pages in file
  u16 e_crlc;                      // 06h Relocations
  u16 e_cparhdr;                   // 08h Size of header in paragraphs
  u16 e_minalloc;                  // 0Ah Minimum extra paragraphs needed
  u16 e_maxalloc;                  // 0Ch Maximum extra paragraphs needed
  u16 e_ss;                        // 0Eh Initial (relative) SS value
  u16 e_sp;                        // 10h Initial SP value
  u16 e_csum;                      // 12h Checksum
  u16 e_ip;                        // 14h Initial IP value
  u16 e_cs;                        // 16h Initial (relative) CS value
  u16 e_lfarlc;                    // 18h File address of relocation table
  u16 e_ovno;                      // 1Ah Overlay number
  u16 e_res[4];                    // 1Ch Reserved words
  u16 e_oemid;                     // 24h OEM identifier (for e_oeminfo)
  u16 e_oeminfo;                   // 26h OEM information; e_oemid specific
  u16 e_res2[10];                  // 28h Reserved words
  u32 e_lfanew;                    // 3Ch File address of new exe header
};

//
// PE image file header
//

struct image_file_header
{
  u16 machine;						// 00h
  u16 number_of_sections;			// 02h
  u32 timestamp;					// 04h
  u32 pointer_to_symboltable;		// 08h
  u32 number_of_symbols;			// 0Ch
  u16 size_of_optional_header;		// 10h
  u16 characteristics;				// 12h
};

#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved externel references)
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Agressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file
#define IMAGE_FILE_SYSTEM                    0x1000  // System File
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed

#ifndef IMAGE_FILE_MACHINE_I386
#define IMAGE_FILE_MACHINE_UNKNOWN      0
#define IMAGE_FILE_MACHINE_ALPHA		0x184	// Alpha AXP™.	   
#define IMAGE_FILE_MACHINE_ARM			0x1c0		   
#define IMAGE_FILE_MACHINE_ALPHA64		0x284	// Alpha AXP™ 64-bit.	   
#define IMAGE_FILE_MACHINE_I386			0x14c	// Intel 386 or later, and compatible processors.	   
#define IMAGE_FILE_MACHINE_IA64			0x200	// Intel IA64™	   
#define IMAGE_FILE_MACHINE_M68K			0x268	// Motorola 68000 series.	   
#define IMAGE_FILE_MACHINE_MIPS16		0x266		   
#define IMAGE_FILE_MACHINE_MIPSFPU		0x366	// MIPS with FPU	   
#define IMAGE_FILE_MACHINE_MIPSFPU16	0x466	// MIPS16 with FPU	   
#define IMAGE_FILE_MACHINE_POWERPC		0x1f0	// Power PC, little endian.	   
#define IMAGE_FILE_MACHINE_R3000		0x162		   
#define IMAGE_FILE_MACHINE_R4000		0x166	// MIPS® little endian.	   
#define IMAGE_FILE_MACHINE_R10000		0x168		   
#define IMAGE_FILE_MACHINE_SH3			0x1a2	// Hitachi SH3	   
#define IMAGE_FILE_MACHINE_SH4			0x1a6	// Hitachi SH4	   
#define IMAGE_FILE_MACHINE_THUMB		0x1c2		 
#endif

//
// Image directory
//

struct image_directory
{
  u32 rva;
  u32 size;
};

#define IMAGE_OPTIONAL_HDR32_MAGIC          0x10B
#define IMAGE_OPTIONAL_HDR32_MAGIC_ROM      0x107

 
#define IMAGE_SUBSYSTEM_UNKNOWN				0	//	Unknown subsystem.	   
#define IMAGE_SUBSYSTEM_NATIVE				1	//	Used for device drivers and native Windows NT processes.	   
#define IMAGE_SUBSYSTEM_WINDOWS_GUI			2	//	Image runs in the Windows™ graphical user interface (GUI) subsystem.	   
#define IMAGE_SUBSYSTEM_WINDOWS_CUI			3	//	Image runs in the Windows character subsystem.	   
#define IMAGE_SUBSYSTEM_POSIX_CUI			7	//	Image runs in the Posix character subsystem.	   
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI		9	//	Image runs in on Windows CE.	   
#define IMAGE_SUBSYSTEM_EFI_APPLICATION		10	//	Image is an EFI application.	   
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_
#define DRIVER								11	//	Image is an EFI driver that provides boot services.	   
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER	12	//	Image is an EFI driver that provides runtime services.	 

//
// Optional image header
//

struct image_optional_header
{
  u16 magic;							// 00h
  u8  major_linker_version;				// 02h
  u8  minor_linker_version;				// 03h
  u32 size_of_code;						// 04h
  u32 size_of_initialized_data;			// 08h
  u32 size_of_uninitialized_data;		// 0Ch
  u32 address_of_entry_point;			// 10h
  u32 base_of_code;						// 14h
  u32 base_of_data;						// 18h

  u32 image_base;						// 1Ch
  u32 section_alignment;				// 20h
  u32 file_alignment;					// 24h
  u16 major_operating_system_version;	// 28h
  u16 minor_operating_system_version;	// 2Ah
  u16 major_image_version;				// 2Ch
  u16 minor_image_version;				// 2Eh
  u16 major_subsystem_version;			// 30h
  u16 minor_subsystem_version;			// 32h
  u32 win32_version_value;				// 34h
  u32 size_of_image;					// 38h
  u32 size_of_headers;					// 3Ch
  u32 checksum;							// 40h
  u16 subsystem;						// 44h
  u16 dll_characteristics;				// 46h
  u32 size_of_stack_reserve;			// 48h
  u32 size_of_stack_commit;				// 4Ch
  u32 size_of_heap_reserve;				// 50h
  u32 size_of_heap_commit;				// 54h
  u32 loader_flags;						// 58h
  u32 number_of_rva_and_sizes;			// 5Ch
  struct image_directory data_directory[0];	// 60h
};

#define IMAGE_OPTIONAL_HDR32_MAGIC_PLUS          0x20B

struct image_optional_header_plus
{
  u16 magic;
  u8  major_linker_version;
  u8  minor_linker_version;
  u32 size_of_code;
  u32 size_of_initialized_data;
  u32 size_of_uninitialized_data;
  u32 address_of_entry_point;
  u32 base_of_code;

  u64 image_base;
  u32 section_alignment;
  u32 file_alignment;
  u16 major_operating_system_version;
  u16 minor_operating_system_version;
  u16 major_image_version;
  u16 minor_image_version;
  u16 major_subsystem_version;
  u16 minor_subsystem_version;
  u32 win32_version_value;
  u32 size_of_image;
  u32 size_of_headers;
  u32 checksum;
  u16 subsystem;
  u16 dll_characteristics;
  u64 size_of_stack_reserve;
  u64 size_of_stack_commit;
  u64 size_of_heap_reserve;
  u64 size_of_heap_commit;
  u32 loader_flags;
  u32 number_of_rva_and_sizes;
  struct image_directory data_directory[0];
};

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

//
// Image section header
//

struct image_section_header
{
  char name[8];
  u32 virtual_size;
  u32 virtual_address;
  u32 size_of_raw_data;
  u32 pointer_to_raw_data;
  u32 pointer_to_relocations;
  u32 pointer_to_linenumbers;
  u16 number_of_relocations;
  u16 number_of_linenumbers;
  u32 characteristics;
};

//
// Section characteristics
//

#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.

#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
#define IMAGE_SCN_MEM_FARDATA                0x00008000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000

#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  //
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  //
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  //
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  //
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  //
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  //
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000  //
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000  //
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  //
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  //
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  //
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  //
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  //

#define IMAGE_SCN_ALIGN_MASK                 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.

//
// Based relocation format
//

struct image_base_offset
{
	u16 offset : 12;
	u16 type : 4;
};

struct image_base_relocation
{
  u32 virtual_address;
  u32 size_of_block;
  struct image_base_offset reloc[0];
};

//
// Based relocation types.
//

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MIPS_JMPADDR          5
#define IMAGE_REL_BASED_SECTION               6
#define IMAGE_REL_BASED_REL32                 7

//
// Export Format
//

#ifndef IMAGE_ORDINAL_FLAG
#define IMAGE_ORDINAL_FLAG 0x80000000
#endif

struct image_export_directory
{
  u32 characteristics;			// 00h
  u32 timestamp;				// 04h
  u16 major_version;			// 08h
  u16 minor_version;			// 0Ah
  u32 name;						// 0Ch
  u32 base;						// 10h
  u32 number_of_functions;		// 14h
  u32 number_of_names;			// 18h
  u32 address_of_functions;		// 1Ch
  u32 address_of_names;			// 20h
  u32 address_of_name_ordinals;	// 24h
};

//
// Import Format
//

struct image_import_by_name
{
  u16 hint;
  char name[0];
};

struct image_import_descriptor
{
  u32 original_first_thunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
  u32 timestamp;
  u32 forwarder_chain;              // -1 if no forwarders
  u32 name;
  u32 first_thunk;                  // RVA to IAT (if bound this IAT has actual addresses)
};

struct image_bound_import_descriptor
{
  u32 timestamp;
  u16 offset_module_name;
  u16 number_of_module_forwarder_refs;
  // array of zero or more struct image_bound_forwarder_ref follows
};

struct image_bound_forwarder_ref
{
  u32 timestamp;
  u16 offset_module_name;
  u16 reserved;
};

//
// Resource Format
//

struct image_resource_directory 
{
  u32 characteristics;
  u32 timestamp;
  u16 major_version;
  u16 minor_version;
  u16 number_of_named_entries;
  u16 number_of_id_entries;
  // struct image_resource_directory_entry directoryentries[];
};

#define IMAGE_RESOURCE_NAME_IS_STRING        0x80000000
#define IMAGE_RESOURCE_DATA_IS_DIRECTORY     0x80000000

struct image_resource_directory_entry 
{
  union 
  {
    struct 
    {
      u32 name_offset : 31;
      u32 name_is_string : 1;
    };
    u32 name;
    u16 id;
  };
  union 
  {
    u32 offset_to_data;
    struct 
    {
      u32 offset_to_directory : 31;
      u32 data_is_directory : 1;
    };
  };
};

struct image_resource_directory_string
{
 u16 length;
 char name_string[0];
};

struct image_resource_data_entry 
{
  u32 offset_to_data;
  u32 size;
  u32 codepage;
  u32 reserved;
};

//

struct image_export_loaded
{
  struct image_export_directory *directory;
  char *name;
  u32 *functions;
  u32 *names;
  u16 *ordinals;
};

struct exe_header
{
	struct dos_header *dhdr;
	u32 *pesig;
	struct image_file_header *ihdr;
	struct image_optional_header *ohdr;
	struct image_optional_header_plus *ohdr_plus;

	struct image_directory *dir;
	struct image_section_header *sect;

	struct image_export_loaded exports;
	struct image_import_descriptor *imports;
	struct image_base_relocation *relocs;
};  


// PEB TEB ...
typedef struct _DISPATCHER_HEADER {
    UCHAR Type;
    UCHAR Absolute;
    UCHAR Size;
    UCHAR Inserted;
    LONG SignalState;
    LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER;

//
// Event object
//

typedef struct _KEVENT {
    DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT, *RESTRICTED_POINTER PRKEVENT;

typedef struct _FAST_MUTEX {
    LONG Count;
    PVOID Owner; // PKTHREAD
    ULONG Contention;
    KEVENT Event;
    ULONG OldIrql;
} FAST_MUTEX, *PFAST_MUTEX;

typedef struct _W32THREAD
{
  PVOID MessageQueue;
  FAST_MUTEX WindowListLock;
  LIST_ENTRY WindowListHead;
  struct _KBDTABLES* KeyboardLayout;
  struct _DESKTOP_OBJECT* Desktop;
  DWORD MessagePumpHookValue;
} W32THREAD, *PW32THREAD;

typedef struct _LDR_MODULE {
//  LIST_ENTRY              InLoadOrderModuleList;	// 00h
struct _LDR_MODULE*			InLoadOrderModuleList;	    // 00h
PVOID dummy;
	LIST_ENTRY              InMemoryOrderModuleList;	// 08h
	LIST_ENTRY              InInitializationOrderModuleList;	// 10h
	PVOID                   BaseAddress;				// 18h
	PVOID                   EntryPoint;					// 1Ch
	ULONG                   SizeOfImage;				// 20h
	UNICODE_STRING          FullDllName;				// 24h
	UNICODE_STRING          BaseDllName;				// 2Ch
	ULONG                   Flags;						// 34h
	SHORT                   LoadCount;					// 38h
	SHORT                   TlsIndex;					// 3Ah
	union {
		struct {
			HANDLE         SectionHandle;
			ULONG          CheckSum;
		};
		LIST_ENTRY              HashTableEntry;			// 3Ch
	};
	ULONG                   TimeDateStamp;				// 44h
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA
{
   ULONG Length;									// 00h
   BOOLEAN Initialized;								// 04h
   PVOID SsHandle;									// 08h
//   LIST_ENTRY InLoadOrderModuleList;				// 0Ch
PLDR_MODULE InLoadOrderModuleList;		            // 0Ch
PVOID dummy;
   LIST_ENTRY InMemoryOrderModuleList;				// 14h
   LIST_ENTRY InInitializationOrderModuleList;		// 1Ch
   PVOID EntryInProgress;							// 24h
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;						// 0
	ULONG Length;								// 4
	ULONG Flags;								// 8
	ULONG DebugFlags;							// c
	PVOID ConsoleHandle;						// 10
	ULONG ConsoleFlags;							// 14
	HANDLE StdInputHandle;						// 18
	HANDLE StdOutputHandle;						// 1c
	HANDLE StdErrorHandle;						// 20
	UNICODE_STRING CurrentDirectoryPath;		// 24
	HANDLE CurrentDirectoryHandle;				// 2c
	UNICODE_STRING DllPath;						// 30
	UNICODE_STRING ImagePathName;				// 38
	UNICODE_STRING CommandLine;					// 40
	PVOID Environment;							// 48
	ULONG StartingPositionLeft;					// 4C
	ULONG StartingPositionTop;					// 50
	ULONG Width; ULONG Height;					// 54 58
	ULONG CharWidth;							// 5C
	ULONG CharHeight;							// 60
	ULONG ConsoleTextAttributes;				// 64
	ULONG WindowFlags;							// 68
	ULONG ShowWindowFlags;						// 6C
	UNICODE_STRING WindowTitle;					// 70
	UNICODE_STRING DesktopName;					// 78
	UNICODE_STRING ShellInfo;					// 80
	UNICODE_STRING RuntimeData;					// 88
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];	// 90
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void (*PPEBLOCKROUTINE)(
    PVOID PebLock
);

typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK* Next;
	ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _PEB
{
   UCHAR InheritedAddressSpace;                     // 00h
   UCHAR ReadImageFileExecOptions;                  // 01h
   UCHAR BeingDebugged;                             // 02h
   UCHAR Spare;                                     // 03h
   PVOID Mutant;                                    // 04h
   PVOID ImageBaseAddress;                          // 08h
   PPEB_LDR_DATA Ldr;                               // 0Ch
   PRTL_USER_PROCESS_PARAMETERS ProcessParameters;  // 10h
   PVOID SubSystemData;                             // 14h
   PVOID ProcessHeap;                               // 18h
   PVOID FastPebLock;                               // 1Ch
   PPEBLOCKROUTINE FastPebLockRoutine;              // 20h
   PPEBLOCKROUTINE FastPebUnlockRoutine;            // 24h
   ULONG EnvironmentUpdateCount;                    // 28h
   PVOID* KernelCallbackTable;                      // 2Ch
   PVOID EventLogSection;                           // 30h
   PVOID EventLog;                                  // 34h
   PPEB_FREE_BLOCK FreeList;                        // 38h
   ULONG TlsExpansionCounter;                       // 3Ch
   PVOID TlsBitmap;                                 // 40h
   ULONG TlsBitmapBits[0x2];                        // 44h
   PVOID ReadOnlySharedMemoryBase;                  // 4Ch
   PVOID ReadOnlySharedMemoryHeap;                  // 50h
   PVOID* ReadOnlyStaticServerData;                 // 54h
   PVOID AnsiCodePageData;                          // 58h
   PVOID OemCodePageData;                           // 5Ch
   PVOID UnicodeCaseTableData;                      // 60h
   ULONG NumberOfProcessors;                        // 64h
   ULONG NtGlobalFlag;                              // 68h
   UCHAR Spare2[0x4];                               // 6Ch
   LARGE_INTEGER CriticalSectionTimeout;            // 70h
   ULONG HeapSegmentReserve;                        // 78h
   ULONG HeapSegmentCommit;                         // 7Ch
   ULONG HeapDeCommitTotalFreeThreshold;            // 80h
   ULONG HeapDeCommitFreeBlockThreshold;            // 84h
   ULONG NumberOfHeaps;                             // 88h
   ULONG MaximumNumberOfHeaps;                      // 8Ch
   PVOID** ProcessHeaps;                            // 90h
   PVOID GdiSharedHandleTable;                      // 94h
   PVOID ProcessStarterHelper;                      // 98h
   PVOID GdiDCAttributeList;                        // 9Ch
   PVOID LoaderLock;                                // A0h
   ULONG OSMajorVersion;                            // A4h
   ULONG OSMinorVersion;                            // A8h
   ULONG OSBuildNumber;                             // ACh
   ULONG OSPlatformId;                              // B0h
   ULONG ImageSubSystem;                            // B4h
   ULONG ImageSubSystemMajorVersion;                // B8h
   ULONG ImageSubSystemMinorVersion;                // BCh
   ULONG ImageProcessAffinityMask;					// C0h
   ULONG GdiHandleBuffer[0x22];                     // C4h
   PVOID PostProcessInitRoutine;					// 14Ch
   PVOID TlsExpansionBitmap;						// 150h
   ULONG TlsExpansionBitmapBits[0x20];				// 154h
   ULONG SessinId;									// 1D4h
   u64   AppCompatFlags;							// 1D8h
   u64	 AppCompatFlagUser;							// 1E0h
   PVOID pShipData;									// 1E8h
   PVOID AppCompatInfo;								// 1ECh
   UNICODE_STRING CSDVersion;						// 1F0h
   PVOID ActivationContextData;						// 1F8h
   PVOID ProcessAssemblyStorageMap;					// 1FCh
   PVOID SystemDefaultActivationContextData;		// 200h
   PVOID SystemAssemblyStorageMap;					// 204h
   ULONG MinimumStackCommit;						// 208h
} PEB, *PPEB;

// +++
// User-Mode Thread Environment Block (UTEB)
// Selector 0x3B: DPL=3, Base=0x7FFDE00 (1st thread), Lim=0x00000FFF
// Base is updated at every thread switch.
// Loaded into FS in User Mode
// ---

typedef struct _EXCEPTION_REGISTRATION_RECORD {
   struct _EXCEPTION_REGISTRATION_RECORD    *Next;
   PVOID                                    Handler;
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;

#if 0
typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;  // 00h
    PVOID StackBase;                                       // 04h
    PVOID StackLimit;                                      // 08h
    PVOID SubSystemTib;                                    // 0Ch
    union {
        PVOID FiberData;                                   // 10h
        ULONG Version;                                     // 10h
    } Fib;
    PVOID ArbitraryUserPointer;                            // 14h
    struct _NT_TIB *Self;                                  // 18h
} NT_TIB, *PNT_TIB;

typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[0x136];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;
#endif

typedef struct _GDI_TEB_BATCH
{
   ULONG Offset;
   ULONG HDC;
   ULONG Buffer[0x136];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _CLIENT_ID
{
	void *UniqueProcess;
	void *UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _TEB
{
   NT_TIB Tib;                         // 00h
   PVOID EnvironmentPointer;           // 1Ch
   CLIENT_ID Cid;                      // 20h
   PVOID ActiveRpcInfo;                // 28h
   PVOID ThreadLocalStoragePointer;    // 2Ch
   PPEB Peb;                           // 30h
   ULONG LastErrorValue;               // 34h
   ULONG CountOfOwnedCriticalSections; // 38h
   PVOID CsrClientThread;              // 3Ch
   struct _W32THREAD* Win32ThreadInfo; // 40h
   ULONG Win32ClientInfo[0x1F];        // 44h
   PVOID WOW32Reserved;                // C0h
   ULONG CurrentLocale;                // C4h
   ULONG FpSoftwareStatusRegister;     // C8h
   PVOID SystemReserved1[0x36];        // CCh
   PVOID Spare1;                       // 1A4h
   LONG ExceptionCode;                 // 1A8h
   ULONG SpareBytes1[0x28/4];          // 1ACh
   PVOID SystemReserved2[0xA];         // 1D4h
   GDI_TEB_BATCH GdiTebBatch;          // 1FCh
   ULONG gdiRgn;                       // 6DCh
   ULONG gdiPen;                       // 6E0h
   ULONG gdiBrush;                     // 6E4h
   CLIENT_ID RealClientId;             // 6E8h
   PVOID GdiCachedProcessHandle;       // 6F0h
   ULONG GdiClientPID;                 // 6F4h
   ULONG GdiClientTID;                 // 6F8h
   PVOID GdiThreadLocaleInfo;          // 6FCh
   PVOID UserReserved[5];              // 700h
   PVOID glDispatchTable[0x118];       // 714h
   ULONG glReserved1[0x1A];            // B74h
   PVOID glReserved2;                  // BDCh
   PVOID glSectionInfo;                // BE0h
   PVOID glSection;                    // BE4h
   PVOID glTable;                      // BE8h
   PVOID glCurrentRC;                  // BECh
   PVOID glContext;                    // BF0h
   NTSTATUS LastStatusValue;           // BF4h
   UNICODE_STRING StaticUnicodeString; // BF8h
   WCHAR StaticUnicodeBuffer[0x105];   // C00h
   PVOID DeallocationStack;            // E0Ch
   PVOID TlsSlots[0x40];               // E10h
   LIST_ENTRY TlsLinks;                // F10h
   PVOID Vdm;                          // F18h
   PVOID ReservedForNtRpc;             // F1Ch
   PVOID DbgSsReserved[0x2];           // F20h
   ULONG HardErrorDisabled;            // F28h
   PVOID Instrumentation[0x10];        // F2Ch
   PVOID WinSockData;                  // F6Ch
   ULONG GdiBatchCount;                // F70h
   ULONG Spare2;                       // F74h
   ULONG Spare3;                       // F78h
   ULONG Spare4;                       // F7Ch
   PVOID ReservedForOle;               // F80h
   ULONG WaitingOnLoaderLock;          // F84h
} TEB, *PTEB;

#if 0
#define SIZE_OF_80387_REGISTERS      80

typedef struct _FLOATING_SAVE_AREA {
    DWORD   ControlWord;		// 0
    DWORD   StatusWord;			// 4
    DWORD   TagWord;			// 8
    DWORD   ErrorOffset;		// C
    DWORD   ErrorSelector;		// 10
    DWORD   DataOffset;			// 14
    DWORD   DataSelector;		// 18
    BYTE    RegisterArea[SIZE_OF_80387_REGISTERS]; // 1C
    DWORD   Cr0NpxState; // 6C
} FLOATING_SAVE_AREA, *PFLOATING_SAVE_AREA;

#define MAXIMUM_SUPPORTED_EXTENSION     512

typedef struct _CONTEXT {
    DWORD ContextFlags;	//0

    //
    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
    // included in CONTEXT_FULL.
    //

    DWORD   Dr0;		// 4
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;		// 10
    DWORD   Dr6;
    DWORD   Dr7;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
    //

    FLOATING_SAVE_AREA FloatSave; // 1C

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_SEGMENTS.
    //

    DWORD   SegGs;	// 8C
    DWORD   SegFs;	// 90
    DWORD   SegEs;
    DWORD   SegDs;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_INTEGER.
    //

    DWORD   Edi;
    DWORD   Esi;	// A0
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;	// B0

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_CONTROL.
    //

    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;	            // MUST BE SANITIZED
    DWORD   EFlags;	// C0       // MUST BE SANITIZED
    DWORD   Esp;
    DWORD   SegSs;

    //
    // This section is specified/returned if the ContextFlags word
    // contains the flag CONTEXT_EXTENDED_REGISTERS.
    // The format and contexts are processor specific
    //

    BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT, *PCONTEXT;

typedef struct _EXCEPTION_RECORD {
    DWORD    ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

typedef struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

LONG WINAPI UnhandledExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo);

#endif
#endif

// _DRIVER_OBJECT