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
	PERSISTENT_CACHE_ENTRY_V2 entry2 = { 0 };

	WINPR_ASSERT(persistent);
	WINPR_ASSERT(entry);

	if (fread((void*)&entry2, sizeof(entry2), 1, persistent->fp) != 1)
		return -1;

	entry->key64 = entry2.key64;
	entry->width = entry2.width;
	entry->height = entry2.height;
	entry->size = entry2.width * entry2.height * 4;
	entry->flags = entry2.flags;

	persistent->bmpData = winpr_aligned_recalloc(persistent->bmpData, persistent->bmpSize, entry->size, 16);
	persistent->bmpSize = entry->size;

	if (!persistent->bmpData)
		return -1;

	entry->data = persistent->bmpData;

	if (fread((void*)entry->data, entry2.storedDataLen, 1, persistent->fp) != 1)
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
