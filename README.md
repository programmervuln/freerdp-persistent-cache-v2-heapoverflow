# freerdp-persistent-cache-v2-heapoverflow
Repo name suggestion: freerdp‑persistent‑v2-poc
Files in repo: gen_poc_v2.c, asan_crash_v2.txt, screenshot_asan.png(optional).
Do NOT push harness.c / standalone_persistent.c

# FreeRDP: Heap‑Based Buffer Overflow / Unsigned Integer Wrap-Around in persistent_cache_read_entry_v2
PoC material for FreeRDP persistent bitmap cache v2 parser.

## Vulnerability Information
- Component: `libfreerdp/cache/persistent.c`
- Function: `persistent_cache_read_entry_v2`
- CWE:
  - Unmodified upstream source: **CWE-190 Integer Overflow or Wraparound**
  - Local test harness (MAX protection removed): **CWE‑122 Heap‑based Buffer Overflow**
- Impact:
  - Unmodified upstream: Parsing malicious persistent cache v2 file triggers 64-bit unsigned multiplication wrap-around, corrupting `entry->size`. This corrupted size value may create risks in other code paths consuming this field.
  - Harness with `MAX(0x4000, expected)` removed: Parsing malicious file triggers heap buffer overflow, potentially leading to arbitrary code execution.
- Affected: FreeRDP versions containing the `persistent_cache_read_entry_v2` code path.

## Root Cause
`persistent_cache_read_entry_v2` reads attacker-controlled `width` and `height` from the malicious persistent cache file and stores them into the `entry` structure.
The function then calls the helper `persist_cache_get_data`, which executes:
```c
const UINT64 expected = 4ull * entry->width * entry->height;
if (expected > UINT32_MAX)
    return FALSE;

The calculation 4ull * entry->width * entry->height uses attacker-supplied width and height. There is no pre-multiplication check to detect UINT64 overflow.An attacker supplies very large width/height such that the true mathematical product 4 * width * height exceeds \(2^{64}\). Under C unsigned 64-bit arithmetic rules, the product wraps modulo \(2^{64}\), and the resulting stored expected becomes a numerically small value (wrapped small expected).The existing check if (expected > UINT32_MAX) only rejects large, non-wrapped values.
Because this wrapped expected is numerically small, expected > UINT32_MAX evaluates to false.
The check is bypassed, persist_cache_get_data does not return FALSE early, and memory allocation logic continues.
Unmodified upstream code
persist_cache_get_data uses allocated = MAX(0x4000, expected). This forces the heap buffer to be at least 0x4000 bytes.
The v2 parser then runs a hardcoded read:

if (fread(entry->data, 0x4000, 1, persistent->fp) != 1)

The buffer size ≥ 0x4000 matches the read length, so no heap overflow occurs in upstream source.
The wrapped fake value is still saved to entry->size, resulting in integer wrap-around defect.
Local PoC harness (for BOF crash reproduction)
The local test harness removes the MAX(0x4000, expected) protection.
winpr_aligned_recalloc allocates a tiny heap buffer using the wrapped small expected.
Returning to persistent_cache_read_entry_v2, the code attempts to read a fixed 0x4000 bytes into this undersized heap buffer.
When allocated buffer size < 0x4000, this operation triggers heap buffer overflow.
NOTE: The persistent_cache_read_entry_v3 parser reuses the same vulnerable persist_cache_get_data helper and shares the same 64-bit unsigned multiplication wrap-around defect.
Unlike v2, v3 uses entry->size as the length argument for fread.
PoC
gen_poc_v2.c: Malicious cache file generator, outputs poc_v2.bin.
asan_crash_v2.txt: Full raw AddressSanitizer crash log from reproduction.
screenshot_asan.png: Optional screenshot of ASan crash.
Reproduction Steps

gcc gen_poc_v2.c -o gen_poc_v2
./gen_poc_v2
# Output: poc_v2.bin, the malicious persistent cache input file.

Local verification setup:
A local standalone harness is required for testing.
The harness embeds the original persistent_cache_read_entry_v2 function taken from FreeRDP upstream source.
To reproduce the heap-buffer-overflow crash, you must remove allocated = MAX(0x4000, expected) inside persist_cache_get_data in the harness.
This harness is for local verification only and not included in this repository.
Compile harness with AddressSanitizer:
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
This repository only provides PoC generator and crash log for CVE application and vulnerability documentation.
In unmodified upstream FreeRDP, only 64‑bit unsigned multiplication wrap-around (CWE‑190) exists, which corrupts entry->size.
Observable heap‑buffer‑overflow (CWE‑122) crash can only be reproduced after removing MAX(0x4000, expected) protection in local test harness.
