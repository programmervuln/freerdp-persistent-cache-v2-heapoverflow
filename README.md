# freerdp-persistent-cache-v2-heapoverflow
Repo name suggestion: freerdp‑persistent‑v2-poc
Files in repo: gen_poc_v2.c, asan_crash_v2.txt, screenshot_asan.png(optional).
Do NOT push harness.c / standalone_persistent.c

# FreeRDP: Heap‑Based Buffer Overflow in persistent_cache_read_entry_v2
PoC for vulnerability in FreeRDP persistent bitmap cache v2 parser.

## Vulnerability Information
- Component: `libfreerdp/cache/persistent.c`
- Function: `persistent_cache_read_entry_v2`
- CWE: **CWE‑122 Heap‑based Buffer Overflow**
- Impact: Parsing malicious persistent cache v2 file can trigger heap buffer overflow, potentially leading to arbitrary code execution.
- Affected: FreeRDP versions containing the `persistent_cache_read_entry_v2` code path.

## Root Cause
The `persist_cache_get_data` helper calculates `expected = 4ull * entry->width * entry->height` using attacker-controlled `width`/`height` parsed from the persistent cache file.
The code only checks `if (expected > UINT32_MAX)` and **does NOT check for 64-bit unsigned multiplication wrap-around overflow**.

An attacker can craft `width` and `height` such that `4ull * width * height` overflows 64-bit unsigned arithmetic and yields a very small `expected` value.
`persist_cache_get_data` then allocates a tiny heap buffer via `winpr_aligned_recalloc`.

In the v2 entry parser, the bitmap payload read length is **hardcoded to 0x4000 (16384 bytes)**.
The code always attempts to read 0x4000 bytes from the cache file into the heap buffer allocated using the overflowed small size.
This causes a heap buffer overflow when the allocated buffer size < 0x4000.

> NOTE: This bug exists in the v2 parser path.
> The v3 parser uses `entry->size` (computed from same width/height) for fread length and shares the same integer overflow defect in `persist_cache_get_data`, so v3 is also vulnerable.

## PoC
gen_poc_v2.c: Malicious cache file generator, outputs poc_v2.bin.
asan_crash_v2.txt: Full raw AddressSanitizer crash log from reproduction.
screenshot_asan.png: Optional screenshot of ASan crash.

## Reproduction Steps
```bash
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

	// Hardcoded read size: always read 0x4000 bytes
	if (fread(entry->data, 0x4000, 1, persistent->fp) != 1)
		return -1;

	return 1;
}
Notes
The vulnerability exists in unmodified upstream FreeRDP, no source‑code patches are needed to trigger.
This repository only provides PoC material for CVE application and vulnerability documentation.
