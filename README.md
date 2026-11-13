# zigil

An x86-64 pattern scanner that matches **decoded instructions**, not bytes.

Instead of writing a byte signature and hoping the compiler never reshuffles the
operands:

```
48 8B ?? ?? ?? ?? ??  E8 ?? ?? ?? ??
```

you write the assembly you actually mean, with typed wildcards and capture
variables:

```x86asm
mov $obj:r64, [rip+$global]   ; capture the register and the target RVA
mov rcx, $obj                 ; only matches if it is the same register
call ?                        ; any callee
mov ?, [$obj+0x38]
```

zigil disassembles the image with Zydis, walks it with a recursive-descent
analyzer, and matches your pattern against the instruction stream. Registers,
operand kinds, immediate widths and rip-relative addresses are all understood, so
a pattern survives the register allocation changes that break a byte signature.

It is built for reverse engineering: finding structures, globals and functions in
a stripped binary.

---

## Contents

- [Quick start](#quick-start)
- [The CLI](#the-cli)
- [Pattern language](#pattern-language)
- [Using it as a library](#using-it-as-a-library)
- [How it works](#how-it-works)
- [How well it works](#how-well-it-works)
- [Project layout](#project-layout)
- [Status and limitations](#status-and-limitations)

---

## Quick start

Build `zigil.vcxproj`, which is the CLI and the tests:

```
MSBuild.exe zigil.vcxproj -p:Configuration=Release -p:Platform=x64
```

Visual Studio opens the project file directly; there is no solution, because the
repository is meant to be consumed from one rather than to carry its own.

Zydis comes from vcpkg through the manifest in the repository, so there is
nothing to install by hand.

Then point it at something:

```
> zigil "mov $reg:r64, [rip+$target]" C:\windows\system32\version.dll -v

pattern:
mov $reg:r64, [rip+$target:imm]

version.dll                                                   3 matches  (0.0s)
  rva 0x117E  (va 0x18000117E)
      reg              = rcx
      target           = rva 0x7628, va 0x180007628
  ...
```

Requires Windows, C++20 and a toolset that implements it — `std::format`,
`constexpr std::vector` and class-type template parameters are all
load-bearing. Developed against MSVC; it also builds with clang-cl.

---

## The CLI

```
zigil <pattern> <path> [options]
zigil -f <pattern-file> <path> [options]
```

`<path>` is a PE image or a directory, which is searched **recursively**. Every
file that matches the extension filter and starts with a real `MZ`/`PE` header is
analyzed and scanned.

| Option | Meaning |
| --- | --- |
| `-f, --file <path>` | read the pattern from a file (the sane way to write multi-line patterns) |
| `-n, --max <count>` | stop after `<count>` matches per file (default 32, `0` = all) |
| `-v, --vars` | print the captured variables of every match |
| `--va` | print virtual addresses instead of RVAs |
| `--ext <list>` | comma separated extensions to scan (default `exe,dll,sys,ocx,efi,node,bin`) |
| `-a, --all` | scan every file whatever its extension |
| `--loaded` | the input is already a flat image (a dumped module, not a file-aligned PE) |
| `--stats` | print the analyzer report per file: coverage per section, seeds, timings |
| `--fast` | recursive descent only, no pointer scan / prologue scan / gap sweep |
| `--set <n>=<v>` | pre-bind variable `<n>` instead of capturing it — see [xref search](#pre-bound-variables-xref-search). Repeatable. |
| `-q, --quiet` | only list files that matched |
| `-h, --help` | usage |

Exit code is `0` if anything matched, `1` if nothing did, `2` on a usage error —
so it composes in a script.

In an inline pattern the two characters `\n` become a newline, because passing
real newlines through a shell argument is miserable. Anything longer than two
instructions is better off in a file.

### Examples

Find every read of a global through a rip-relative load, across a folder of
modules:

```
zigil "mov $reg:r64, [rip+$target]" .\modules -v
```

Find a vtable dispatch, no matter which register the compiler picked:

```
zigil "mov $reg:r64, [rcx+$vtable_off]\ncall [$reg+?]" target.exe -v
```

Find every read of one specific global — an xref search, by pre-binding the
address instead of capturing it:

```
> zigil "mov $reg:r64, [rip+$target]" version.dll --set target=0x7628 -v

version.dll                                                   6 matches  (0.0s)
  rva 0x117E  (va 0x18000117E)
      reg              = rcx
      target           = rva 0x7628, va 0x180007628
  ...
```

A register name binds as a register (`--set reg=rcx`), anything else as a number
that satisfies both an immediate and a resolved address.

Use a pattern file for anything longer than a line or two:

```
> type demo.zig
; a global loaded rip-relative, checked, then used as a this pointer
mov $obj:r64, [rip+$global:imm]
test $obj, $obj
jz ?
mov rcx, $obj

> zigil -f demo.zig C:\windows\system32\shell32.dll -v

shell32.dll                                                   2 matches  (0.4s)
  rva 0x1F1AD1  (va 0x1801F1AD1)
      obj              = rbx
      global           = rva 0x71E040, va 0x18071E040
  rva 0x1F1B46  (va 0x1801F1B46)
      obj              = rbx
      global           = rva 0x71FCE0, va 0x18071FCE0
```

Two matches in a 6 MB `.text`. `$obj` is enforced across three of the four lines,
and `$global` is the **resolved** address of the global, not the raw
displacement — see [captures](#captures).

---

## Pattern language

One instruction per line, `;` starts a comment. Mnemonics, register names and
type suffixes are case-insensitive.

### Wildcards

| Syntax | Matches |
| --- | --- |
| `?` | any operand: register, immediate or memory |
| `?:r8` `?:r16` `?:r32` `?:r64` | any register of that width |
| `?:xmm` `?:ymm` `?:zmm` | any SIMD register |
| `?:imm` | any immediate |
| `[?]` | any memory operand, whatever the addressing mode |

```x86asm
mov rcx, [rax+?]      ; any displacement
mov ?, 0x1337         ; any destination
movdqu ?:xmm, [rsp+?]
call ?                ; any target
```

Each `?` on a line is its own anonymous wildcard, so `mov ?:r32, ?:r64` does not
require the two registers to be related.

### Capture variables

`$name` captures on first use and is **enforced** on every later use. A variable
is immutable once bound.

```x86asm
mov rcx, [rax+$off]   ; $off captures the displacement
mov $reg, 0x1337      ; $reg captures the register
cmp rcx, $reg         ; only matches if it is that same register
call [?+$off]         ; only matches if it is that same displacement
```

Type suffixes work the same as on `?`. Declaring conflicting types for one
variable is a **parse error**, unless you write `:*` to reuse a captured register
at a different width:

```x86asm
mov $x:r32, [rax+?]
mov [$base+$x:*], rdx   ; reuse $x as a 64-bit base
```

Only explicit suffixes are checked; an untyped reuse (`$x`) constrains nothing.
Up to 254 variables per pattern.

### Memory operands

```
[ SEG: ] '[' term ( ('+'|'-') term )* ']'
```

```x86asm
mov rax, [rcx]
mov rax, [rcx+0x10]
mov rax, [rcx+rdx*4]
mov rax, [rcx+rdx*4+0x10]
mov rax, [rcx-0x8]
lea rax, ds:[rcx*8]
mov rax, [?]
```

Terms are classified by shape, not position, so `[rdx*4+rcx]` and `[rcx+rdx*4]`
are the same thing. Two plain registers (`[rax+rbx]`) mean base + index with
scale 1, the x86 semantic. Scale must be `1`, `2`, `4` or `8`. A pattern that
writes no displacement matches only an instruction that encodes none, or encodes
a zero.

The segment must be a literal segment register — it can never be a variable.

### Gaps

Skip over instructions you do not care about.

| Syntax | Meaning |
| --- | --- |
| `<1>` | exactly one instruction |
| `<3-7>` | three to seven |
| `<?>` | any number, including zero |
| `<1+>` | one or more |
| `<4->` | zero to four |

```x86asm
mov rcx, [rax+0x10]
<?>
test rcx, rcx
<1-3>
jnz ?
```

Gaps do **not** stop at `ret`, `int3` padding or function boundaries — "the next
instruction" means the next one in address order. The open-ended forms are capped
at 256 instructions by default (`Scanner::SetSkipLimit`), because without a bound
every failed match would walk to the end of the section.

### Numbers and prefixes

Decimal `4096`, hex `0x1000`, binary `0b1101`, negative `-1` and `[rcx-0x8]`.
Immediates and displacements are compared **as bit patterns truncated to the
width the instruction encodes them with**, so `-1` and `0xFFFFFFFF` both match an
imm32 of `0xFFFFFFFF`.

`rep`, `lock` and friends are x86 *prefixes*, not mnemonics, and are ignored: a
pattern of `movsb` matches both `movsb` and `rep movsb`. Writing the prefix is a
parse error.

A pattern has to cover every **explicit** operand of an instruction; implicit
ones may be left out, which is what lets `mul rcx` match without writing out the
implicit `rax` and `rdx`.

---

## Using it as a library

Three headers matter: `zigil/zigil.hh` for patterns, `zigil/analyzer/pe_analyzer.hh`
for the image, `zigil/scanner.hh` for matching.

To pull it into another solution, reference `zigil.lib.vcxproj`, which builds the
same code as a static library without the CLI and without the test translation
units, and put `include` on the include path:

```xml
<ProjectReference Include="third_party\zigil\zigil.lib.vcxproj">
  <Project>{4CECF771-6A14-4C6E-ADAC-9B1F0359C7EE}</Project>
</ProjectReference>
```

Dropping the sources straight into another project works too: add
`src/zigil/scanner.cc` and `src/zigil/analyzer/pe_analyzer.cc` to it and leave
`src/main.cc` out. Either way Zydis is a hard dependency, so the consuming
project needs it as well - add `zydis` to its vcpkg manifest, and link `Zydis.lib`
and `Zycore.lib` explicitly if it has vcpkg auto-link turned off.

### Patterns at compile time

The `_sig` literal parses the pattern **at compile time** and yields a heap-free
`FixedPattern`. The query string never reaches the binary, and a malformed
pattern is a compile error.

```cpp
using namespace zigil::literals;

constexpr auto pattern = R"(
    mov $reg:r64, [rcx+$vtable_off]
    call [$reg+?]
)"_sig;
```

Only the parsed structure and the FNV-1a hashes of the variable names survive
into the executable — the query text and the variable names are gone.

If you want a compile-time pattern to know its own variable names, for instance
so `Print` spells them out, ask for it:

```cpp
// one pattern
constexpr auto named = zigil::Parser::Parse<R"(mov $reg:r64, rcx)", true>();
named.View().Print();                  // mov $reg:r64, rcx
static_assert(named.View().NameOf(0) == "reg");

// or every pattern in the build
#define ZIGIL_KEEP_VARIABLE_NAMES 1
```

Off (the default) the name storage is not a member at all but an empty base
class, so it costs exactly zero bytes — an empty `std::array` would not, MSVC
gives it a dummy element. On, it costs 48 bytes per variable and the names do
land in the binary. Both directions are checked by `tests/parser_constexpr.cc`.

A **runtime** pattern from `Parser::Parse(std::string_view)` always carries its
names: the query string is in memory anyway, so there is nothing to save. That is
how the CLI labels captures without re-lexing anything. Use that overload for
patterns from a config file, or from `argv` as the CLI does — it returns a
`Pattern` and prints parse errors with line and column.

### Analyzing and scanning

```cpp
#include "zigil/analyzer/pe_analyzer.hh"
#include "zigil/scanner.hh"

std::vector<uint8_t> file = ReadAllBytes("target.exe");

zigil::analyzer::PEAnalyzer analyzer;
analyzer.Analyze(file.data(), file.size(), /*loaded=*/false);
analyzer.PrintReport();                    // coverage per section, seeds, timings

zigil::Scanner scanner(analyzer);
auto match = scanner.Find(pattern.View());
if (match) {
    printf("found at rva %llX\n", match->Rva());
}
```

`loaded = false` means the buffer is a file-aligned PE and has to be flattened
into virtual layout first. Pass `true` for an image dumped from a running
process, which is already flat.

`FindAll(pattern, limit)` collects matches in a single pass; `limit == 0` means
no limit. A small limit is the cheap way to check whether a signature is unique.

`AnalysisOptions` turns individual analyzer stages off, which is mostly useful
for isolating one when a result looks wrong:

```cpp
zigil::analyzer::AnalysisOptions options;
options.sweep_gaps = false;   // no linear sweep over the uncovered gaps
options.progress = false;     // no per-stage output
analyzer.Analyze(data, size, false, options);
```

### Captures

```cpp
auto reg  = match->Get<ZydisRegister>("obj");
auto rva  = match->Get<uint64_t>("global");        // RVA
auto va   = match->GetVA<uint64_t>("global");      // image base + RVA
auto off  = match->Get<uint32_t, "vtable_off">();  // hashed at compile time
```

Both spellings work: a `std::string_view` name is hashed at runtime, an NTTP name
at compile time, and the return type is always the caller's choice.

A capture holds one of: a **register** (`ZydisRegister`), an **immediate**, a
**resolved address**, or a **memory operand** (base, index, scale, displacement).

Captures are addressed by name, which is a hash lookup, so this works whether or
not the pattern kept the readable names. `PatternView::NameOf(index)` goes the
other way and returns the name, or an empty view when they were not kept.

Addresses are always **RVAs**. When a capture binds a rip-relative operand or a
branch target, zigil resolves the effective address for you — `[rip+$global]`
gives you the address of the global, not the raw displacement. `GetVA` is the
only place the image base enters the picture.

### Pre-bound variables: xref search

Seed a variable before scanning and it is *enforced* instead of captured. Same
syntax, and it turns a pattern into a cross-reference search:

```cpp
scanner.SetAddress("target", global_rva);
auto reads = scanner.FindAll(R"(mov $reg:r64, [rip+$target:imm])"_sig.View());
// every rip-relative 64-bit read of that global, with $reg telling you where it went
```

| Setter | Binds as |
| --- | --- |
| `Set(name, ZydisRegister)` | a register |
| `SetAddress(name, rva)` | a resolved address — an **RVA**, not a VA |
| `SetImmediate(name, value, width = 0)` | an immediate, width in bits, 0 = any |
| `Set(name, uint64_t)` | either an immediate or a resolved address |

A type suffix on a pre-bound variable is an assertion: seeding a register into
`$x:imm` is reported and the scan returns nothing, instead of silently never
matching.

Because a resolved address depends on where the instruction sits, this is the one
case where matching is position-dependent.

From the CLI the same thing is `--set name=value`, repeatable.

### From C and other languages

`zigil/zigil_c.h` wraps the above in a plain C API for callers that are not
C++ (Rust, through FFI, in [Zidro](https://github.com/zigilan/zidro)). Build
`src/zigil/zigil_c.cc` along with the other two sources.

```c
char err[256];
zigil_image* image = zigil_image_analyze(bytes, size, /*loaded=*/1, err, sizeof err);
zigil_pattern* pattern = zigil_pattern_compile(text, strlen(text), err, sizeof err);
zigil_binding bind = { "target", global_rva };   /* optional, like Scanner::Set */
zigil_matches* m = zigil_find_all(image, pattern, 0, &bind, 1, err, sizeof err);
for (size_t i = 0; i < zigil_matches_count(m); i++) {
    zigil_capture reg;
    zigil_match_capture(m, i, 0, &reg);           /* variable 0, see zigil_pattern_variable_name */
    printf("%llx %s\n", zigil_match_rva(m, i), reg.reg);
}
zigil_matches_free(m); zigil_pattern_free(pattern); zigil_image_free(image);
```

Errors come back as text in the caller's buffer instead of being printed: a
parse error carries its line and column. The image bytes are copied, so the
buffer can go once `zigil_image_analyze` returns.

---

## How it works

**The analyzer** turns a PE into a flat, RVA-addressed buffer plus a bitmap of
every offset where an instruction starts. After flattening, *buffer offset == RVA*
everywhere, which is the invariant everything else is built on.

It seeds a worklist and drains it, stage by stage, each stage only working on
what the previous ones failed to reach:

1. the entry point, the `.pdata` exception table, exports, TLS callbacks and the
   language-specific handlers out of `UNWIND_INFO`
2. jump tables, extracted during the walk from the dispatch sequence — the base
   the entries are relative to comes from resolving the `lea`, the table address
   from that base plus the displacement of the indexed load, the entry size and
   signedness from the load itself, and the entry count from the bounds check
3. a code-pointer scan over `.data` and `.rdata`, which is how vtable slots and
   callbacks get found — they have no direct branch pointing at them
4. a prologue scan over whatever is still uncovered, for functions with no xrefs
5. a linear **gap sweep** over everything still left, which unlike the walk does
   not stop at `ret`

Coverage is reported **per section**, never aggregated — one packed or encrypted
section is enough to make a total meaningless.

**The matcher** walks that bitmap in ascending RVA and re-decodes on demand.
Storing decoded instructions would cost gigabytes on a large image; decoding runs
at over 100M instructions per second, so it is cheaper to keep one bit per
address and decode again when needed.

---

## How well it works

`.text` coverage and analysis time on stock Windows binaries, which you can
reproduce with `--stats`:

| binary | `.text` | covered | coverage | analysis |
| --- | ---: | ---: | ---: | ---: |
| `kernel32.dll` | 543,508 | 507,193 | 93.32 % | 12 ms |
| `ntdll.dll` | 1,479,578 | 1,431,296 | 96.74 % | 33 ms |
| `shell32.dll` | 6,102,196 | 5,763,438 | 94.45 % | 128 ms |
| `windows.storage.dll` | 6,703,612 | 6,260,776 | 93.39 % | 141 ms |

The uncovered remainder is mostly alignment padding and data embedded in `.text`,
which the analyzer deliberately does not claim as code.

Scanning is a separate pass over the instructions the analyzer found. A
four-instruction pattern over shell32's 1.5M instructions takes about 0.4 s; the
cost scales with the instruction count, not the file size.

Two things decide what a pass costs beyond that walk. Patterns are bucketed by
the mnemonic they open on, and each bucket decodes an address with its operands
once for every candidate in it, so a second pattern on the same mnemonic is
nearly free and one that opens on a rare mnemonic barely enters the matcher at
all — **anchor a pattern on its rarest instruction, not on the one that happens
to come first.** And an unlimited scan is split across ranges of instruction
starts, one worker per hardware thread by default; `SetThreadCount` overrides
that, and the results are merged in address order, so the thread count changes
nothing about what a scan returns. On a 65M-instruction image a ten-pattern pass
went from 23 s to 2 s across the two.

---

## Project layout

```
zigil.vcxproj               the CLI and the tests
zigil.lib.vcxproj           the same code as a static library, without either
include/zigil/
  zigil.hh                  the _sig literal
  zigil_c.h                 the C API
  lexer.hh                  Token, TokenType, Lexer (constexpr)
  parser.hh                 Parser, including the consteval pivot
  pattern.hh                Pattern / FixedPattern / PatternView, operand model
  scanner.hh                Scanner, MatchResult, Capture
  tables.hh                 generated mnemonic and register tables
  analyzer/pe_analyzer.hh   PE parsing, seeding, recursive descent, gap sweep
  detail/                   FixedString for NTTP patterns, constexpr FNV-1a
src/
  main.cc                   the CLI
  zigil/scanner.cc          the matcher
  zigil/analyzer/pe_analyzer.cc
  zigil/zigil_c.cc          the C API
tests/
  lexer_constexpr.cc        lexer level static_asserts
  parser_constexpr.cc       the parser test set
```

Tests are `static_assert`s rather than a test binary: the lexer and parser are
`constexpr`, so a regression breaks the build.

---

## Status and limitations

Working: lexer, parser, compile-time pivot, analyzer, matcher, captures,
pre-bound variables, the CLI.

- **x86-64 PE only.** No 32-bit, no ELF, no Mach-O.
- **Windows.** The code is not portable yet; it includes `windows.h` for the PE
  structures. Developed with MSVC; it also builds with MinGW-w64 g++ 13.
- Write+execute sections are skipped by the aggressive analyzer stages, because a
  packed section at rest does not disassemble into anything meaningful. Recursive
  descent still follows a real branch into one.
- Open-ended gaps are capped at 256 instructions.
- Jump table extraction handles the MSVC and PIC forms (`lea` base, indexed load,
  `add`, indirect `jmp`, with the table either at the `lea` or at a displacement
  from it) and the non-PIC absolute form. When the base register is loaded outside
  the dispatch's basic block, the image base is assumed and the table has to
  confirm it. Other dispatch shapes fall back to the later analyzer stages rather
  than being recognised as tables.
- Nothing rejects an immediate in a destination slot (`mov $off:imm, rcx`); that
  would need per-mnemonic operand knowledge.
- Every file is analyzed from scratch, and the analysis itself is single
  threaded. Only the scan is split across threads.

## License

See [`LICENSE`](LICENSE).
