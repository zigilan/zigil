#include "zigil/analyzer/pe_analyzer.hh"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace zigil::analyzer {
	namespace {
		using Clock = std::chrono::steady_clock;

		constexpr uint16_t kNoSection = 0xFFFF;
		/*
		* A jump table with more entries than this is almost certainly a
		* misdetection, so the extractor stops there instead of walking off into
		* whatever follows the table.
		*/
		constexpr uint64_t kMaxJumpTableEntries = 4096;
		/* a table whose relative base was assumed rather than read off a lea has to
		 * resolve at least this many entries before it is believed, for the case
		 * where the bounds check sits in another basic block and gives no size */
		constexpr uint64_t kMinGuessedEntries = 2;
		/* the array is null terminated; the cap is only a corruption guard */
		constexpr size_t kMaxTlsCallbacks = 256;

		struct ProloguePattern {
			uint8_t bytes[6];
			uint8_t length;
		};
		/*
		* Common MSVC x64 function prologues. These only seed the walk, so a false
		* positive costs one wasted work item, not a wrong result.
		*/
		constexpr ProloguePattern kPrologues[] = {
			{ { 0x48, 0x89, 0x5C, 0x24 }, 4 },       // mov [rsp+disp8], rbx
			{ { 0x48, 0x89, 0x6C, 0x24 }, 4 },       // mov [rsp+disp8], rbp
			{ { 0x48, 0x89, 0x74, 0x24 }, 4 },       // mov [rsp+disp8], rsi
			{ { 0x48, 0x89, 0x7C, 0x24 }, 4 },       // mov [rsp+disp8], rdi
			{ { 0x48, 0x89, 0x4C, 0x24, 0x08 }, 5 }, // mov [rsp+8], rcx
			{ { 0x48, 0x89, 0x54, 0x24, 0x10 }, 5 }, // mov [rsp+10h], rdx
			{ { 0x48, 0x83, 0xEC }, 3 },             // sub rsp, imm8
			{ { 0x48, 0x81, 0xEC }, 3 },             // sub rsp, imm32
			{ { 0x48, 0x8B, 0xC4 }, 3 },             // mov rax, rsp
			{ { 0x4C, 0x8B, 0xDC }, 3 },             // mov r11, rsp
			{ { 0x55, 0x48, 0x8B, 0xEC }, 4 },       // push rbp / mov rbp, rsp
			{ { 0x40, 0x53 }, 2 },                   // push rbx
			{ { 0x40, 0x55 }, 2 },                   // push rbp
			{ { 0x40, 0x56 }, 2 },                   // push rsi
			{ { 0x40, 0x57 }, 2 },                   // push rdi
		};

		bool SameRegister(ZydisRegister a, ZydisRegister b) {
			if (a == ZYDIS_REGISTER_NONE || b == ZYDIS_REGISTER_NONE) {
				return false;
			}
			return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, a) ==
				ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, b);
		}
	} // namespace

	bool PEAnalyzer::ValidateHeaders(const uint8_t* data, size_t size, PIMAGE_NT_HEADERS64& nt) {
		nt = nullptr;
		if (size < sizeof(IMAGE_DOS_HEADER)) {
			return false;
		}
		const auto dos = (PIMAGE_DOS_HEADER)data;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
			return false;
		}
		// e_lfanew is a signed LONG: a negative value would wrap on conversion to
		// size_t, pass a naive size check and leave nt pointing before the buffer
		if (dos->e_lfanew < 0) {
			return false;
		}
		const size_t nt_off = (size_t)dos->e_lfanew;
		if (nt_off > size || size - nt_off < sizeof(IMAGE_NT_HEADERS64)) {
			return false;
		}
		const auto headers = (PIMAGE_NT_HEADERS64)(data + nt_off);
		if (headers->Signature != IMAGE_NT_SIGNATURE) {
			return false;
		}
		// everything below casts to the 64 bit header unconditionally, so both of
		// these have to hold before that cast is legal
		if (headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
			headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return false;
		}
		if (headers->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
			return false;
		}
		// the whole section table has to fit, end included
		const size_t table_off = nt_off + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
			headers->FileHeader.SizeOfOptionalHeader;
		const size_t table_size = (size_t)headers->FileHeader.NumberOfSections *
			sizeof(IMAGE_SECTION_HEADER);
		if (table_off > size || size - table_off < table_size) {
			return false;
		}
		nt = headers;
		return true;
	}

	std::vector<uint8_t> PEAnalyzer::FlattenImage(const uint8_t* data, size_t size) {
		PIMAGE_NT_HEADERS64 nt = nullptr;
		if (!ValidateHeaders(data, size, nt)) {
			return {};
		}
		const uint32_t image_size = nt->OptionalHeader.SizeOfImage;
		if (!image_size) {
			return {};
		}
		// value initialized, so inter-section gaps and BSS tails end up zero filled
		// the way a real loader leaves them
		std::vector<uint8_t> buf(image_size);
		const uint32_t header_size = nt->OptionalHeader.SizeOfHeaders;
		if (header_size > buf.size() || header_size > size) {
			return {};
		}
		memcpy(buf.data(), data, header_size);

		const auto sections = IMAGE_FIRST_SECTION(nt);
		for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
			const IMAGE_SECTION_HEADER& section = sections[i];
			const uint32_t raw_off = section.PointerToRawData;
			const uint32_t raw_size = section.SizeOfRawData;
			if (!raw_size) {
				continue;
			}
			if ((size_t)section.VirtualAddress + raw_size > buf.size() ||
				(size_t)raw_off + raw_size > size) {
				return {};
			}
			memcpy(&buf[section.VirtualAddress], data + raw_off, raw_size);
		}
		return buf;
	}

	bool PEAnalyzer::BuildSectionMap() {
		sections_.clear();
		const auto headers = IMAGE_FIRST_SECTION(nt_);
		for (uint16_t i = 0; i < nt_->FileHeader.NumberOfSections; ++i) {
			const IMAGE_SECTION_HEADER& header = headers[i];
			uint32_t vsize = header.Misc.VirtualSize ? header.Misc.VirtualSize : header.SizeOfRawData;
			if (!vsize || (size_t)header.VirtualAddress >= size_) {
				// a section outside the image is skipped rather than made a hard
				// error for every other section
				continue;
			}
			if ((size_t)header.VirtualAddress + vsize > size_) {
				vsize = (uint32_t)(size_ - header.VirtualAddress);
			}
			Section section;
			section.name.assign((const char*)header.Name,
				strnlen((const char*)header.Name, sizeof(header.Name)));
			section.va = header.VirtualAddress;
			section.vsize = vsize;
			section.characteristics = header.Characteristics;
			section.executable = (header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
			sections_.push_back(std::move(section));
		}
		if (sections_.empty() || sections_.size() >= kNoSection) {
			return false;
		}
		page_section_.assign((size_ >> 12) + 1, kNoSection);
		for (uint16_t i = 0; i < (uint16_t)sections_.size(); ++i) {
			const Section& section = sections_[i];
			const uint64_t last_page = (section.End() - 1) >> 12;
			for (uint64_t page = section.va >> 12; page <= last_page; ++page) {
				if (page < page_section_.size() && page_section_[page] == kNoSection) {
					page_section_[page] = i;
				}
			}
		}
		return true;
	}

	const Section* PEAnalyzer::SectionOf(uint64_t rva) const {
		if (rva >= size_ || page_section_.empty()) {
			return nullptr;
		}
		const uint16_t index = page_section_[rva >> 12];
		if (index == kNoSection) {
			return nullptr;
		}
		const Section& section = sections_[index];
		// the last page of a section reaches past VirtualSize into the alignment
		// tail, which belongs to no section
		return section.Contains(rva) ? &section : nullptr;
	}

	bool PEAnalyzer::Enqueue(uint64_t rva, uint64_t end) {
		if (rva >= size_) {
			return false;
		}
		// a target outside executable memory is not code, no matter what the
		// instruction that produced it looked like
		const Section* section = SectionOf(rva);
		if (!section || !section->executable) {
			return false;
		}
		if (queued_[rva] || starts_[rva]) {
			return false;
		}
		// never let a work item run past the end of its own section
		if (!end || end > section->End()) {
			end = section->End();
		}
		if (end <= rva) {
			return false;
		}
		queued_[rva] = true;
		work_list_.emplace_back(WorkItem{ .begin = rva, .end = end });
		return true;
	}

	void PEAnalyzer::MarkInstruction(uint64_t offset, uint8_t length) {
		starts_[offset] = true;
		for (uint8_t i = 0; i < length; ++i) {
			const uint64_t byte = offset + i;
			if (byte >= size_) {
				break;
			}
			// counted per byte instead of accumulating instruction lengths, so an
			// overlapping instruction stream cannot inflate the number
			if (!covered_[byte]) {
				covered_[byte] = true;
				++covered_bytes_;
			}
		}
		++stats_.instructions;
	}

	void PEAnalyzer::MarkData(uint64_t rva, uint64_t length) {
		for (uint64_t i = 0; i < length && rva + i < size_; ++i) {
			if (!covered_[rva + i] && !is_data_[rva + i]) {
				is_data_[rva + i] = true;
				++stats_.data_bytes;
			}
		}
	}

	bool PEAnalyzer::HandleInstruction(uint64_t offset, const ZydisDecodedInstruction& inst,
		const History& history) {
		const bool is_call = inst.meta.category == ZYDIS_CATEGORY_CALL;
		const bool is_uncond = inst.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
		const bool is_cond = inst.meta.category == ZYDIS_CATEGORY_COND_BR;

		if ((is_call || is_uncond || is_cond) && inst.operand_count) {
			ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
			if (ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder_, &ctx_, &inst,
				operands, inst.operand_count))) {
				const ZydisDecodedOperand& op = operands[0];
				if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
					// ZYDIS_ATTRIB_IS_RELATIVE is instruction level and also set for
					// call qword [rip+X], where the absolute address is the IAT slot
					// and not the callee. Only a relative immediate is a target.
					uint64_t target = 0;
					if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &op, offset, &target))) {
						Enqueue(target);
					}
				}
				else if (is_uncond) {
					TryJumpTable(inst, operands, history);
				}
			}
			else {
				// a failure here ends this run, never the whole walk
				++stats_.decode_failures;
			}
		}
		return is_uncond || inst.meta.category == ZYDIS_CATEGORY_RET;
	}

	size_t PEAnalyzer::Walk(const char* stage) {
		const size_t before = stats_.instructions;
		const size_t covered_before = covered_bytes_;
		const auto start = Clock::now();

		History history;
		ZydisDecodedInstruction inst{};
		for (size_t i = 0; i < work_list_.size(); ++i) {
			const WorkItem item = work_list_[i];
			if (opts_.progress && (i & 0xFFFFF) == 0) {
				printf("\r  %-10s walk %zu / %zu", stage, i, work_list_.size());
			}
			history.Clear();

			uint64_t offset = item.begin;
			while (offset < item.end) {
				if (starts_[offset]) {
					break;
				}
				if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(&decoder_, &ctx_,
					data_ + offset, (size_t)(item.end - offset), &inst))) {
					++stats_.decode_failures;
					break;
				}
				MarkInstruction(offset, inst.length);
				history.Push(offset);
				if (HandleInstruction(offset, inst, history)) {
					break;
				}
				offset += inst.length;
			}
		}
		const std::chrono::duration<double, std::milli> elapsed = Clock::now() - start;
		if (opts_.progress) {
			printf("\r  %-10s %10zu items  %10zu instr  +%9zu bytes  %8.0f ms\n",
				stage, work_list_.size(), stats_.instructions - before,
				covered_bytes_ - covered_before, elapsed.count());
		}

		stats_.work_items += work_list_.size();
		work_list_.clear();
		return stats_.instructions - before;
	}

	void PEAnalyzer::SeedEntryPoint() {
		const uint32_t entry = nt_->OptionalHeader.AddressOfEntryPoint;
		if (entry && Enqueue(entry)) {
			++stats_.seeds_entry;
		}
	}

	void PEAnalyzer::SeedRuntimeFunctions() {
		const PIMAGE_DATA_DIRECTORY dir =
			&nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (!dir->VirtualAddress || dir->Size < sizeof(RUNTIME_FUNCTION)) {
			return;
		}
		const Section* section = SectionOf(dir->VirtualAddress);
		if (!section) {
			return;
		}
		// the directory may start mid-section, so what is actually available is
		// what is left from its VA to the end of that section
		const uint64_t available = section->End() - dir->VirtualAddress;
		const uint64_t real_size = std::min<uint64_t>(dir->Size, available);
		if ((uint64_t)dir->VirtualAddress + real_size > size_) {
			return;
		}
		const auto functions = (const RUNTIME_FUNCTION*)(data_ + dir->VirtualAddress);
		const size_t count = (size_t)(real_size / sizeof(RUNTIME_FUNCTION));

		uint32_t prev_end = 0;
		for (size_t i = 0; i < count; ++i) {
			const RUNTIME_FUNCTION& fn = functions[i];
			// On a dumped image the header declared .pdata size overruns the real
			// table and the bytes past its end decode as IMAGE_BASE_RELOCATION
			// blocks, which have a similar shape. The first anomaly ends the table.
			if (fn.EndAddress <= fn.BeginAddress || fn.BeginAddress < prev_end) {
				break;
			}
			const Section* code = SectionOf(fn.BeginAddress);
			if (!code || !code->executable || fn.EndAddress > code->End()) {
				break;
			}
			prev_end = fn.EndAddress;
			if (Enqueue(fn.BeginAddress, fn.EndAddress)) {
				++stats_.seeds_pdata;
			}
			if (opts_.scan_unwind_handlers) {
				SeedUnwindHandler(fn.UnwindData);
			}
		}
	}

	void PEAnalyzer::SeedExports() {
		const PIMAGE_DATA_DIRECTORY dir =
			&nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!dir->VirtualAddress || dir->Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
			return;
		}
		if ((size_t)dir->VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) > size_) {
			return;
		}
		const auto exports = (const IMAGE_EXPORT_DIRECTORY*)(data_ + dir->VirtualAddress);
		const uint32_t table = exports->AddressOfFunctions;
		const uint32_t count = exports->NumberOfFunctions;
		if (!table || !count ||
			(size_t)table + (size_t)count * sizeof(uint32_t) > size_) {
			return;
		}
		for (uint32_t i = 0; i < count; ++i) {
			uint32_t rva = 0;
			memcpy(&rva, data_ + table + (size_t)i * sizeof(uint32_t), sizeof(rva));
			if (!rva) {
				continue;
			}
			// a forwarder entry points into the export directory itself
			if (rva >= dir->VirtualAddress && rva < dir->VirtualAddress + dir->Size) {
				continue;
			}
			if (Enqueue(rva)) {
				++stats_.seeds_exports;
			}
		}
	}

	void PEAnalyzer::SeedTlsCallbacks() {
		const PIMAGE_DATA_DIRECTORY dir =
			&nt_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (!dir->VirtualAddress || dir->Size < sizeof(IMAGE_TLS_DIRECTORY64) ||
			(size_t)dir->VirtualAddress + sizeof(IMAGE_TLS_DIRECTORY64) > size_) {
			return;
		}
		const auto tls = (const IMAGE_TLS_DIRECTORY64*)(data_ + dir->VirtualAddress);
		// AddressOfCallBacks is a VA pointing at a null terminated array of VAs
		if (tls->AddressOfCallBacks <= image_base_) {
			return;
		}
		uint64_t off = tls->AddressOfCallBacks - image_base_;
		for (size_t i = 0; i < kMaxTlsCallbacks; ++i) {
			if (off + sizeof(uint64_t) > size_) {
				break;
			}
			uint64_t va = 0;
			memcpy(&va, data_ + off, sizeof(va));
			if (!va || va <= image_base_) {
				break;
			}
			if (Enqueue(va - image_base_)) {
				++stats_.seeds_tls;
			}
			off += sizeof(uint64_t);
		}
	}

	void PEAnalyzer::SeedUnwindHandler(uint32_t unwind_rva) {
		// UNWIND_INFO is not in the public headers:
		//   +0  Version : 3, Flags : 5
		//   +1  SizeOfProlog
		//   +2  CountOfCodes
		//   +3  FrameRegister : 4, FrameOffset : 4
		//   +4  UnwindCode[CountOfCodes], padded to an even count
		//       then, with UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER, a handler RVA
		// Funclets get their own .pdata entries, so the scope table behind the
		// handler adds nothing that the seeding above has not already covered.
		constexpr uint8_t kFlagEHandler = 0x01;
		constexpr uint8_t kFlagUHandler = 0x02;

		if (!unwind_rva || (size_t)unwind_rva + 4 > size_) {
			return;
		}
		const uint8_t version = data_[unwind_rva] & 0x07;
		const uint8_t flags = (data_[unwind_rva] >> 3) & 0x1F;
		if ((version != 1 && version != 2) ||
			!(flags & (kFlagEHandler | kFlagUHandler))) {
			return;
		}
		const uint8_t code_count = data_[unwind_rva + 2];
		const uint64_t handler_off =
			(uint64_t)unwind_rva + 4 + (((uint64_t)code_count + 1) & ~1ull) * 2;
		if (handler_off + sizeof(uint32_t) > size_) {
			return;
		}
		uint32_t handler = 0;
		memcpy(&handler, data_ + handler_off, sizeof(handler));
		if (handler && Enqueue(handler)) {
			++stats_.seeds_handlers;
		}
	}

	void PEAnalyzer::SeedPointerScan() {
		// Functions that are only ever called indirectly - vtable slots, callbacks,
		// function pointer tables - are invisible to recursive descent. On a dumped
		// image .reloc is a stub, so harvesting relocations is not an option and the
		// pointers have to be found by scanning the data sections instead.
		const auto start = Clock::now();
		size_t candidates = 0;
		for (const Section& section : sections_) {
			if (section.executable ||
				!(section.characteristics & IMAGE_SCN_MEM_READ) ||
				(section.characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {
				continue;
			}
			const uint64_t begin = (section.va + 7) & ~7ull;
			for (uint64_t off = begin; off + sizeof(uint64_t) <= section.End(); off += 8) {
				uint64_t va = 0;
				memcpy(&va, data_ + off, sizeof(va));
				if (va <= image_base_) {
					continue;
				}
				const uint64_t rva = va - image_base_;
				if (rva >= size_) {
					continue;
				}
				// a value that lands inside an instruction we already decoded is a
				// coincidence, not a function pointer
				if (covered_[rva] && !starts_[rva]) {
					continue;
				}
				++candidates;
				if (Enqueue(rva)) {
					++stats_.seeds_pointers;
				}
			}
		}
		const std::chrono::duration<double, std::milli> elapsed = Clock::now() - start;
		if (opts_.progress) {
			printf("  %-10s %10zu candidates  %10zu new seeds  %8.0f ms\n",
				"pointers", candidates, stats_.seeds_pointers, elapsed.count());
		}
	}

	void PEAnalyzer::SeedPrologues() {
		// Targets the function-with-no-xrefs case: after the walk converges, look
		// for known prologues in whatever is still uncovered and seed those.
		const auto start = Clock::now();
		for (const Section& section : sections_) {
			if (!section.executable) {
				continue;
			}
			if (opts_.skip_writable_code && (section.characteristics & IMAGE_SCN_MEM_WRITE)) {
				continue;
			}
			for (uint64_t off = section.va; off < section.End(); ++off) {
				if (covered_[off] || is_data_[off]) {
					continue;
				}
				const uint8_t first = data_[off];
				if (first != 0x40 && first != 0x48 && first != 0x4C && first != 0x55) {
					continue;
				}
				for (const ProloguePattern& prologue : kPrologues) {
					if (off + prologue.length > section.End() ||
						memcmp(data_ + off, prologue.bytes, prologue.length) != 0) {
						continue;
					}
					if (Enqueue(off)) {
						++stats_.seeds_prologues;
					}
					break;
				}
			}
		}
		const std::chrono::duration<double, std::milli> elapsed = Clock::now() - start;
		if (opts_.progress) {
			printf("  %-10s %10zu new seeds %25s%8.0f ms\n",
				"prologues", stats_.seeds_prologues, "", elapsed.count());
		}
	}

	void PEAnalyzer::SweepGaps() {
		// Last resort: linear sweep over everything the other stages did not reach.
		// Unlike the walk this does not stop at ret or at an unconditional branch,
		// it just keeps decoding forward through the gap. Branch targets it finds
		// go back into the worklist, so the walk that follows picks them up.
		const auto start = Clock::now();
		const size_t before = stats_.instructions;
		History history;
		ZydisDecodedInstruction inst{};

		for (const Section& section : sections_) {
			if (!section.executable) {
				continue;
			}
			if (opts_.skip_writable_code && (section.characteristics & IMAGE_SCN_MEM_WRITE)) {
				continue;
			}
			history.Clear();
			uint64_t off = section.va;
			while (off < section.End()) {
				if (covered_[off] || is_data_[off]) {
					++off;
					continue;
				}
				// alignment padding: int3 fill and the zero fill between sections
				const uint8_t first = data_[off];
				if (first == 0x00 || first == 0xCC) {
					++off;
					continue;
				}
				if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(&decoder_, &ctx_,
					data_ + off, (size_t)(section.End() - off), &inst))) {
					++stats_.decode_failures;
					++off;
					continue;
				}
				MarkInstruction(off, inst.length);
				history.Push(off);
				if (HandleInstruction(off, inst, history)) {
					// a new run starts after a ret or a jmp, so the dispatch history
					// from the old one is meaningless
					history.Clear();
				}
				off += inst.length;
			}
		}
		stats_.sweep_instructions = stats_.instructions - before;
		const std::chrono::duration<double, std::milli> elapsed = Clock::now() - start;
		if (opts_.progress) {
			printf("  %-10s %10zu instr %27s%8.0f ms\n",
				"sweep", stats_.sweep_instructions, "", elapsed.count());
		}
	}

	void PEAnalyzer::TryJumpTable(const ZydisDecodedInstruction& inst,
		const ZydisDecodedOperand* operands, const History& history) {
		if (!opts_.scan_jump_tables || inst.mnemonic != ZYDIS_MNEMONIC_JMP) {
			return;
		}
		uint64_t table_rva = 0;
		// what the entries are relative to. Not the same thing as the table
		// address: MSVC's image base relative form keeps the table in the
		// displacement of the load and points the base register at the image base.
		uint64_t relative_base = 0;
		uint64_t count = 0;
		uint8_t entry_size = 0;
		bool table_relative = false;
		bool entries_signed = false;
		bool guessed_base = false;

		const ZydisDecodedOperand& target_op = operands[0];
		if (target_op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
			// jmp [table + idx*scale] - the non-PIC form. Entries are absolute
			// addresses, there is no lea/add pair to look for.
			if (target_op.mem.base != ZYDIS_REGISTER_NONE ||
				target_op.mem.index == ZYDIS_REGISTER_NONE ||
				!target_op.mem.disp.has_displacement) {
				return;
			}
			const uint64_t disp = (uint64_t)target_op.mem.disp.value;
			table_rva = disp >= image_base_ ? disp - image_base_ : disp;
			entry_size = target_op.mem.scale;
		}
		else if (target_op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
			// The MSVC x64 idiom:
			//   cmp   idx, N                 ; entry count is N + 1
			//   ja    default
			//   lea   base, [rip+X]          ; what the entries are relative to
			//   movsxd val, [base+idx*4+D]   ; table at base + D, scale = entry size
			//   add   val, base              ; target = relative base + entry
			//   jmp   val
			// Read scale, signedness and base off the instructions rather than
			// assuming them, so the other compilers stay one added branch away.
			// D is zero when the lea points at the table itself and the table RVA
			// when it points at the image base; both forms fall out of the same
			// three registers.
			const ZydisRegister value_reg = target_op.reg.value;
			ZydisRegister base_reg = ZYDIS_REGISTER_NONE;
			ZydisRegister index_reg = ZYDIS_REGISTER_NONE;
			ZydisRegister add_base = ZYDIS_REGISTER_NONE;
			ZydisRegister load_base = ZYDIS_REGISTER_NONE;
			int64_t load_disp = 0;
			bool have_add = false;
			bool have_load = false;
			bool have_base = false;

			ZydisDecodedInstruction prev{};
			ZydisDecodedOperand prev_ops[ZYDIS_MAX_OPERAND_COUNT];
			for (size_t back = 1; back < history.Depth(); ++back) {
				// the bounds check sits in front of the lea, so the scan cannot stop
				// at the table base if the entry count is still wanted
				if (have_base && count) {
					break;
				}
				const uint64_t prev_off = history.Get(back);
				if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder_, data_ + prev_off,
					size_ - prev_off, &prev, prev_ops))) {
					continue;
				}
				if (prev.operand_count_visible < 2) {
					continue;
				}
				const ZydisDecodedOperand& dst = prev_ops[0];
				const ZydisDecodedOperand& src = prev_ops[1];

				// the entry count comes from the bounds check in front of the
				// dispatch: cmp against the index register, so the immediate of an
				// unrelated cmp in the window is not mistaken for the count
				if (!count && prev.mnemonic == ZYDIS_MNEMONIC_CMP &&
					src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
					dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
					SameRegister(dst.reg.value, index_reg)) {
					count = src.imm.value.u + 1;
					continue;
				}
				// the bounds check usually runs on the register the index was
				// widened from (cmp ax, 3 / movzx r8d, ax / [rdx+r8*4]), so follow
				// the index back through moves and extends
				if (have_load && dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
					src.type == ZYDIS_OPERAND_TYPE_REGISTER &&
					SameRegister(dst.reg.value, index_reg) &&
					(prev.mnemonic == ZYDIS_MNEMONIC_MOV ||
						prev.mnemonic == ZYDIS_MNEMONIC_MOVZX ||
						prev.mnemonic == ZYDIS_MNEMONIC_MOVSX ||
						prev.mnemonic == ZYDIS_MNEMONIC_MOVSXD)) {
					index_reg = src.reg.value;
					continue;
				}
				if (!have_add && prev.mnemonic == ZYDIS_MNEMONIC_ADD &&
					dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
					src.type == ZYDIS_OPERAND_TYPE_REGISTER &&
					SameRegister(dst.reg.value, value_reg)) {
					base_reg = src.reg.value;
					add_base = src.reg.value;
					table_relative = true;
					have_add = true;
					continue;
				}
				if (!have_load && dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
					src.type == ZYDIS_OPERAND_TYPE_MEMORY &&
					src.mem.index != ZYDIS_REGISTER_NONE &&
					SameRegister(dst.reg.value, value_reg) &&
					(prev.mnemonic == ZYDIS_MNEMONIC_MOVSXD ||
						prev.mnemonic == ZYDIS_MNEMONIC_MOV ||
						prev.mnemonic == ZYDIS_MNEMONIC_MOVZX)) {
					// the signedness comes from the load opcode, not from convention
					entries_signed = prev.mnemonic == ZYDIS_MNEMONIC_MOVSXD;
					entry_size = src.mem.scale;
					index_reg = src.mem.index;
					load_base = src.mem.base;
					load_disp = src.mem.disp.has_displacement ? src.mem.disp.value : 0;
					if (src.mem.base != ZYDIS_REGISTER_NONE) {
						base_reg = src.mem.base;
					}
					have_load = true;
					continue;
				}
				if ((have_add || have_load) && prev.mnemonic == ZYDIS_MNEMONIC_LEA &&
					dst.type == ZYDIS_OPERAND_TYPE_REGISTER &&
					src.type == ZYDIS_OPERAND_TYPE_MEMORY &&
					src.mem.base == ZYDIS_REGISTER_RIP &&
					SameRegister(dst.reg.value, base_reg)) {
					// the base is whatever the lea resolves to, never the address
					// the dispatch happens to sit next to
					uint64_t resolved = 0;
					if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&prev, &src, prev_off, &resolved))) {
						relative_base = resolved;
						have_base = true;
					}
				}
			}
			if (!have_load) {
				return;
			}
			if (!have_base) {
				// MSVC hoists `lea base, __ImageBase` out of loops and reuses the
				// register across several dispatches, so it is regularly set far
				// outside the history window. Only that form gets here, and it is
				// always image base relative, so assume RVA 0 and make the table
				// itself confirm the guess below.
				if (!have_add || load_base == ZYDIS_REGISTER_NONE ||
					!SameRegister(add_base, load_base) || load_disp <= 0) {
					return;
				}
				relative_base = 0;
				guessed_base = true;
			}
			const int64_t table = (int64_t)relative_base + load_disp;
			if (table <= 0 || (uint64_t)table >= size_) {
				return;
			}
			table_rva = (uint64_t)table;
		}
		else {
			return;
		}

		if (!table_rva || (entry_size != 4 && entry_size != 8)) {
			return;
		}
		const Section* table_section = SectionOf(table_rva);
		if (!table_section) {
			return;
		}
		const bool have_count = count != 0 && count <= kMaxJumpTableEntries;
		if (!have_count) {
			count = kMaxJumpTableEntries;
		}

		// resolving is kept separate from enqueueing so a guessed relative base
		// can be rejected on the whole table before anything is seeded from it
		const auto resolve = [&](uint64_t index, uint64_t& out) {
			const uint64_t entry_off = table_rva + index * entry_size;
			if (entry_off + entry_size > table_section->End()) {
				return false;
			}
			int64_t value = 0;
			if (entry_size == 4) {
				int32_t raw = 0;
				memcpy(&raw, data_ + entry_off, sizeof(raw));
				value = entries_signed ? (int64_t)raw : (int64_t)(uint32_t)raw;
			}
			else {
				memcpy(&value, data_ + entry_off, sizeof(value));
			}
			if (table_relative) {
				out = (uint64_t)((int64_t)relative_base + value);
			}
			else {
				if ((uint64_t)value < image_base_) {
					return false;
				}
				out = (uint64_t)value - image_base_;
			}
			const Section* target_section = SectionOf(out);
			return target_section != nullptr && target_section->executable;
		};

		uint64_t entries = 0;
		uint64_t target = 0;
		while (entries < count && resolve(entries, target)) {
			++entries;
		}
		if (!entries) {
			return;
		}
		// without a lea the base is an assumption, so the table has to confirm it:
		// the whole bounds checked size has to resolve, or, when the check sits in
		// another basic block and the history never saw it, enough entries in a row
		// that they cannot be an unrelated array of integers
		if (guessed_base && (have_count ? entries != count : entries < kMinGuessedEntries)) {
			return;
		}

		uint64_t added = 0;
		for (uint64_t i = 0; i < entries; ++i) {
			if (resolve(i, target) && Enqueue(target)) {
				++added;
			}
		}
		MarkData(table_rva, entries * entry_size);
		stats_.seeds_jump_tables += added;
		++stats_.jump_tables;
	}

	size_t PEAnalyzer::CountCovered(const Section& section) const {
		size_t count = 0;
		for (uint64_t rva = section.va; rva < section.End(); ++rva) {
			if (covered_[rva]) {
				++count;
			}
		}
		return count;
	}

	bool PEAnalyzer::Analyze(const uint8_t* data, size_t size, bool loaded,
		const AnalysisOptions& options) {
		if (!data || !size) {
			return false;
		}
		opts_ = options;
		data_ = nullptr;
		owned_.clear();

		if (loaded) {
			data_ = data;
			size_ = size;
		}
		else {
			owned_ = FlattenImage(data, size);
			if (owned_.empty()) {
				printf("PEAnalyzer: failed to flatten the image\n");
				return false;
			}
			data_ = owned_.data();
			size_ = owned_.size();
		}
		if (!ValidateHeaders(data_, size_, nt_)) {
			printf("PEAnalyzer: not a valid 64 bit PE image\n");
			data_ = nullptr;
			return false;
		}
		image_base_ = nt_->OptionalHeader.ImageBase;
		if (!BuildSectionMap()) {
			printf("PEAnalyzer: no usable sections\n");
			data_ = nullptr;
			return false;
		}
		if (ZYAN_FAILED(ZydisDecoderInit(&decoder_,
			ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
			printf("PEAnalyzer: failed to initialize the decoder\n");
			data_ = nullptr;
			return false;
		}

		starts_.assign(size_, false);
		covered_.assign(size_, false);
		queued_.assign(size_, false);
		is_data_.assign(size_, false);
		work_list_.clear();
		stats_ = {};
		covered_bytes_ = 0;

		const auto start = Clock::now();

		SeedEntryPoint();
		SeedRuntimeFunctions();
		if (opts_.scan_exports) {
			SeedExports();
		}
		if (opts_.scan_tls) {
			SeedTlsCallbacks();
		}
		Walk("descent");

		if (opts_.scan_pointers) {
			SeedPointerScan();
			Walk("pointers");
		}
		if (opts_.scan_prologues) {
			SeedPrologues();
			Walk("prologues");
		}
		if (opts_.sweep_gaps) {
			SweepGaps();
			Walk("sweep");
		}

		const std::chrono::duration<double, std::milli> elapsed = Clock::now() - start;
		analysis_ms_ = elapsed.count();
		return true;
	}

	void PEAnalyzer::PrintReport() const {
		if (!IsAnalyzed()) {
			return;
		}
		printf("\nimage base 0x%llX, image size 0x%zX (%zu bytes)\n",
			(unsigned long long)image_base_, size_, size_);
		printf("%-10s %-12s %-12s %-14s %-8s %s\n",
			"section", "va", "vsize", "covered", "cov%", "flags");

		size_t exec_size = 0;
		size_t exec_covered = 0;
		for (const Section& section : sections_) {
			const size_t covered = CountCovered(section);
			char flags[5] = "----";
			flags[0] = section.executable ? 'X' : '-';
			flags[1] = (section.characteristics & IMAGE_SCN_MEM_WRITE) ? 'W' : '-';
			flags[2] = (section.characteristics & IMAGE_SCN_MEM_READ) ? 'R' : '-';
			flags[3] = (section.characteristics & IMAGE_SCN_MEM_SHARED) ? 'S' : '-';
			printf("%-10s 0x%08X   0x%08X   %-14zu %6.2f%%  %s\n",
				section.name.c_str(), section.va, section.vsize, covered,
				section.vsize ? 100.0 * covered / section.vsize : 0.0, flags);
			if (section.executable) {
				exec_size += section.vsize;
				exec_covered += covered;
			}
		}
		printf("\nexecutable total: %zu / %zu bytes (%.2f%%)\n",
			exec_covered, exec_size, exec_size ? 100.0 * exec_covered / exec_size : 0.0);
		printf("instructions:     %zu (%zu from the gap sweep)\n",
			stats_.instructions, stats_.sweep_instructions);
		printf("work items:       %zu\n", stats_.work_items);
		printf("decode failures:  %zu\n", stats_.decode_failures);
		printf("jump tables:      %zu (%zu bytes marked as data)\n",
			stats_.jump_tables, stats_.data_bytes);
		printf("seeds:            entry %zu, pdata %zu, exports %zu, tls %zu, "
			"handlers %zu,\n                  pointers %zu, jump tables %zu, "
			"prologues %zu\n",
			stats_.seeds_entry, stats_.seeds_pdata, stats_.seeds_exports,
			stats_.seeds_tls, stats_.seeds_handlers, stats_.seeds_pointers,
			stats_.seeds_jump_tables, stats_.seeds_prologues);
		printf("analysis time:    %.0f ms\n", analysis_ms_);
	}
} // namespace zigil::analyzer
