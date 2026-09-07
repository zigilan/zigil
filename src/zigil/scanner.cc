#include "zigil/scanner.hh"

#include <algorithm>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <variant>

namespace zigil {
	namespace {
		// the parser resolves register names through tables.hh, and [rip+...] only
		// works if that table agrees with the enum the decoder reports
		static_assert(tables::FindRegister("rip") == ZYDIS_REGISTER_RIP,
			"register table is out of sync with the Zydis enum");

		constexpr uint8_t kNoVariable = 0xFF;
		/* an x86-64 instruction is never longer than this */
		constexpr size_t kMaxInstructionLength = 16;
		/* below this a range is not worth handing to a thread of its own */
		constexpr uint64_t kMinScanChunk = 1ull << 20;

		/*
		* A limited scan stays on the calling thread. It stops as soon as it has
		* enough matches, so which ones it keeps would otherwise depend on which
		* worker reached its range first.
		*/
		unsigned WorkerCount(unsigned requested, size_t limit_each) {
			if (limit_each) {
				return 1;
			}
			if (requested) {
				return requested;
			}
			const unsigned hardware = std::thread::hardware_concurrency();
			return hardware ? hardware : 1;
		}

		constexpr uint64_t WidthMask(uint8_t bits) {
			return (bits == 0 || bits >= 64) ? ~0ull : (1ull << bits) - 1;
		}
		/*
		* Immediates and displacements are compared as bit patterns truncated to the
		* width the instruction actually encodes them with, so `-1` and `0xFFFFFFFF`
		* both match an imm32 of 0xFFFFFFFF.
		*/
		bool ValueEquals(int64_t a, int64_t b, uint8_t bits) {
			const uint64_t mask = WidthMask(bits);
			return ((uint64_t)a & mask) == ((uint64_t)b & mask);
		}
		/*
		* Two captures are compared at the narrower of the two widths, and an
		* unset width means "the full 64 bits". Written out because the ternaries
		* promote their uint8_t operands to int, so the result has to be narrowed
		* back deliberately rather than by an implicit conversion at the call.
		*/
		uint8_t CommonWidth(uint8_t a, uint8_t b) {
			return (uint8_t)std::min(a ? a : 64, b ? b : 64);
		}
		bool SameEnclosingRegister(ZydisRegister a, ZydisRegister b) {
			if (a == ZYDIS_REGISTER_NONE || b == ZYDIS_REGISTER_NONE) {
				return false;
			}
			return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, a) ==
				ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, b);
		}
		bool RegMatchesWidth(ZydisRegister reg, RegWidth width) {
			if (width == RegWidth::kNone || width == RegWidth::kAny) {
				return true;
			}
			const ZydisRegisterClass reg_class = ZydisRegisterGetClass(reg);
			switch (width) {
			case RegWidth::k8:   return reg_class == ZYDIS_REGCLASS_GPR8;
			case RegWidth::k16:  return reg_class == ZYDIS_REGCLASS_GPR16;
			case RegWidth::k32:  return reg_class == ZYDIS_REGCLASS_GPR32;
			case RegWidth::k64:  return reg_class == ZYDIS_REGCLASS_GPR64;
			case RegWidth::kXmm: return reg_class == ZYDIS_REGCLASS_XMM;
			case RegWidth::kYmm: return reg_class == ZYDIS_REGCLASS_YMM;
			case RegWidth::kZmm: return reg_class == ZYDIS_REGCLASS_ZMM;
			default: return false;
			}
		}
		bool IsRipBase(ZydisRegister reg) {
			return reg == ZYDIS_REGISTER_RIP || reg == ZYDIS_REGISTER_EIP;
		}
		const char* CaptureKindToString(CaptureKind kind) {
			switch (kind) {
			case CaptureKind::kRegister:  return "register";
			case CaptureKind::kImmediate: return "immediate";
			case CaptureKind::kAddress:   return "address";
			case CaptureKind::kMemory:    return "memory";
			default: return "unbound";
			}
		}
	} // namespace

	void MatchResult::Print() const {
		printf("match at rva 0x%llX (va 0x%llX)\n",
			(unsigned long long)rva_, (unsigned long long)Va());
		for (size_t i = 0; i < captures_.size(); i++) {
			const Capture& capture = captures_[i];
			printf("  $v%zu %-10s ", i, CaptureKindToString(capture.kind));
			switch (capture.kind) {
			case CaptureKind::kRegister:
				printf("%s\n", tables::RegisterToString(capture.reg).data());
				break;
			case CaptureKind::kImmediate:
				printf("0x%llX (%lld)\n",
					(unsigned long long)capture.value, (long long)capture.value);
				break;
			case CaptureKind::kAddress:
				printf("rva 0x%llX, va 0x%llX\n",
					(unsigned long long)capture.value,
					(unsigned long long)(image_base_ + (uint64_t)capture.value));
				break;
			case CaptureKind::kMemory:
				printf("[%s + %s*%u + 0x%llX]\n",
					tables::RegisterToString(capture.mem_base).data(),
					tables::RegisterToString(capture.mem_index).data(),
					capture.mem_scale, (unsigned long long)capture.value);
				break;
			default:
				printf("\n");
				break;
			}
		}
	}

	Scanner::Scanner(const analyzer::PEAnalyzer& analyzer) : analyzer_(&analyzer) {
		image_ = analyzer.Image();
		size_ = analyzer.ImageSize();
		starts_ = &analyzer.InstructionStarts();
		ZydisDecoderInit(&decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	}

	void Scanner::SetCapture(std::string_view name, const Capture& capture) {
		const uint64_t hash = detail::Fnv1a(name);
		for (PreBound& bound : prebound_) {
			if (bound.hash == hash) {
				bound.capture = capture;
				return;
			}
		}
		prebound_.emplace_back(PreBound{ .hash = hash, .capture = capture });
	}

	void Scanner::Set(std::string_view name, ZydisRegister reg) {
		Capture capture;
		capture.kind = CaptureKind::kRegister;
		capture.reg = reg;
		SetCapture(name, capture);
	}

	void Scanner::SetAddress(std::string_view name, uint64_t rva) {
		Capture capture;
		capture.kind = CaptureKind::kAddress;
		capture.value = (int64_t)rva;
		capture.width = 64;
		SetCapture(name, capture);
	}

	void Scanner::SetImmediate(std::string_view name, int64_t value, uint8_t width) {
		Capture capture;
		capture.kind = CaptureKind::kImmediate;
		capture.value = value;
		capture.width = width;
		SetCapture(name, capture);
	}

	void Scanner::Set(std::string_view name, uint64_t value) {
		Capture capture;
		capture.kind = CaptureKind::kImmediate;
		capture.value = (int64_t)value;
		// the caller cannot know whether the operand will decode as an immediate
		// or as a rip-relative address, so accept either
		capture.numeric_any = true;
		SetCapture(name, capture);
	}

	void Scanner::Unset(std::string_view name) {
		const uint64_t hash = detail::Fnv1a(name);
		for (size_t i = 0; i < prebound_.size(); i++) {
			if (prebound_[i].hash == hash) {
				prebound_.erase(prebound_.begin() + i);
				return;
			}
		}
	}

	const Capture* Scanner::PreboundFor(PatternView pattern, uint8_t var_idx) const {
		if (var_idx >= pattern.variable_hashes.size()) {
			return nullptr;
		}
		const uint64_t hash = pattern.variable_hashes[var_idx];
		for (const PreBound& bound : prebound_) {
			if (bound.hash == hash) {
				return &bound.capture;
			}
		}
		return nullptr;
	}

	std::vector<Capture> Scanner::SeedCaptures(PatternView pattern) const {
		std::vector<Capture> captures(pattern.variable_hashes.size());
		for (const PreBound& bound : prebound_) {
			const uint8_t index = pattern.IndexOf(bound.hash);
			if (index != kNoVariable && index < captures.size()) {
				captures[index] = bound.capture;
			}
		}
		return captures;
	}

	bool Scanner::ValidatePrebound(PatternView pattern) const {
		if (prebound_.empty()) {
			return true;
		}
		bool ok = true;
		const auto check = [&](uint8_t var_idx, bool wants_register, RegWidth width) {
			if (var_idx == kNoVariable) {
				return;
			}
			const Capture* seeded = PreboundFor(pattern, var_idx);
			if (!seeded || seeded->kind == CaptureKind::kNone) {
				return;
			}
			const bool is_register = seeded->kind == CaptureKind::kRegister;
			if (wants_register != is_register) {
				printf("pre-bound $v%u is a %s but the pattern uses it as a %s\n",
					var_idx, CaptureKindToString(seeded->kind),
					wants_register ? "register" : "value");
				ok = false;
				return;
			}
			// the type suffix is an assertion on a pre-bound value
			if (is_register && !RegMatchesWidth(seeded->reg, width)) {
				printf("pre-bound $v%u is %s, which is not %s\n", var_idx,
					tables::RegisterToString(seeded->reg).data(),
					RegWidthToString(width).data());
				ok = false;
			}
		};
		for (const Instruction& instruction : pattern.instructions) {
			const MatchInstruction* match = std::get_if<MatchInstruction>(&instruction);
			if (!match) {
				continue;
			}
			for (uint8_t i = 0; i < match->operand_count; i++) {
				const Operand& op = match->operands[i];
				switch (op.type) {
				case OperandType::kRegister:
					if (op.reg.is_wildcard) {
						check(op.reg.var_idx, true, op.reg.width);
					}
					break;
				case OperandType::kImmediate:
					if (op.imm.is_wildcard) {
						check(op.imm.var_idx, false, RegWidth::kNone);
					}
					break;
				case OperandType::kMemory:
					if (op.mem.has_base && op.mem.base.is_wildcard) {
						check(op.mem.base.var_idx, true, op.mem.base.width);
					}
					if (op.mem.has_index && op.mem.index.is_wildcard) {
						check(op.mem.index.var_idx, true, op.mem.index.width);
						if (op.mem.scale.is_wildcard) {
							check(op.mem.scale.var_idx, false, RegWidth::kNone);
						}
					}
					if (op.mem.has_disp && op.mem.disp.is_wildcard) {
						check(op.mem.disp.var_idx, false, RegWidth::kNone);
					}
					break;
				case OperandType::kWildcard:
				default:
					// a bare ? takes whatever the operand turns out to be
					break;
				}
			}
		}
		return ok;
	}

	bool Scanner::Decode(uint64_t rva, ZydisDecodedInstruction& inst) const {
		if (!image_ || rva >= size_) {
			return false;
		}
		const size_t left = std::min<size_t>(size_ - rva, kMaxInstructionLength);
		return ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
			&decoder_, nullptr, image_ + rva, left, &inst));
	}

	bool Scanner::DecodeFull(uint64_t rva, ZydisDecodedInstruction& inst,
		ZydisDecodedOperand* operands) const {
		if (!image_ || rva >= size_) {
			return false;
		}
		const size_t left = std::min<size_t>(size_ - rva, kMaxInstructionLength);
		return ZYAN_SUCCESS(ZydisDecoderDecodeFull(
			&decoder_, image_ + rva, left, &inst, operands));
	}

	uint64_t Scanner::NextStart(uint64_t rva, uint8_t length) const {
		const analyzer::Section* section = analyzer_->SectionOf(rva);
		if (!section) {
			return 0;
		}
		// starting at rva + length rather than rva + 1 keeps an overlapping
		// instruction stream from being mistaken for the next instruction
		for (uint64_t next = rva + length; next < section->End(); ++next) {
			if ((*starts_)[next]) {
				return next;
			}
		}
		return 0;
	}

	Capture Scanner::CaptureFromOperand(const ZydisDecodedInstruction& inst,
		const ZydisDecodedOperand& op, uint8_t imm_slot, uint64_t rva) const {
		Capture capture;
		switch (op.type) {
		case ZYDIS_OPERAND_TYPE_REGISTER:
			capture.kind = CaptureKind::kRegister;
			capture.reg = op.reg.value;
			break;
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			capture.kind = CaptureKind::kImmediate;
			capture.value = (int64_t)op.imm.value.u;
			capture.width = inst.raw.imm[imm_slot].size;
			if (op.imm.is_relative) {
				// a branch target is an address, not a number
				uint64_t target = 0;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &op, rva, &target))) {
					capture.kind = CaptureKind::kAddress;
					capture.value = (int64_t)target;
					capture.width = 64;
				}
			}
			break;
		case ZYDIS_OPERAND_TYPE_MEMORY:
			if (IsRipBase(op.mem.base)) {
				// rip-relative operands resolve to an effective address; store the
				// RVA, which is what the user actually wants out of [rip+X]
				uint64_t target = 0;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst, &op, rva, &target))) {
					capture.kind = CaptureKind::kAddress;
					capture.value = (int64_t)target;
					capture.width = 64;
					break;
				}
			}
			capture.kind = CaptureKind::kMemory;
			capture.mem_segment = op.mem.segment;
			capture.mem_base = op.mem.base;
			capture.mem_index = op.mem.index;
			capture.mem_scale = op.mem.scale;
			capture.value = op.mem.disp.has_displacement ? op.mem.disp.value : 0;
			capture.width = inst.raw.disp.size;
			break;
		default:
			break;
		}
		return capture;
	}

	bool Scanner::BindOrCheck(uint8_t var_idx, const Capture& value, RegWidth width,
		std::vector<Capture>& captures) const {
		if (var_idx == kNoVariable) {
			return true;
		}
		if (var_idx >= captures.size() || value.kind == CaptureKind::kNone) {
			return false;
		}
		Capture& slot = captures[var_idx];
		// a variable is immutable once bound: the first occurrence captures, every
		// later one compares
		if (slot.kind == CaptureKind::kNone) {
			slot = value;
			return true;
		}
		if (slot.kind != value.kind) {
			// a pre-bound plain number satisfies both an immediate and a resolved
			// address, since the caller cannot know which one the operand yields
			const bool both_numeric =
				(slot.kind == CaptureKind::kImmediate || slot.kind == CaptureKind::kAddress) &&
				(value.kind == CaptureKind::kImmediate || value.kind == CaptureKind::kAddress);
			if (!slot.numeric_any || !both_numeric) {
				return false;
			}
			if (!ValueEquals(slot.value, value.value,
				CommonWidth(slot.width, value.width))) {
				return false;
			}
			// the value stands, but now that the operand has been seen the kind is
			// known: adopt it so the capture reports as what it actually is. This
			// is not a rebind - the value does not change - and a backtrack
			// restores the snapshot anyway.
			slot.kind = value.kind;
			slot.width = value.width;
			return true;
		}
		switch (slot.kind) {
		case CaptureKind::kRegister:
			// :* relaxes the width constraint on reuse, so rax and eax are the same
			// register there and only there
			return width == RegWidth::kAny
				? SameEnclosingRegister(slot.reg, value.reg)
				: slot.reg == value.reg;
		case CaptureKind::kImmediate:
			return ValueEquals(slot.value, value.value,
				CommonWidth(slot.width, value.width));
		case CaptureKind::kAddress:
			return slot.value == value.value;
		case CaptureKind::kMemory:
			return slot.mem_segment == value.mem_segment &&
				slot.mem_base == value.mem_base &&
				slot.mem_index == value.mem_index &&
				slot.mem_scale == value.mem_scale &&
				ValueEquals(slot.value, value.value,
					CommonWidth(slot.width, value.width));
		default:
			return false;
		}
	}

	bool Scanner::MatchMemory(const MemOperand& pattern, const ZydisDecodedInstruction& inst,
		const ZydisDecodedOperand& op, uint64_t rva, std::vector<Capture>& captures) const {
		if (pattern.is_full_wildcard) {
			return true;
		}
		if (pattern.has_segment && op.mem.segment != pattern.segment.reg) {
			return false;
		}
		if (pattern.has_base) {
			if (!pattern.base.is_wildcard) {
				if (op.mem.base != pattern.base.reg) {
					return false;
				}
			}
			else {
				if (op.mem.base == ZYDIS_REGISTER_NONE ||
					!RegMatchesWidth(op.mem.base, pattern.base.width)) {
					return false;
				}
				Capture capture;
				capture.kind = CaptureKind::kRegister;
				capture.reg = op.mem.base;
				if (!BindOrCheck(pattern.base.var_idx, capture, pattern.base.width, captures)) {
					return false;
				}
			}
		}
		else if (op.mem.base != ZYDIS_REGISTER_NONE) {
			return false;
		}
		if (pattern.has_index) {
			if (!pattern.index.is_wildcard) {
				if (op.mem.index != pattern.index.reg) {
					return false;
				}
			}
			else {
				if (op.mem.index == ZYDIS_REGISTER_NONE ||
					!RegMatchesWidth(op.mem.index, pattern.index.width)) {
					return false;
				}
				Capture capture;
				capture.kind = CaptureKind::kRegister;
				capture.reg = op.mem.index;
				if (!BindOrCheck(pattern.index.var_idx, capture, pattern.index.width, captures)) {
					return false;
				}
			}
			if (!pattern.scale.is_wildcard) {
				if ((int64_t)op.mem.scale != pattern.scale.value) {
					return false;
				}
			}
			else {
				Capture capture;
				capture.kind = CaptureKind::kImmediate;
				capture.value = op.mem.scale;
				capture.width = 8;
				if (!BindOrCheck(pattern.scale.var_idx, capture, RegWidth::kNone, captures)) {
					return false;
				}
			}
		}
		else if (op.mem.index != ZYDIS_REGISTER_NONE) {
			return false;
		}
		const int64_t disp = op.mem.disp.has_displacement ? op.mem.disp.value : 0;
		if (pattern.has_disp) {
			if (!pattern.disp.is_wildcard) {
				return ValueEquals(pattern.disp.value, disp, inst.raw.disp.size);
			}
			// [rip+$var] captures the effective address, not the raw displacement
			Capture capture;
			if (IsRipBase(op.mem.base)) {
				capture = CaptureFromOperand(inst, op, 0, rva);
			}
			else {
				capture.kind = CaptureKind::kImmediate;
				capture.value = disp;
				capture.width = inst.raw.disp.size;
			}
			return BindOrCheck(pattern.disp.var_idx, capture, RegWidth::kNone, captures);
		}
		// a pattern that writes no displacement only matches an instruction that
		// encodes none, or encodes one that is zero
		return disp == 0;
	}

	bool Scanner::MatchOperand(const Operand& pattern, const ZydisDecodedInstruction& inst,
		const ZydisDecodedOperand& op, uint8_t imm_slot, uint64_t rva,
		std::vector<Capture>& captures) const {
		switch (pattern.type) {
		case OperandType::kWildcard: {
			// ? matches any operand at all; $var additionally captures whatever it is
			if (pattern.var_idx == kNoVariable) {
				return true;
			}
			const Capture capture = CaptureFromOperand(inst, op, imm_slot, rva);
			return BindOrCheck(pattern.var_idx, capture, RegWidth::kNone, captures);
		}
		case OperandType::kRegister: {
			if (op.type != ZYDIS_OPERAND_TYPE_REGISTER) {
				return false;
			}
			if (!pattern.reg.is_wildcard) {
				return op.reg.value == pattern.reg.reg;
			}
			if (!RegMatchesWidth(op.reg.value, pattern.reg.width)) {
				return false;
			}
			Capture capture;
			capture.kind = CaptureKind::kRegister;
			capture.reg = op.reg.value;
			return BindOrCheck(pattern.reg.var_idx, capture, pattern.reg.width, captures);
		}
		case OperandType::kImmediate: {
			if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				return false;
			}
			if (!pattern.imm.is_wildcard) {
				return ValueEquals(pattern.imm.value, (int64_t)op.imm.value.u,
					inst.raw.imm[imm_slot].size);
			}
			const Capture capture = CaptureFromOperand(inst, op, imm_slot, rva);
			return BindOrCheck(pattern.imm.var_idx, capture, RegWidth::kNone, captures);
		}
		case OperandType::kMemory:
			if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) {
				return false;
			}
			return MatchMemory(pattern.mem, inst, op, rva, captures);
		default:
			return false;
		}
	}

	bool Scanner::MatchInstructionAt(const MatchInstruction& pattern, uint64_t rva,
		std::vector<Capture>& captures, uint8_t& length,
		const DecodedInstruction* decoded) const {
		DecodedInstruction own;
		if (!decoded) {
			if (!DecodeFull(rva, own.inst, own.operands)) {
				return false;
			}
			decoded = &own;
		}
		const ZydisDecodedInstruction& inst = decoded->inst;
		const ZydisDecodedOperand* operands = decoded->operands;
		length = inst.length;
		// prefixes are attributes, not mnemonics, so `movsb` matches `rep movsb`
		if (inst.mnemonic != pattern.mnemonic) {
			return false;
		}
		if (pattern.operand_count > inst.operand_count_visible) {
			return false;
		}
		// the pattern has to cover every explicit operand; implicit ones (rax in
		// `mul rcx`, the 1 in `shl rax, 1`) may be left out
		for (uint8_t i = pattern.operand_count; i < inst.operand_count_visible; i++) {
			if (operands[i].visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT) {
				return false;
			}
		}
		// An instruction encodes at most two immediates (enter imm16, imm8), and
		// Zydis reports their encoded widths in raw.imm[0] and raw.imm[1] in that
		// order. Taking raw.imm[0] for both would compare the second one at the
		// first one's width.
		uint8_t imm_slot = 0;
		for (uint8_t i = 0; i < pattern.operand_count; i++) {
			if (!MatchOperand(pattern.operands[i], inst, operands[i], imm_slot, rva,
				captures)) {
				return false;
			}
			if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && imm_slot == 0) {
				imm_slot = 1;
			}
		}
		return true;
	}

	bool Scanner::MatchFrom(PatternView pattern, size_t index, uint64_t rva,
		std::vector<Capture>& captures, uint64_t& next_rva,
		const DecodedInstruction* decoded) const {
		if (index >= pattern.instructions.size()) {
			next_rva = rva;
			return true;
		}
		if (!rva) {
			return false;
		}
		const Instruction& current = pattern.instructions[index];
		if (const SkipRange* skip = std::get_if<SkipRange>(&current)) {
			const uint64_t hi = std::min<uint64_t>(skip->hi, skip_limit_);
			uint64_t cursor = rva;
			for (uint64_t skipped = 0; ; ++skipped) {
				if (skipped >= skip->lo) {
					// every gap length is its own branch, so the captures have to be
					// rolled back before the next one is tried
					std::vector<Capture> snapshot = captures;
					if (MatchFrom(pattern, index + 1, cursor, captures, next_rva, nullptr)) {
						return true;
					}
					captures = std::move(snapshot);
				}
				if (skipped >= hi || !cursor) {
					return false;
				}
				ZydisDecodedInstruction inst{};
				if (!Decode(cursor, inst)) {
					return false;
				}
				cursor = NextStart(cursor, inst.length);
				if (!cursor) {
					return false;
				}
			}
		}
		const MatchInstruction& match = std::get<MatchInstruction>(current);
		uint8_t length = 0;
		if (!MatchInstructionAt(match, rva, captures, length, decoded)) {
			return false;
		}
		if (index + 1 >= pattern.instructions.size()) {
			next_rva = NextStart(rva, length);
			return true;
		}
		return MatchFrom(pattern, index + 1, NextStart(rva, length), captures, next_rva, nullptr);
	}

	bool Scanner::MatchAt(PatternView pattern, uint64_t rva, const std::vector<Capture>& seed,
		std::vector<Capture>& scratch, const DecodedInstruction* decoded,
		MatchResult& out) const {
		// assign rather than construct: keeps the buffer's capacity between
		// candidates, so a failed match costs no allocation at all
		scratch.assign(seed.begin(), seed.end());
		uint64_t next_rva = 0;
		if (!MatchFrom(pattern, 0, rva, scratch, next_rva, decoded)) {
			return false;
		}
		out.rva_ = rva;
		out.next_rva_ = next_rva;
		out.image_base_ = analyzer_->ImageBase();
		out.captures_ = scratch;
		out.hashes_.assign(pattern.variable_hashes.begin(), pattern.variable_hashes.end());
		return true;
	}

	void Scanner::ScanRange(const ScanSet& set, uint64_t begin, uint64_t end, size_t limit_each,
		ScanState& state, std::span<std::vector<MatchResult>> out) const {
		auto try_candidate = [&](size_t index, uint64_t rva, const DecodedInstruction* decoded) {
			if (state.done[index]) {
				return;
			}
			const ScanSet::Candidate& candidate = set.candidates[index];
			MatchResult result;
			if (!MatchAt(candidate.pattern, rva, candidate.seed, state.scratch, decoded, result)) {
				return;
			}
			out[index].push_back(std::move(result));
			if (limit_each && out[index].size() >= limit_each) {
				state.done[index] = true;
				state.remaining--;
			}
		};
		for (uint64_t rva = begin; rva < end && state.remaining != 0; ++rva) {
			if (!(*starts_)[rva]) {
				continue;
			}
			ZydisDecodedInstruction header{};
			// header only, no operands: this is the shared walk, and it is what
			// makes a pattern that opens on a rare mnemonic nearly free
			if (!set.by_mnemonic.empty() && Decode(rva, header)) {
				const auto bucket = set.by_mnemonic.find(header.mnemonic);
				if (bucket != set.by_mnemonic.end()) {
					/*
					* Decoded with operands once for the whole bucket. Each candidate
					* used to run this same decode itself before it could reject on
					* an operand, which on a common opening mnemonic - a mov is a
					* quarter of the image - was most of what a pass cost.
					*/
					DecodedInstruction decoded;
					if (DecodeFull(rva, decoded.inst, decoded.operands)) {
						for (const size_t index : bucket->second) {
							try_candidate(index, rva, &decoded);
						}
					}
				}
			}
			for (const size_t index : set.anywhere) {
				try_candidate(index, rva, nullptr);
			}
		}
	}

	void Scanner::Collect(std::span<const PatternView> patterns, uint64_t start_rva,
		size_t limit_each, std::span<std::vector<MatchResult>> out) const {
		if (!analyzer_ || !analyzer_->IsAnalyzed()) {
			return;
		}

		ScanSet set;
		set.candidates.reserve(patterns.size());
		for (size_t i = 0; i < patterns.size() && i < out.size(); i++) {
			if (patterns[i].instructions.empty() || !ValidatePrebound(patterns[i])) {
				continue;
			}
			const size_t index = set.candidates.size();
			set.candidates.push_back({ patterns[i], SeedCaptures(patterns[i]), i });
			// the parser rejects an unknown mnemonic, so a MatchInstruction always
			// carries a concrete one and every candidate lands in exactly one of
			// these two
			if (const MatchInstruction* match =
				std::get_if<MatchInstruction>(&patterns[i].instructions[0])) {
				set.by_mnemonic[match->mnemonic].push_back(index);
			}
			else {
				set.anywhere.push_back(index);
			}
		}
		if (set.candidates.empty()) {
			return;
		}

		// the ranges a pass covers, in the order one pass over the image would
		// have reached them; the merge below relies on that order
		std::vector<std::pair<uint64_t, uint64_t>> ranges;
		const unsigned workers = WorkerCount(threads_, limit_each);
		for (const analyzer::Section& section : analyzer_->Sections()) {
			if (!section.executable || section.End() <= start_rva) {
				continue;
			}
			const uint64_t begin = std::max<uint64_t>(start_rva, section.va);
			// several chunks per worker, because instruction density varies enough
			// across a section that one chunk each would leave threads idle
			const uint64_t span = section.End() - begin;
			const uint64_t chunk =
				std::max<uint64_t>(kMinScanChunk, span / std::max(1u, workers * 4));
			for (uint64_t at = begin; at < section.End(); at += chunk) {
				ranges.emplace_back(at, std::min<uint64_t>(at + chunk, section.End()));
			}
		}
		if (ranges.empty()) {
			return;
		}

		// indexed by range, then by candidate; merged into `out` in range order,
		// so the result is the same whoever scanned which range
		std::vector<std::vector<std::vector<MatchResult>>> collected(ranges.size());
		auto run = [&](size_t range, ScanState& state) {
			collected[range].resize(set.candidates.size());
			ScanRange(set, ranges[range].first, ranges[range].second, limit_each, state,
				collected[range]);
		};

		if (workers <= 1) {
			ScanState state{ std::vector<bool>(set.candidates.size(), false),
				set.candidates.size(), {} };
			for (size_t range = 0; range < ranges.size() && state.remaining != 0; range++) {
				run(range, state);
			}
		}
		else {
			std::atomic<size_t> next{ 0 };
			std::vector<std::thread> pool;
			pool.reserve(workers - 1);
			auto worker = [&] {
				// limit_each is 0 on this path, so `done` never trips and a worker
				// covers whatever ranges are left when it asks
				ScanState state{ std::vector<bool>(set.candidates.size(), false),
					set.candidates.size(), {} };
				for (size_t range = next.fetch_add(1); range < ranges.size();
					range = next.fetch_add(1)) {
					run(range, state);
				}
			};
			for (unsigned i = 1; i < workers; i++) {
				pool.emplace_back(worker);
			}
			worker();
			for (std::thread& thread : pool) {
				thread.join();
			}
		}

		for (std::vector<std::vector<MatchResult>>& ranged : collected) {
			for (size_t index = 0; index < ranged.size(); index++) {
				std::vector<MatchResult>& target = out[set.candidates[index].out_index];
				target.insert(target.end(), std::make_move_iterator(ranged[index].begin()),
					std::make_move_iterator(ranged[index].end()));
			}
		}
	}

	std::vector<std::vector<MatchResult>> Scanner::FindAll(std::span<const PatternView> patterns,
		size_t limit_each) const {
		std::vector<std::vector<MatchResult>> results(patterns.size());
		Collect(patterns, 0, limit_each, results);
		return results;
	}

	std::optional<MatchResult> Scanner::Find(PatternView pattern, uint64_t start_rva) const {
		std::vector<MatchResult> results[1];
		const PatternView one[] = { pattern };
		Collect(one, start_rva, 1, results);
		if (results[0].empty()) {
			return std::nullopt;
		}
		return std::move(results[0].front());
	}

	std::vector<MatchResult> Scanner::FindAll(PatternView pattern, size_t limit) const {
		std::vector<MatchResult> results[1];
		const PatternView one[] = { pattern };
		Collect(one, 0, limit, results);
		return std::move(results[0]);
	}
} // namespace zigil
