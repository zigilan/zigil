// Parser tests derived from CONCEPT.md, one section per syntax section there.
//
// Everything is a static_assert: the parser is constexpr, so a drift between the
// documentation and the code breaks the build instead of waiting for someone to
// run a test binary. A failed parse returns an empty Pattern, which is what
// Rejects() checks - PrintError does nothing while constant-evaluated.
#include "zigil/zigil.hh"

#include <variant>

namespace zigil::tests {
	namespace {
		constexpr bool Rejects(std::string_view query) {
			return Parser::Parse(query).instructions.empty();
		}
		constexpr size_t Size(std::string_view query) {
			return Parser::Parse(query).instructions.size();
		}
		constexpr uint8_t VarCount(std::string_view query) {
			return Parser::Parse(query).variable_count;
		}
		constexpr bool IsGap(std::string_view query, size_t index) {
			const Pattern pattern = Parser::Parse(query);
			return index < pattern.instructions.size() &&
				std::holds_alternative<SkipRange>(pattern.instructions[index]);
		}
		constexpr SkipRange Gap(std::string_view query, size_t index = 0) {
			return std::get<SkipRange>(Parser::Parse(query).instructions[index]);
		}
		constexpr MatchInstruction Inst(std::string_view query, size_t index = 0) {
			return std::get<MatchInstruction>(Parser::Parse(query).instructions[index]);
		}
		constexpr Operand Op(std::string_view query, uint8_t operand, size_t index = 0) {
			return Inst(query, index).operands[operand];
		}

		// --- CONCEPT.md: Quick Example ---------------------------------------
		constexpr std::string_view kQuick =
			"; Find a vtable dispatch, capture the vtable offset and the register\n"
			"mov $reg:r64, [rcx+$vtable_off]\n"
			"call [$reg+?]";

		static_assert(Size(kQuick) == 2, "quick example: two instructions");
		static_assert(VarCount(kQuick) == 2, "quick example: two variables");
		static_assert(Inst(kQuick, 0).mnemonic == ZYDIS_MNEMONIC_MOV);
		static_assert(Inst(kQuick, 0).operand_count == 2);
		static_assert(Op(kQuick, 0).type == OperandType::kRegister);
		static_assert(Op(kQuick, 0).reg.is_wildcard);
		static_assert(Op(kQuick, 0).reg.width == RegWidth::k64);
		static_assert(Op(kQuick, 0).reg.var_idx == 0);
		static_assert(Op(kQuick, 1).type == OperandType::kMemory);
		static_assert(Op(kQuick, 1).mem.has_base);
		static_assert(!Op(kQuick, 1).mem.base.is_wildcard);
		static_assert(Op(kQuick, 1).mem.base.reg == ZYDIS_REGISTER_RCX);
		static_assert(Op(kQuick, 1).mem.has_disp);
		static_assert(Op(kQuick, 1).mem.disp.is_wildcard);
		static_assert(Op(kQuick, 1).mem.disp.var_idx == 1);
		static_assert(Inst(kQuick, 1).mnemonic == ZYDIS_MNEMONIC_CALL);
		// the same name resolves to the same index on reuse
		static_assert(Op(kQuick, 0, 1).mem.base.var_idx == 0);
		// the anonymous ? in the same operand stays unnamed
		static_assert(Op(kQuick, 0, 1).mem.has_disp);
		static_assert(Op(kQuick, 0, 1).mem.disp.var_idx == 0xFF);

		// --- Strict match ----------------------------------------------------
		static_assert(Op("mov rcx, [rax+0x10]", 0).type == OperandType::kRegister);
		static_assert(!Op("mov rcx, [rax+0x10]", 0).reg.is_wildcard);
		static_assert(Op("mov rcx, [rax+0x10]", 0).reg.reg == ZYDIS_REGISTER_RCX);
		static_assert(Op("mov rdx, 0x1337", 1).type == OperandType::kImmediate);
		static_assert(!Op("mov rdx, 0x1337", 1).imm.is_wildcard);
		static_assert(Op("mov rdx, 0x1337", 1).imm.value == 0x1337);

		// --- Number literals -------------------------------------------------
		static_assert(Op("mov rax, 4096", 1).imm.value == 4096, "decimal");
		static_assert(Op("mov rax, 0x1000", 1).imm.value == 0x1000, "hex");
		static_assert(Op("mov rax, 0b1101", 1).imm.value == 0b1101, "binary");
		static_assert(Op("mov rax, -1", 1).imm.value == -1, "negative immediate");
		static_assert(Op("mov rax, [rcx-0x8]", 1).mem.disp.value == -8,
			"negative displacement");

		// --- Wildcards -------------------------------------------------------
		static_assert(Op("mov rcx, [rax+?]", 1).mem.has_disp &&
			Op("mov rcx, [rax+?]", 1).mem.disp.is_wildcard, "any displacement");
		static_assert(Op("mov ?, 0x1337", 0).type == OperandType::kWildcard);
		static_assert(Op("mov ?, 0x1337", 0).var_idx == 0xFF);
		static_assert(Op("mov rcx, ?", 1).type == OperandType::kWildcard);
		static_assert(Inst("mov ?, ?").operand_count == 2);
		static_assert(VarCount("mov ?, ?") == 0, "anonymous wildcards are not variables");

		// --- Typed wildcards -------------------------------------------------
		static_assert(Op("mov ?:r8, rcx", 0).reg.width == RegWidth::k8);
		static_assert(Op("mov ?:r16, rcx", 0).reg.width == RegWidth::k16);
		static_assert(Op("mov ?:r32, rcx", 0).reg.width == RegWidth::k32);
		static_assert(Op("mov ?:r64, rcx", 0).reg.width == RegWidth::k64);
		static_assert(Op("movdqu ?:xmm, [rsp+?]", 0).reg.width == RegWidth::kXmm);
		static_assert(Op("vmovdqu ?:ymm, [rsp+?]", 0).reg.width == RegWidth::kYmm);
		static_assert(Op("vmovdqu64 ?:zmm, [rsp+?]", 0).reg.width == RegWidth::kZmm);
		static_assert(Op("mov rdx, ?:imm", 1).type == OperandType::kImmediate &&
			Op("mov rdx, ?:imm", 1).imm.is_wildcard, "any immediate");
		static_assert(Op("mov rcx, [?:r64+0x10]", 1).mem.base.width == RegWidth::k64,
			"typed wildcard as a memory base");
		// each ? on a line is its own anonymous wildcard
		static_assert([] {
			const MatchInstruction inst = Inst("mov ?:r32, ?:r64");
			return inst.operands[0].reg.width == RegWidth::k32 &&
				inst.operands[1].reg.width == RegWidth::k64 &&
				inst.operands[0].reg.var_idx == 0xFF &&
				inst.operands[1].reg.var_idx == 0xFF;
		}(), "two typed wildcards on one line are independent");

		// --- Wildcard variables ----------------------------------------------
		static_assert(VarCount("mov rcx, [rax+$x]\nmov $y, 0x1337\ncmp rcx, $y") == 2);
		static_assert([] {
			// $x is captured in instruction 0 and compared in instruction 3
			constexpr std::string_view query =
				"mov rcx, [rax+$x]\n"
				"mov $y, 0x1337\n"
				"cmp rcx, $y\n"
				"call [?+$x]";
			return Op(query, 1, 0).mem.disp.var_idx == 0 &&
				Op(query, 0, 1).var_idx == 1 &&
				Op(query, 1, 2).var_idx == 1 &&
				Op(query, 0, 3).mem.disp.var_idx == 0;
		}(), "a variable keeps its index across instructions");
		static_assert(Op("mov $base:r64, [rsp+?]", 0).reg.width == RegWidth::k64);

		// --- Register width casting ------------------------------------------
		static_assert(Op("mov [$x:*+0x8], rdx", 0).mem.base.width == RegWidth::kAny);
		static_assert(!Rejects("mov $x:r32, [rax+?]\nmov [$base+$x:*], rdx"),
			"':*' relaxes the width check on reuse");
		static_assert(Rejects("mov $x:r32, rcx\nmov $x:r64, rdx"),
			"a conflicting declared width is a parse error");
		static_assert(Rejects("mov $x:r32, rcx\nmov rdx, [$x:r64]"),
			"the width check reaches into memory operands");
		static_assert(Rejects("mov $x:r64, rcx\nmov rdx, $x:imm"),
			"a register cannot later be declared an immediate");
		static_assert(!Rejects("mov $x:r64, rcx\nmov rdx, $x\nmov [$x+0x8], rax"),
			"an untyped reuse constrains nothing");
		static_assert(!Rejects("mov $x:r64, rcx\nmov $x:r64, rdx"),
			"the same width twice is fine");

		// --- Memory operands --------------------------------------------------
		static_assert([] {
			const Operand op = Op("mov rax, [rcx]", 1);
			return op.type == OperandType::kMemory && op.mem.has_base &&
				op.mem.base.reg == ZYDIS_REGISTER_RCX &&
				!op.mem.has_index && !op.mem.has_disp;
		}(), "base only");
		static_assert([] {
			const Operand op = Op("mov rax, [rcx+rdx*4+0x10]", 1);
			return op.mem.has_base && op.mem.base.reg == ZYDIS_REGISTER_RCX &&
				op.mem.has_index && op.mem.index.reg == ZYDIS_REGISTER_RDX &&
				op.mem.scale.value == 4 &&
				op.mem.has_disp && op.mem.disp.value == 0x10;
		}(), "full form");
		static_assert([] {
			// terms are classified by shape, so the order does not matter
			const Operand op = Op("mov rax, [rdx*4+rcx]", 1);
			return op.mem.has_base && op.mem.base.reg == ZYDIS_REGISTER_RCX &&
				op.mem.has_index && op.mem.index.reg == ZYDIS_REGISTER_RDX &&
				op.mem.scale.value == 4 && !op.mem.has_disp;
		}(), "[rdx*4+rcx] == [rcx+rdx*4]");
		static_assert([] {
			// two plain registers are base + index with scale 1, the x86 semantic
			const Operand op = Op("mov rax, [rax+rbx]", 1);
			return op.mem.has_base && op.mem.base.reg == ZYDIS_REGISTER_RAX &&
				op.mem.has_index && op.mem.index.reg == ZYDIS_REGISTER_RBX &&
				!op.mem.scale.is_wildcard && op.mem.scale.value == 1;
		}(), "[rax+rbx] is base + index, scale 1");
		static_assert([] {
			const Operand op = Op("lea rax, ds:[rcx*8]", 1);
			return op.mem.has_segment &&
				op.mem.segment.reg == ZYDIS_REGISTER_DS &&
				!op.mem.has_base && op.mem.has_index && op.mem.scale.value == 8;
		}(), "segment override");
		static_assert(Op("mov rax, [?]", 1).mem.is_full_wildcard, "[?]");
		static_assert(Rejects("mov rax, [rax+rbx*3]"), "scale must be 1, 2, 4 or 8");
		static_assert(!Rejects("mov rax, [rax+rbx*8]"), "scale 8 is valid");
		static_assert(Rejects("mov rax, [rcx+rdx+rbx]"), "three registers");
		static_assert(Rejects("mov rax, [rcx+0x10+0x20]"), "two displacements");
		static_assert(Rejects("mov rax, [rcx"), "unterminated memory operand");
		static_assert(Rejects("mov rax, []"), "empty memory operand");
		static_assert(Rejects("mov rax, rcx:[rdx]"), "rcx is not a segment register");
		static_assert(Rejects("mov rax, es:rcx"), "a segment override needs brackets");

		// --- Instruction gap wildcards ----------------------------------------
		static_assert(Gap("<1>").lo == 1 && Gap("<1>").hi == 1, "<N>");
		static_assert(Gap("<3-7>").lo == 3 && Gap("<3-7>").hi == 7, "<N-M>");
		static_assert(Gap("<?>").lo == 0 && Gap("<?>").hi == UINT32_MAX, "<?>");
		static_assert(Gap("<1+>").lo == 1 && Gap("<1+>").hi == UINT32_MAX, "<N+>");
		static_assert(Gap("<4->").lo == 0 && Gap("<4->").hi == 4, "<N->");
		static_assert(Rejects("<4-2>"), "min must not exceed max");
		static_assert(Rejects("<1"), "unterminated gap");
		static_assert(Rejects("<>"), "empty gap");
		static_assert([] {
			constexpr std::string_view query =
				"mov rcx, [rax+0x10]\n"
				"<?>\n"
				"test rcx, rcx\n"
				"<1-3>\n"
				"jnz ?";
			return Size(query) == 5 && IsGap(query, 1) && IsGap(query, 3) &&
				!IsGap(query, 0) && !IsGap(query, 2) && !IsGap(query, 4);
		}(), "gaps sit between instructions in one pattern");

		// --- Branch and call targets ------------------------------------------
		static_assert(Inst("call ?").mnemonic == ZYDIS_MNEMONIC_CALL &&
			Inst("call ?").operand_count == 1);
		static_assert(Inst("jmp ?").mnemonic == ZYDIS_MNEMONIC_JMP);
		static_assert(Inst("jz ?").mnemonic == ZYDIS_MNEMONIC_JZ);
		static_assert(Inst("jnz ?").mnemonic == ZYDIS_MNEMONIC_JNZ);

		// --- Comments ----------------------------------------------------------
		static_assert(Size("mov rcx, [rax+$x] ; $x is the vtable offset") == 1);
		static_assert(Inst("mov rcx, rdx ; trailing comment").operand_count == 2);
		static_assert(Size("; only a comment") == 0, "a comment-only query is empty");
		static_assert(Size("mov rax, rcx\n; comment line\nmov rdx, rbx") == 2);

		// --- Case-insensitivity (P7-6) -----------------------------------------
		static_assert(Inst("MOV RCX, RDX").mnemonic == ZYDIS_MNEMONIC_MOV);
		static_assert(Op("MOV RCX, RDX", 0).reg.reg == ZYDIS_REGISTER_RCX);
		static_assert(Op("mov ?:R64, rcx", 0).reg.width == RegWidth::k64);
		static_assert(Op("LEA RAX, DS:[RCX*8]", 1).mem.segment.reg == ZYDIS_REGISTER_DS);

		// --- Malformed instructions --------------------------------------------
		static_assert(Rejects("movx rax, rcx"), "unknown mnemonic");
		static_assert(Rejects("mov rax, rzx"), "unknown register");
		static_assert(Rejects("mov rcx rdx"), "missing comma between operands");
		static_assert(Rejects("mov rax,"), "trailing comma");
		static_assert(Rejects("mov rax, , rcx"), "empty operand");
		static_assert(Rejects("0x10"), "a query must start with a mnemonic or a gap");
		// prefixes are Zydis attributes, not mnemonics: a pattern of movsb matches
		// both movsb and rep movsb, and writing the prefix is an error
		static_assert(Rejects("rep movsb"), "prefixes are not writable");
		static_assert(!Rejects("movsb"), "the unprefixed mnemonic parses");

		// --- Compile-time pivot -------------------------------------------------
		constexpr auto kFixed = R"(mov $reg:r64, [rcx+$vtable_off]
call [$reg+?])"_sig;
		static_assert(kFixed.instructions.size() == 2, "_sig keeps every instruction");
		static_assert(kFixed.variable_hashes.size() == 2, "_sig keeps every variable");
		static_assert(kFixed.variable_count == 2);
		static_assert(kFixed.View().instructions.size() == 2, "the view spans the array");
		static_assert(kFixed.View().IndexOf(detail::Fnv1a("reg")) == 0,
			"variable names are interned as FNV-1a hashes");
		static_assert(kFixed.View().IndexOf(detail::Fnv1a("vtable_off")) == 1);
		static_assert(kFixed.View().IndexOf(detail::Fnv1a("nope")) == 0xFF);

		// --- Variable names: dropped by default, kept on request --------------
		// The distinctive names make this checkable from outside as well: build
		// the project and search the binary. $dropped_by_default is absent,
		// $kept_by_request is present, which is the whole point of the switch.
		constexpr auto kDropped = R"(mov $dropped_by_default:r64, rcx)"_sig;
		static_assert(!kDropped.kKeepsNames, "_sig drops names by default");
		static_assert(!kDropped.View().HasNames());
		static_assert(kDropped.View().NameOf(0).empty());
		// the hash is still there, so the capture getters work either way
		static_assert(kDropped.View().IndexOf(detail::Fnv1a("dropped_by_default")) == 0);

		constexpr auto kKept = Parser::Parse<R"(mov $kept_by_request:r64, rcx)", true>();
		static_assert(kKept.kKeepsNames, "Parse<Query, true> keeps them");
		static_assert(kKept.View().HasNames());
		static_assert(kKept.View().NameOf(0) == "kept_by_request");
		static_assert(kKept.View().IndexOf(detail::Fnv1a("kept_by_request")) == 0);
		// the name storage is a base class, so switching it off costs nothing at
		// all rather than an empty array MSVC would still give a dummy element
		static_assert(sizeof(kDropped) + sizeof(detail::VarName) <= sizeof(kKept),
			"dropping the names has to actually shrink the pattern");

		// a runtime parsed pattern always carries its names: the query string is
		// already in memory, so there is nothing to save by dropping them
		static_assert([] {
			const Pattern pattern = Parser::Parse("mov $runtime_name:r64, [rip+$other]");
			return pattern.View().HasNames() &&
				pattern.View().NameOf(0) == "runtime_name" &&
				pattern.View().NameOf(1) == "other" &&
				pattern.View().NameOf(2).empty();
		}(), "runtime patterns keep their names");
	} // namespace
} // namespace zigil::tests
