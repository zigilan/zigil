#ifndef ZIGIL_PATTERN_HH_
#define ZIGIL_PATTERN_HH_

#include "zigil/detail/fixed_string.hh"
#include "zigil/detail/hash.hh"
#include "zigil/tables.hh"

#include <Zydis/Zydis.h>

#include <array>
#include <cstdio>
#include <format>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace zigil {
	enum class OperandType : uint8_t {
		kWildcard,
		kRegister,
		kImmediate,
		kMemory
	};
	enum class TypeSpecifier : uint8_t {
		kInvalid,
		kNone,
		kImmediate,
		kRegWidth
	};
	enum class RegWidth : uint8_t {
		kInvalid,
		kNone, // not set, may be treated as any if variable is new and untyped
		kAny, // explicit :* cast
		k8,
		k16,
		k32,
		k64,
		kXmm,
		kYmm,
		kZmm
	};
	struct RegOperand {
		ZydisRegister reg = ZYDIS_REGISTER_NONE;
		RegWidth width = RegWidth::kNone;
		uint8_t var_idx = 0xFF;
		bool is_wildcard = true;
	};
	struct ImmOperand {
		int64_t value = 0;
		uint8_t var_idx = 0xFF;
		bool is_wildcard = true;
	};
	struct MemOperand {
		// ex: ds:[rax+rcx*4+0x10]
		RegOperand segment; // ds
		RegOperand base; // rax
		RegOperand index; // rcx
		ImmOperand scale; // 4
		ImmOperand disp; // 0x10

		bool has_segment = false;
		bool has_base = false;
		bool has_index = false;
		bool has_disp = false;
		bool is_full_wildcard = false;
	};
	// TODO: update documentation to say that Variables are immutable after their initialization
	struct Operand {
		OperandType type = OperandType::kWildcard;
		// this variable index is only used for kWildcard
		uint8_t var_idx = 0xFF;

		RegOperand reg;
		ImmOperand imm;
		MemOperand mem;
	};
	struct MatchInstruction {
		ZydisMnemonic mnemonic = ZYDIS_MNEMONIC_INVALID;
		std::array<Operand, ZYDIS_MAX_OPERAND_COUNT_VISIBLE> operands;
		uint8_t operand_count = 0;
	};
	/*
	* The members are lo/hi rather than min/max on purpose. Windows.h defines
	* min and max as function-like macros unless NOMINMAX is set, and a consumer
	* that includes Windows.h before this header would have `min(min)` in the
	* member initializer expanded as a macro invocation. Since this header is
	* meant to be dropped into other projects, it cannot rely on who is included
	* first.
	*/
	struct SkipRange {
		uint32_t lo = 0;
		uint32_t hi = UINT32_MAX;

		constexpr SkipRange() = default;
		constexpr SkipRange(uint32_t lo, uint32_t hi) : lo(lo), hi(hi) {}
	};
	using Instruction = std::variant<MatchInstruction, SkipRange>;
	struct Pattern {
		std::vector<Instruction> instructions;
		std::vector<uint64_t> variable_hashes;
		/*
		* Always filled. This is the runtime type, so the names cost nothing that
		* the query string did not already cost; the heap-free FixedPattern only
		* copies them when it is asked to.
		*/
		std::vector<detail::VarName> variable_names;
		uint8_t variable_count = 0;

		constexpr struct PatternView View() const;
		// it is fine to call this GetVariable since the pattern object 
		// is gonna be immutable in the matcher
		// 0xFF means error
		constexpr uint8_t GetVariable(std::string_view variable);
	};
	namespace detail {
		/*
		* Carried as a base class rather than a member so that the empty case is
		* genuinely free: an empty base costs nothing, while a member - including
		* std::array<T, 0>, which MSVC gives a dummy element - would not.
		*/
		template<size_t NVar, bool Keep>
		struct NameStore {
			std::array<VarName, NVar> variable_names{};

			constexpr std::span<const VarName> Names() const { return variable_names; }
		};
		template<size_t NVar>
		struct NameStore<NVar, false> {
			constexpr std::span<const VarName> Names() const { return {}; }
		};
	} // namespace detail

	/*
	* The heap-free result of the _sig literal, carried from compile time to
	* runtime. With KeepNames == false - the default - variable names exist only
	* during constant evaluation and never reach the binary: the pattern holds
	* nothing but FNV-1a hashes, and the name storage is not even there. Set
	* KeepNames to carry the names too, which costs 48 bytes per variable and
	* makes Print spell them out.
	*/
	template<size_t NInst, size_t NVar, bool KeepNames = false>
	struct FixedPattern : detail::NameStore<NVar, KeepNames> {
		std::array<Instruction, NInst> instructions{};
		std::array<uint64_t, NVar> variable_hashes{};
		uint8_t variable_count = 0;

		static constexpr bool kKeepsNames = KeepNames;

		constexpr struct PatternView View() const;
	};
	/*
	* Non-owning view of Pattern or FixedPattern
	*/
	struct PatternView {
		std::span<const Instruction> instructions;
		std::span<const uint64_t> variable_hashes;
		/* empty unless the pattern was built with names, see FixedPattern */
		std::span<const detail::VarName> variable_names;

		constexpr uint8_t IndexOf(uint64_t hash) const;
		/* the variable's name, or an empty view when the names were not kept */
		constexpr std::string_view NameOf(uint8_t index) const {
			return index < variable_names.size() ? variable_names[index].View()
				: std::string_view();
		}
		constexpr bool HasNames() const { return !variable_names.empty(); }
		void Print() const;
	};

	constexpr RegWidth RegWidthFromString(std::string_view str) {
		// case-insensitive like mnemonics and register names, so :R64 works too
		if (tables::CaselessEqual(str, "r8")) {
			return RegWidth::k8;
		}
		if (tables::CaselessEqual(str, "r16")) {
			return RegWidth::k16;
		}
		if (tables::CaselessEqual(str, "r32")) {
			return RegWidth::k32;
		}
		if (tables::CaselessEqual(str, "r64")) {
			return RegWidth::k64;
		}
		if (tables::CaselessEqual(str, "xmm")) {
			return RegWidth::kXmm;
		}
		if (tables::CaselessEqual(str, "ymm")) {
			return RegWidth::kYmm;
		}
		if (tables::CaselessEqual(str, "zmm")) {
			return RegWidth::kZmm;
		}
		return RegWidth::kInvalid;
	}
	constexpr std::string_view TypeSpecifierToString(TypeSpecifier spec) {
		switch (spec) {
		case TypeSpecifier::kNone:      return "untyped";
		case TypeSpecifier::kImmediate: return "an immediate";
		case TypeSpecifier::kRegWidth:  return "a register";
		case TypeSpecifier::kInvalid:
		default: return "invalid";
		}
	}
	constexpr std::string_view RegWidthToString(RegWidth width) {
		switch (width) {
		case RegWidth::kNone: return "";
		case RegWidth::kAny: return "*";
		case RegWidth::k8:   return "r8";
		case RegWidth::k16:  return "r16";
		case RegWidth::k32:  return "r32";
		case RegWidth::k64:  return "r64";
		case RegWidth::kXmm: return "xmm";
		case RegWidth::kYmm: return "ymm";
		case RegWidth::kZmm: return "zmm";
		case RegWidth::kInvalid:
		default: return "invalid";
		}
	}

	inline std::string FormatWildcard(uint8_t var_idx,
		std::span<const detail::VarName> names = {}) {
		if (var_idx != 0xFF) {
			if (var_idx < names.size() && names[var_idx].length) {
				return "$" + std::string(names[var_idx].View());
			}
			return std::format("$v{:d}", var_idx);
		}
		return "?";
	}
	inline std::string FormatReg(const RegOperand& reg,
		std::span<const detail::VarName> names = {}) {
		if (reg.is_wildcard) {
			return FormatWildcard(reg.var_idx, names) +
				(reg.width != RegWidth::kNone ?
					std::format(":{}", RegWidthToString(reg.width)) :
					"");
		}
		return std::string(tables::RegisterToString(reg.reg));
	}
	inline std::string FormatImm(const ImmOperand& imm,
		std::span<const detail::VarName> names = {}) {
		if (imm.is_wildcard) {
			return FormatWildcard(imm.var_idx, names) + ":imm";
		}
		return std::format("{:#x}", imm.value);
	}

	constexpr PatternView Pattern::View() const {
		return { instructions, variable_hashes, variable_names };
	}
	constexpr uint8_t Pattern::GetVariable(std::string_view variable) {
		const uint64_t hash = detail::Fnv1a(variable);
		for (uint8_t i = 0; i < variable_hashes.size(); i++) {
			if (variable_hashes[i] == hash) {
				return i;
			}
		}
		if (variable_count == 0xFE) {
			return 0xFF;
		}
		variable_hashes.emplace_back(hash);
		variable_names.emplace_back(variable);
		return variable_count++;
	}

	template<size_t NInst, size_t NVar, bool KeepNames>
	constexpr PatternView FixedPattern<NInst, NVar, KeepNames>::View() const {
		return { instructions, variable_hashes, this->Names() };
	}

	constexpr uint8_t PatternView::IndexOf(uint64_t hash) const {
		for (uint8_t i = 0; i < variable_hashes.size(); i++) {
			if (variable_hashes[i] == hash) {
				return i;
			}
		}
		return 0xFF;
	}
	inline void PatternView::Print() const {
		const std::span<const detail::VarName> names = variable_names;
		for (const auto& inst : instructions) {
			if (std::holds_alternative<SkipRange>(inst)) {
				const SkipRange& skip = std::get<SkipRange>(inst);
				printf("skip %u-%u\n", skip.lo, skip.hi);
			}
			else {
				const MatchInstruction& mi = std::get<MatchInstruction>(inst);
				std::string_view mnemonic = tables::MnemonicToString(mi.mnemonic);
				std::string operands;
				for (uint8_t i = 0; i < mi.operand_count; i++) {
					const Operand& op = mi.operands[i];
					switch (op.type) {
					case OperandType::kWildcard:
						operands += FormatWildcard(op.var_idx, names);
						break;
					case OperandType::kRegister:
						operands += FormatReg(op.reg, names);
						break;
					case OperandType::kImmediate:
						operands += FormatImm(op.imm, names);
						break;
					case OperandType::kMemory:
						if (op.mem.is_full_wildcard) {
							operands += "[?]";
						}
						else {
							if (op.mem.has_segment) {
								operands += FormatReg(op.mem.segment, names) + ":";
							}
							operands += "[";
							if (op.mem.has_base) {
								operands += FormatReg(op.mem.base, names);
								if (op.mem.has_index) {
									operands += "+";
								}
								else if (op.mem.has_disp) {
									operands += op.mem.disp.value >= 0 ? "+" : "-";
								}
							}
							if (op.mem.has_index) {
								operands += FormatReg(op.mem.index, names) + "*" + FormatImm(op.mem.scale, names);
								if (op.mem.has_disp) {
									operands += op.mem.disp.value >= 0 ? "+" : "-";
								}
							}
							if (op.mem.has_disp) {
								operands += FormatImm(op.mem.disp, names);
							}
							operands += "]";
						}
						break;
					default: break;
					}
					if (i != mi.operand_count - 1) {
						operands += ", ";
					}
				}
				printf("%s %s\n", mnemonic.data(), operands.c_str());
			}
		}
	}
} // namespace zigil

#endif // ZIGIL_PATTERN_HH_