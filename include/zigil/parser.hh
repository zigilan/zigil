#ifndef ZIGIL_PARSER_HH_
#define ZIGIL_PARSER_HH_

#include "zigil/lexer.hh"
#include "zigil/pattern.hh"
#include "zigil/tables.hh"
#include "zigil/detail/fixed_string.hh"

/*
* Whether a compile-time pattern carries its variable names.
*
* 0 (the default) keeps the promise that a _sig pattern puts nothing but FNV-1a
* hashes in the binary - the names exist during constant evaluation and are
* dropped. Define it to 1 to have every _sig pattern carry its names, which
* makes PatternView::Print spell them out and costs at most 48 bytes per
* variable. Parse<Query, true>() opts one single pattern in without the switch.
*/
#ifndef ZIGIL_KEEP_VARIABLE_NAMES
#define ZIGIL_KEEP_VARIABLE_NAMES 0
#endif

namespace zigil {
	class Parser {
#if defined(_MSC_VER) && !defined(__clang__) && !defined(__INTEL_COMPILER)
	public:
		constexpr Parser(const std::vector<Token>& tokens) : tokens_(tokens) {}
	private:
#else
	private:
		constexpr Parser(const std::vector<Token>& tokens) : tokens_(tokens) {}
#endif

		constexpr bool ConsumeToken(size_t count = 1);
		constexpr Token FutureToken(size_t look_ahead = 1);
		constexpr bool ParseSkipRange();
		constexpr bool NoteVariableType(uint8_t var_idx, TypeSpecifier spec, RegWidth width);
		constexpr bool GetCurrentVariable(uint8_t& index);
		constexpr TypeSpecifier GetCurrentTypeSpecifier(RegWidth* width /* out, optional */);
		constexpr bool ParseWildcardInfo(uint8_t& var_idx, TypeSpecifier& type_spec, RegWidth* width /* out, optional */);
		constexpr bool FillReg(RegOperand& op);
		constexpr bool FillImm(ImmOperand& op, bool negative);
		constexpr bool ParseWildcardOrVariable(Operand& op);
		constexpr bool ParseMemTerm(MemOperand& op, bool negative);
		constexpr bool ParseMemoryOperand(Operand& op);
		constexpr bool ParseOperand(Operand& op);
		constexpr bool ParseMnemonic();
		constexpr bool ParseInstruction();
		constexpr Pattern Parse();

	public:
		static constexpr Pattern Parse(const std::vector<Token>& tokens);
		static constexpr Pattern Parse(std::string_view query);
		
		template<detail::FixedString Query, bool KeepNames = ZIGIL_KEEP_VARIABLE_NAMES>
		static consteval auto Parse() {
			struct Counts {
				size_t instructions;
				size_t variables;
			};

			constexpr Counts n = [] {
				Pattern p = Parse(Query.View());
				return Counts{
					.instructions = p.instructions.size(),
					.variables = p.variable_hashes.size(),
				};
			}();
			// A parse error leaves the pattern empty. The message itself cannot
			// travel into a compiler diagnostic - MSVC reports neither a thrown
			// value nor a format argument, only C3615 and a call stack - so this
			// says how to get at it instead of dumping that on the user.
			static_assert(n.instructions != 0,
				"zigil: this pattern does not parse. Pass the same string to "
				"zigil::Parser::Parse(std::string_view) at runtime to get the "
				"message with line and column.");

			Pattern p = Parse(Query.View());
			FixedPattern<n.instructions, n.variables, KeepNames> out;
			for (size_t i = 0; i < n.instructions; i++) {
				out.instructions[i] = p.instructions[i];
			}
			for (size_t i = 0; i < n.variables; i++) {
				out.variable_hashes[i] = p.variable_hashes[i];
				// only reached when names are kept, so nothing is copied into the
				// binary otherwise
				if constexpr (KeepNames) {
					out.variable_names[i] = p.variable_names[i];
				}
			}
			out.variable_count = p.variable_count;
			return out;
		}

	private:
		/*
		* What a variable was declared as, by index. Only *explicit* type suffixes
		* are recorded: an untyped reuse (`$x`) constrains nothing, because the
		* parser classifies memory terms by shape and would otherwise reject
		* perfectly good patterns.
		*/
		struct VarType {
			TypeSpecifier spec = TypeSpecifier::kNone;
			RegWidth width = RegWidth::kNone;
		};

	private:
		std::vector<Token> tokens_;
		std::vector<Token>::iterator current_;
		Pattern pattern_;
		std::vector<VarType> var_types_;
	};

	constexpr bool Parser::ConsumeToken(size_t count) {
		current_ += count;
		return current_ < tokens_.end();
	}
	constexpr Token Parser::FutureToken(size_t look_ahead) {
		if (current_ + look_ahead >= tokens_.end()) {
			return Token();
		}
		return *(current_ + look_ahead);
	}
	constexpr bool Parser::ParseSkipRange() {
		switch (current_->type) {
		case TokenType::kQuestion: // <?
			if (!ConsumeToken()) return false;
			if (current_->type != TokenType::kGreaterThan) {
				current_->PrintError("Invalid gap range, did you mean '<?>' ?");
				return false;
			}
			pattern_.instructions.push_back(SkipRange());
			return ConsumeToken();
		case TokenType::kNumber: { // <1
			uint32_t first = (uint32_t)current_->value.num;
			if (!ConsumeToken()) return false;
			switch (current_->type) {
			case TokenType::kGreaterThan: // <1>
				pattern_.instructions.push_back(SkipRange(first, first));
				return ConsumeToken();
			case TokenType::kPlus: // <1+
				if (!ConsumeToken()) return false;
				if (current_->type != TokenType::kGreaterThan) {
					current_->PrintError("Invalid gap range, '<N+>' expected.");
					return false;
				}
				pattern_.instructions.push_back(SkipRange(first, UINT32_MAX));
				return ConsumeToken();
			case TokenType::kMinus: // <1-
				if (!ConsumeToken()) return false;
				if (current_->type == TokenType::kGreaterThan) { // <1->
					pattern_.instructions.push_back(SkipRange(0, first));
					return ConsumeToken();
				}
				if (current_->type == TokenType::kNumber) { // <1-4
					uint32_t second = (uint32_t)current_->value.num;
					if (!ConsumeToken()) return false;
					if (current_->type != TokenType::kGreaterThan) {
						current_->PrintError("Invalid gap range, '<N-M>' expected.");
						return false;
					}
					if (first > second) {
						current_->PrintError("Invalid gap range, '<N-M>' expected where N<=M.");
						return false;
					}
					pattern_.instructions.push_back(SkipRange(first, second));
					return ConsumeToken();
				}
				current_->PrintError("Invalid gap range, '<N->' or '<N-M>' expected.");
				return false;
			default:
				current_->PrintError("Invalid gap range");
				return false;
			}
		}
		default:
			current_->PrintError("Invalid gap range");
			return false;
		}
	}
	constexpr bool Parser::NoteVariableType(uint8_t var_idx, TypeSpecifier spec, RegWidth width) {
		if (var_idx == 0xFF ||
			spec == TypeSpecifier::kNone ||
			spec == TypeSpecifier::kInvalid) {
			// no variable, or nothing declared here to check against
			return true;
		}
		while (var_types_.size() <= var_idx) {
			var_types_.push_back(VarType());
		}
		VarType& known = var_types_[var_idx];
		if (known.spec == TypeSpecifier::kNone) {
			known.spec = spec;
			known.width = width;
			return true;
		}
		if (known.spec != spec) {
			current_->PrintError("Variable was declared as {} before but is {} here",
				TypeSpecifierToString(known.spec), TypeSpecifierToString(spec));
			return false;
		}
		if (spec == TypeSpecifier::kRegWidth) {
			// ':*' is exactly the escape hatch for reusing a capture at a
			// different width, so it suppresses the check on either side
			if (width == RegWidth::kAny || known.width == RegWidth::kAny ||
				width == known.width) {
				return true;
			}
			current_->PrintError(
				"Variable was declared as {} before but is {} here, write ':*' to reuse it at a different width",
				RegWidthToString(known.width), RegWidthToString(width));
			return false;
		}
		return true;
	}
	constexpr bool Parser::GetCurrentVariable(uint8_t& index) {
		index = 0xFF;
		if (current_->type != TokenType::kDollar) {
			return true;
		}
		if (!ConsumeToken()) return false;
		if (current_->type != TokenType::kIdentifier) {
			current_->PrintError("Identifier expected after '$'");
			return false;
		}
		index = pattern_.GetVariable(current_->value.str);
		if (index == 0xFF) {
			current_->PrintError("Maximum number of variables exceeded: 254");
			return false;
		}
		return ConsumeToken();
	}
	constexpr TypeSpecifier Parser::GetCurrentTypeSpecifier(RegWidth* width /* out, optional */) {
		if (current_->type != TokenType::kColon) {
			return TypeSpecifier::kNone;
		}
		// :
		if (!ConsumeToken()) return TypeSpecifier::kInvalid;
		if (current_->type == TokenType::kStar) { // :*
			if (width) {
				*width = RegWidth::kAny;
			}
			// return value can safely be ignored as long as the function just consumes one token,
			// because there is always an EOF token at the end
			ConsumeToken();
			return TypeSpecifier::kRegWidth;
		}
		if (current_->type == TokenType::kIdentifier) {
			if (tables::CaselessEqual(current_->value.str, "imm")) { // :imm
				ConsumeToken();
				return TypeSpecifier::kImmediate;
			}
			RegWidth w = RegWidthFromString(current_->value.str);
			if (w != RegWidth::kInvalid) {
				if (width) {
					*width = w;
				}
				ConsumeToken();
				return TypeSpecifier::kRegWidth;
			}
		}
		current_->PrintError("Invalid type");
		return TypeSpecifier::kInvalid;
	}
	constexpr bool Parser::ParseWildcardInfo(uint8_t& var_idx, TypeSpecifier& type_spec, RegWidth* width) {
		if (!GetCurrentVariable(var_idx)) return false;
		if (var_idx == 0xFF && current_->type == TokenType::kQuestion) {
			if (!ConsumeToken()) return false;
		}
		type_spec = GetCurrentTypeSpecifier(width);
		// width is only written when the specifier is a register width, so it is
		// only read back in that case
		const RegWidth declared = (type_spec == TypeSpecifier::kRegWidth && width) ?
			*width : RegWidth::kNone;
		return NoteVariableType(var_idx, type_spec, declared);
	}
	constexpr bool Parser::FillReg(RegOperand& op) {
		if (current_->type == TokenType::kIdentifier) {
			op.reg = tables::FindRegister(current_->value.str);
			op.is_wildcard = false;
			return op.reg != ZYDIS_REGISTER_NONE && ConsumeToken();
		}
		uint8_t idx;
		TypeSpecifier type_spec;
		RegWidth width;
		if (!ParseWildcardInfo(idx, type_spec, &width)) return false;
		op.var_idx = idx;
		if (type_spec == TypeSpecifier::kRegWidth) {
			op.width = width;
		}
		return type_spec == TypeSpecifier::kNone ||
			type_spec == TypeSpecifier::kRegWidth;
	}
	constexpr bool Parser::FillImm(ImmOperand& op, bool negative) {
		if (current_->type == TokenType::kNumber) {
			op.value = negative ?
				-(int64_t)current_->value.num :
				(int64_t)current_->value.num;
			op.is_wildcard = false;
			return ConsumeToken();
		}
		uint8_t idx;
		TypeSpecifier type_spec;
		if (!ParseWildcardInfo(idx, type_spec, nullptr)) return false;
		op.var_idx = idx;
		return type_spec == TypeSpecifier::kNone ||
			type_spec == TypeSpecifier::kImmediate;
	}
	constexpr bool Parser::ParseWildcardOrVariable(Operand& op) {
		uint8_t idx;
		TypeSpecifier type_spec;
		RegWidth width;
		if (!ParseWildcardInfo(idx, type_spec, &width)) return false;
		switch (type_spec) {
		case TypeSpecifier::kImmediate:
			op.type = OperandType::kImmediate;
			op.imm.var_idx = idx;
			return true;
		case TypeSpecifier::kRegWidth:
			op.type = OperandType::kRegister;
			op.reg.width = width;
			op.reg.var_idx = idx;
			return true;
		case TypeSpecifier::kNone:
			op.type = OperandType::kWildcard;
			op.var_idx = idx;
			return true;
		case TypeSpecifier::kInvalid:
		default: break;
		}
		return false;
	}
	constexpr bool Parser::ParseMemTerm(MemOperand& op, bool negative) {
		const auto fill_index = [&]() -> bool {
			if (op.has_index) {
				current_->PrintError("Too many registers in memory operand");
				return false;
			}
			if (!FillReg(op.index)) {
				current_->PrintError("Register expected before *scale");
				return false;
			}
			op.has_index = true;
			if (!ConsumeToken()) return false; // remove the *
			if (!FillImm(op.scale, false)) {
				current_->PrintError("Immediate value/variable expected after index register");
				return false;
			}
			if (!op.scale.is_wildcard) {
				if (op.scale.value != 1 &&
					op.scale.value != 2 &&
					op.scale.value != 4 &&
					op.scale.value != 8) {
					current_->PrintError("Scale may only be one of {{1, 2, 4, 8}}");
					return false;
				}
			}
			return true;
			};
		const auto fill_preferred_register = [&](const RegOperand& reg) -> bool {
			if (op.has_base) {
				if (op.has_index) {
					current_->PrintError("Too many registers in memory operand");
					return false;
				}
				op.index = reg;
				op.scale.value = 1;
				op.scale.is_wildcard = false;
				op.has_index = true;
				return true;
			}
			op.base = reg;
			op.has_base = true;
			return true;
			};

		const bool is_index = current_->type == TokenType::kDollar ?
			FutureToken(2).type == TokenType::kStar :
			FutureToken().type == TokenType::kStar;

		if (current_->type == TokenType::kNumber) {
			if (op.has_disp) {
				current_->PrintError("Only one displacement allowed in memory operand");
				return false;
			}
			op.has_disp = true;
			return FillImm(op.disp, negative);
		}
		if (current_->type == TokenType::kIdentifier) {
			if (is_index) {
				return fill_index();
			}
			if (negative) {
				current_->PrintError("Registers cannot be negative");
				return false;
			}
			RegOperand reg;
			if (!FillReg(reg)) {
				current_->PrintError("Invalid register");
				return false;
			}
			return fill_preferred_register(reg);
		}
		if (current_->type == TokenType::kDollar ||
			current_->type == TokenType::kQuestion) {
			if (is_index) {
				return fill_index();
			}
			uint8_t idx;
			TypeSpecifier type_spec;
			// the width has to be kept: passing nullptr here dropped the constraint
			// on '[$x:r32+8]' and made ':*' inside a memory operand a no-op
			RegWidth width = RegWidth::kNone;
			if (!ParseWildcardInfo(idx, type_spec, &width)) return false;

			switch (type_spec) {
			case TypeSpecifier::kNone:
				if (op.has_base || negative) {
					if (op.has_disp) {
						current_->PrintError("Can't decide which operand type this is supposed to be");
						return false;
					}
					op.disp.var_idx = idx;
					op.has_disp = true;
					return true;
				}
				op.base.var_idx = idx;
				op.has_base = true;
				return true;
			case TypeSpecifier::kRegWidth: {
				if (negative) {
					current_->PrintError("Registers cannot be negative");
					return false;
				}
				RegOperand reg;
				reg.var_idx = idx;
				reg.width = width;
				return fill_preferred_register(reg);
			}
			case TypeSpecifier::kImmediate:
				if (op.has_disp) {
					current_->PrintError("Two displacements are not allowed");
					return false;
				}
				op.disp.var_idx = idx;
				op.has_disp = true;
				return true;
			case TypeSpecifier::kInvalid:
			default:
				return false;
			}
		}
		return false;
	}
	constexpr bool Parser::ParseMemoryOperand(Operand& op) {
		// [BASE + INDEX*SCALE + DISP] (memory)
		// SEG:[BASE + INDEX*SCALE + DISP] (memory)
		// 
		// special cases:
		// [?] memory wildcard, anything (also any segment) will be accepted
		// SEG:[$var] displacement
		// [$var] base register

		op.type = OperandType::kMemory;

		if (current_->type == TokenType::kIdentifier) { // segment registers can't be variables
			op.mem.segment.reg = tables::FindRegister(current_->value.str);
			op.mem.segment.is_wildcard = false;
			if (op.mem.segment.reg < ZYDIS_REGISTER_ES ||
				op.mem.segment.reg > ZYDIS_REGISTER_GS) {
				current_->PrintError("Invalid segment register");
				return false;
			}
			op.mem.has_segment = true;
			if (!ConsumeToken()) return false;
			if (current_->type != TokenType::kColon || !ConsumeToken()) return false;
		}
		if (current_->type != TokenType::kBracketOpen) {
			current_->PrintError("Invalid format for memory operand");
			return false;
		}
		if (!ConsumeToken()) return false;
		if (current_->type == TokenType::kBracketClose) {
			current_->PrintError("Invalid format for memory operand");
			return false;
		}
		if (current_->type == TokenType::kQuestion &&
			FutureToken().type == TokenType::kBracketClose) {
			op.mem.is_full_wildcard = true;
			return ConsumeToken(2);
		}

		bool negative = false;

		while (true) {
			if (!ParseMemTerm(op.mem, negative)) {
				return false;
			}
			negative = false;
			if (current_->type == TokenType::kBracketClose) {
				return ConsumeToken();
			}
			if (current_->type == TokenType::kMinus) {
				negative = true;
			}
			else if (current_->type == TokenType::kPlus) {
				negative = false;
			}
			else {
				current_->PrintError("Invalid format for memory operand");
				return false;
			}
			if (!ConsumeToken()) return false;
		}
	}
	constexpr bool Parser::ParseOperand(Operand& op) {
		// operand may be
		// $var (variable)
		// $var:type (typed variable)
		bool negative = false;

		if (current_->type == TokenType::kQuestion ||
			current_->type == TokenType::kDollar) {
			return ParseWildcardOrVariable(op);
		}
		if (current_->type == TokenType::kIdentifier) {
			if (FutureToken().type == TokenType::kColon) {
				return ParseMemoryOperand(op);
			}
			op.type = OperandType::kRegister;
			return FillReg(op.reg);
		}
		if (current_->type == TokenType::kBracketOpen) {
			return ParseMemoryOperand(op);
		}
		if (current_->type == TokenType::kMinus) {
			negative = true;
			if (!ConsumeToken()) return false;
		}
		if (current_->type == TokenType::kNumber) {
			op.type = OperandType::kImmediate;
			return FillImm(op.imm, negative);
		}
		current_->PrintError("Invalid operand");
		return false;
	}
	constexpr bool Parser::ParseMnemonic() {
		MatchInstruction inst;
		inst.mnemonic = tables::FindMnemonic(current_->value.str);
		if (inst.mnemonic == ZYDIS_MNEMONIC_INVALID) {
			current_->PrintError("Invalid mnemonic");
			return false;
		}
		if (!ConsumeToken()) return false;
		while (current_->type != TokenType::kNewline &&
			current_->type != TokenType::kEOF) {
			if (inst.operand_count == inst.operands.size()) {
				current_->PrintError("Maximum number of operands exceeded");
				return false;
			}
			if (!ParseOperand(inst.operands[inst.operand_count++])) {
				return false;
			}
			if (current_->type == TokenType::kComma) {
				if (!ConsumeToken()) return false;
				// an operand has to follow: without this 'mov rax,' parses as
				// 'mov rax' because the loop condition ends the instruction
				if (current_->type == TokenType::kNewline ||
					current_->type == TokenType::kEOF) {
					current_->PrintError("Trailing comma, operand expected");
					return false;
				}
			}
			else if (current_->type != TokenType::kNewline &&
				current_->type != TokenType::kEOF) {
				current_->PrintError("Operands must be separated by comma (got {})",
					TokenTypeToString(current_->type));
				return false;
			}
		}
		pattern_.instructions.push_back(inst);
		return true;
	}
	constexpr bool Parser::ParseInstruction() {
		if (current_->type == TokenType::kNewline) {
			if (!ConsumeToken()) return false;
			return true;
		}
		if (current_->type == TokenType::kLessThan) {
			if (!ConsumeToken()) return false;
			return ParseSkipRange();
		}
		if (current_->type == TokenType::kIdentifier) {
			return ParseMnemonic();
		}
		return false;
	}
	constexpr Pattern Parser::Parse() {
		current_ = tokens_.begin();
		while (current_ != tokens_.end() &&
			current_->type != TokenType::kEOF) {
			if (!ParseInstruction()) {
				return {};
			}
		}
		return pattern_;
	}

	constexpr Pattern Parser::Parse(const std::vector<Token>& tokens) {
		Parser ctx(tokens);
		return ctx.Parse();
	}
	constexpr Pattern Parser::Parse(std::string_view query) {
		Parser ctx(
			Lexer::Tokenize(query)
		);
		return ctx.Parse();
	}
} // namespace zigil

#endif // ZIGIL_PARSER_HH_