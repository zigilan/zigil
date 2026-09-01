#include "zigil/lexer.hh"

namespace zigil {
	class LexerTests {
		static_assert(Lexer::IsDigit('1'), "Lexer::IsDigit not compile-time evaluatable");
		static_assert(Lexer::IsHexDigit('a'), "Lexer::IsHexDigit not compile-time evaluatable");
		static_assert(Lexer::DigitValue('3') == 3, "Lexer::DigitValue not compile-time evaluatable");
		static_assert(Lexer::HexDigitValue('a') == 10, "Lexer::HexDigitValue not compile-time evaluatable");
		static_assert(Lexer::IsWhitespace(' '), "Lexer::IsWhitespace not compile-time evaluatable");
		static_assert(Lexer::GetCharTokenType('<') == TokenType::kLessThan,
			"Lexer::GetCharTokenType not compile-time evaluatable");
		static_assert([] {
			std::string_view src = "0x40]";
			uint64_t n;
			return Lexer::ParseNumber(src, n) && n == 0x40 && src == "]";
		}(), "Lexer::ParseNumber failed test 1");
		static_assert([] {
			std::string_view src = "0b1101";
			uint64_t n;
			return Lexer::ParseNumber(src, n) && n == 0b1101;
		}(), "Lexer::ParseNumber failed test 2");
		static_assert([] {
			std::string_view src = "256";
			uint64_t n;
			return Lexer::ParseNumber(src, n) && n == 256;
		}(), "Lexer::ParseNumber failed test 3");
		static_assert([] {
			std::string_view src = "0x";
			uint64_t n;
			return !Lexer::ParseNumber(src, n);
		}(), "Lexer::ParseNumber failed test 4");
		static_assert([] {
			std::string_view src = "0x10000000000000000";
			uint64_t n;
			return !Lexer::ParseNumber(src, n);
		}(), "Lexer::ParseNumber failed test 5");
		static_assert([] {
			std::string_view expr = "[rcx+0x10]";
			Token t = Lexer::NextToken(expr);
			if (t.type != TokenType::kBracketOpen) return false;
			t = Lexer::NextToken(expr);
			return t.type == TokenType::kIdentifier && t.value.str == "rcx";
		}(), "Lexer::NextToken failed test");
		static_assert(Lexer::Tokenize("mov rax, [$obj+0x10]; comment").size() == 10);
	};
} // namespace zigil