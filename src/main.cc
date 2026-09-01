// zigil - x86-64 assembly pattern scanner, command line front end.
//
// Scans a PE image, or every PE under a directory, for a pattern written as
// assembly with typed wildcards and capture variables. The pattern comes from
// the command line, so it is parsed at runtime; the compile-time _sig path is
// for patterns baked into a program (see README.md).
#include "zigil/zigil.hh"

#include "zigil/analyzer/pe_analyzer.hh"
#include "zigil/scanner.hh"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {
	struct Options {
		std::string pattern;
		std::string path;
		std::vector<std::string> extensions{ "exe", "dll", "sys", "ocx", "efi", "node", "bin" };
		size_t max_matches = 32;
		bool all_files = false;
		bool show_vars = false;
		bool use_va = false;
		bool loaded = false;
		bool stats = false;
		bool fast = false;
		bool quiet = false;
		/* name=value pairs for pre-bound variables */
		std::vector<std::pair<std::string, std::string>> prebound;
	};

	constexpr size_t kMaxImageSize = 2ull * 1024 * 1024 * 1024;

	void PrintUsage() {
		printf(
			"zigil - x86-64 assembly pattern scanner\n"
			"\n"
			"usage:\n"
			"  zigil <pattern> <path> [options]\n"
			"  zigil -f <pattern-file> <path> [options]\n"
			"\n"
			"  <pattern>  the pattern in quotes. Separate instructions with a real\n"
			"             newline or with the two characters \\n\n"
			"  <path>     a PE image, or a directory that is searched recursively\n"
			"\n"
			"options:\n"
			"  -f, --file <path>   read the pattern from a file\n"
			"  -n, --max <count>   stop after <count> matches per file (default 32, 0 = all)\n"
			"  -v, --vars          print the captured variables of every match\n"
			"      --va            print virtual addresses instead of RVAs\n"
			"      --ext <list>    comma separated extensions to scan\n"
			"                      (default: exe,dll,sys,ocx,efi,node,bin)\n"
			"  -a, --all           scan every file, whatever its extension\n"
			"      --loaded        the input is already a flat image (a dumped module)\n"
			"      --stats         print the analyzer report for every file\n"
			"      --fast          recursive descent only: no pointer scan, no prologue\n"
			"                      scan, no gap sweep. Faster, finds less.\n"
			"      --set <n>=<v>   pre-bind variable <n> to <v> instead of capturing it.\n"
			"                      A register name binds as a register, a number as an\n"
			"                      address or immediate. Turns a pattern into an xref\n"
			"                      search. Repeatable.\n"
			"  -q, --quiet         only list files that matched\n"
			"  -h, --help          this text\n"
			"\n"
			"examples:\n"
			"  zigil \"mov rcx, [rax+0x10]\\ncall [rcx+?]\" C:\\windows\\system32\\ntdll.dll\n"
			"  zigil -f vtable.zig .\\modules -v\n"
			"  zigil \"lea $reg:r64, [rip+$str]\\ncall ?\" game.exe -v --va\n"
			"  zigil \"mov $r:r64, [rip+$g]\" game.exe --set g=0x1A2B3C -v\n"
			"\n"
			"exit code: 0 if something matched, 1 if nothing did, 2 on a usage error.\n");
	}

	/* turns the two characters \n in an argument into a real newline */
	std::string Unescape(std::string_view text) {
		std::string out;
		out.reserve(text.size());
		for (size_t i = 0; i < text.size(); i++) {
			if (text[i] == '\\' && i + 1 < text.size()) {
				const char next = text[i + 1];
				if (next == 'n') { out += '\n'; i++; continue; }
				if (next == 't') { out += '\t'; i++; continue; }
				if (next == '\\') { out += '\\'; i++; continue; }
			}
			out += text[i];
		}
		return out;
	}

	std::string ReadFileText(const fs::path& path) {
		std::ifstream in(path, std::ios::binary);
		if (!in) {
			return {};
		}
		return std::string((std::istreambuf_iterator<char>(in)),
			std::istreambuf_iterator<char>());
	}

	std::vector<uint8_t> ReadFileBytes(const fs::path& path) {
		std::ifstream in(path, std::ios::binary | std::ios::ate);
		if (!in) {
			return {};
		}
		const std::streamoff size = in.tellg();
		if (size <= 0 || (size_t)size > kMaxImageSize) {
			return {};
		}
		std::vector<uint8_t> data((size_t)size);
		in.seekg(0, std::ios::beg);
		in.read((char*)data.data(), size);
		return data;
	}

	/* cheap pre-filter so a directory scan does not report every text file */
	bool LooksLikePe(const fs::path& path) {
		std::ifstream in(path, std::ios::binary);
		if (!in) {
			return false;
		}
		char dos[0x40]{};
		in.read(dos, sizeof(dos));
		if (in.gcount() < (std::streamsize)sizeof(dos) || dos[0] != 'M' || dos[1] != 'Z') {
			return false;
		}
		int32_t e_lfanew = 0;
		memcpy(&e_lfanew, dos + 0x3C, sizeof(e_lfanew));
		if (e_lfanew < 0) {
			return false;
		}
		in.seekg(e_lfanew, std::ios::beg);
		char nt[4]{};
		in.read(nt, sizeof(nt));
		return in.gcount() == (std::streamsize)sizeof(nt) &&
			nt[0] == 'P' && nt[1] == 'E' && nt[2] == 0 && nt[3] == 0;
	}

	/*
	* A runtime parsed Pattern carries its variable names, so they can just be
	* read back. A compile-time pattern only would if it was built with
	* ZIGIL_KEEP_VARIABLE_NAMES; NameOf returns an empty view otherwise, which is
	* why this falls back to $vN.
	*/
	std::string VariableLabel(zigil::PatternView view, size_t index) {
		const std::string_view name = view.NameOf((uint8_t)index);
		return name.empty() ? "v" + std::to_string(index) : std::string(name);
	}

	void PrintCapture(const zigil::Capture& capture, uint64_t image_base) {
		switch (capture.kind) {
		case zigil::CaptureKind::kRegister:
			printf("%s", zigil::tables::RegisterToString(capture.reg).data());
			break;
		case zigil::CaptureKind::kImmediate:
			printf("0x%llX (%lld)", (unsigned long long)capture.value,
				(long long)capture.value);
			break;
		case zigil::CaptureKind::kAddress:
			printf("rva 0x%llX, va 0x%llX", (unsigned long long)capture.value,
				(unsigned long long)(image_base + (uint64_t)capture.value));
			break;
		case zigil::CaptureKind::kMemory:
			printf("[%s", zigil::tables::RegisterToString(capture.mem_base).data());
			if (capture.mem_index != ZYDIS_REGISTER_NONE) {
				printf("+%s*%u", zigil::tables::RegisterToString(capture.mem_index).data(),
					capture.mem_scale);
			}
			printf("%+lld]", (long long)capture.value);
			break;
		default:
			printf("(unbound)");
			break;
		}
	}

	struct FileResult {
		size_t matches = 0;
		bool analyzed = false;
		double seconds = 0.0;
	};

	FileResult ScanFile(const fs::path& path, const std::string& label,
		zigil::PatternView pattern, const Options& options) {
		FileResult result;
		const auto start = std::chrono::steady_clock::now();

		const std::vector<uint8_t> data = ReadFileBytes(path);
		if (data.empty()) {
			return result;
		}
		zigil::analyzer::AnalysisOptions analysis;
		analysis.progress = options.stats;
		if (options.fast) {
			analysis.scan_pointers = false;
			analysis.scan_prologues = false;
			analysis.sweep_gaps = false;
		}
		zigil::analyzer::PEAnalyzer analyzer;
		if (!analyzer.Analyze(data.data(), data.size(), options.loaded, analysis)) {
			return result;
		}
		result.analyzed = true;
		if (options.stats) {
			analyzer.PrintReport();
		}

		zigil::Scanner scanner(analyzer);
		for (const auto& [name, value] : options.prebound) {
			// a register name binds as a register, anything else as a number that
			// satisfies an immediate as well as a resolved address
			const ZydisRegister reg = zigil::tables::FindRegister(value);
			if (reg != ZYDIS_REGISTER_NONE) {
				scanner.Set(name, reg);
			}
			else {
				scanner.Set(name, strtoull(value.c_str(), nullptr, 0));
			}
		}
		const std::vector<zigil::MatchResult> matches =
			scanner.FindAll(pattern, options.max_matches);
		result.matches = matches.size();
		result.seconds =
			std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

		if (matches.empty()) {
			if (!options.quiet) {
				printf("%-60s  no match   (%.1fs)\n", label.c_str(), result.seconds);
			}
			return result;
		}
		printf("%-60s  %zu match%s  (%.1fs)\n", label.c_str(), matches.size(),
			matches.size() == 1 ? "" : "es", result.seconds);
		for (const zigil::MatchResult& match : matches) {
			if (options.use_va) {
				printf("  va 0x%llX\n", (unsigned long long)match.Va());
			}
			else {
				printf("  rva 0x%llX  (va 0x%llX)\n",
					(unsigned long long)match.Rva(), (unsigned long long)match.Va());
			}
			if (!options.show_vars) {
				continue;
			}
			for (size_t i = 0; i < match.CaptureCount(); i++) {
				const zigil::Capture* capture = match.CaptureAt(i);
				printf("      %-16s = ", VariableLabel(pattern, i).c_str());
				PrintCapture(*capture, analyzer.ImageBase());
				printf("\n");
			}
		}
		return result;
	}

	bool WantedExtension(const fs::path& path, const Options& options) {
		if (options.all_files) {
			return true;
		}
		std::string ext = path.extension().string();
		if (ext.empty()) {
			return false;
		}
		ext.erase(ext.begin());
		for (char& c : ext) {
			c = (char)zigil::tables::ToLower(c);
		}
		for (const std::string& wanted : options.extensions) {
			if (ext == wanted) {
				return true;
			}
		}
		return false;
	}

	bool ParseArguments(int argc, char** argv, Options& options) {
		std::vector<std::string> positional;
		bool pattern_from_file = false;

		for (int i = 1; i < argc; i++) {
			const std::string arg = argv[i];
			const auto value = [&](const char* name) -> const char* {
				if (i + 1 >= argc) {
					printf("zigil: %s needs a value\n", name);
					return nullptr;
				}
				return argv[++i];
				};
			if (arg == "-h" || arg == "--help") {
				PrintUsage();
				return false;
			}
			else if (arg == "-f" || arg == "--file") {
				const char* file = value("--file");
				if (!file) return false;
				options.pattern = ReadFileText(file);
				if (options.pattern.empty()) {
					printf("zigil: cannot read the pattern file %s\n", file);
					return false;
				}
				pattern_from_file = true;
			}
			else if (arg == "-n" || arg == "--max") {
				const char* count = value("--max");
				if (!count) return false;
				options.max_matches = strtoull(count, nullptr, 0);
			}
			else if (arg == "--ext") {
				const char* list = value("--ext");
				if (!list) return false;
				options.extensions.clear();
				std::string current;
				for (const char* c = list; ; c++) {
					if (*c == ',' || !*c) {
						if (!current.empty()) {
							options.extensions.push_back(current);
							current.clear();
						}
						if (!*c) break;
						continue;
					}
					current += (char)zigil::tables::ToLower(*c);
				}
			}
			else if (arg == "--set") {
				const char* pair = value("--set");
				if (!pair) return false;
				const char* eq = strchr(pair, '=');
				if (!eq || eq == pair || !eq[1]) {
					printf("zigil: --set wants <name>=<value>, got %s\n", pair);
					return false;
				}
				options.prebound.emplace_back(std::string(pair, eq - pair), std::string(eq + 1));
			}
			else if (arg == "-v" || arg == "--vars") { options.show_vars = true; }
			else if (arg == "--va") { options.use_va = true; }
			else if (arg == "-a" || arg == "--all") { options.all_files = true; }
			else if (arg == "--loaded") { options.loaded = true; }
			else if (arg == "--stats") { options.stats = true; }
			else if (arg == "--fast") { options.fast = true; }
			else if (arg == "-q" || arg == "--quiet") { options.quiet = true; }
			else if (!arg.empty() && arg[0] == '-' && arg != "-") {
				printf("zigil: unknown option %s\n", arg.c_str());
				return false;
			}
			else {
				positional.push_back(arg);
			}
		}

		size_t next = 0;
		if (!pattern_from_file) {
			if (positional.empty()) {
				PrintUsage();
				return false;
			}
			options.pattern = Unescape(positional[next++]);
		}
		if (next >= positional.size()) {
			printf("zigil: no path given\n");
			return false;
		}
		options.path = positional[next];
		return true;
	}
} // namespace

int main(int argc, char** argv) {
	Options options;
	if (!ParseArguments(argc, argv, options)) {
		return 2;
	}

	const zigil::Pattern pattern = zigil::Parser::Parse(options.pattern);
	if (pattern.instructions.empty()) {
		// Parse already printed the message with line and column
		printf("zigil: the pattern does not parse\n");
		return 2;
	}
	const zigil::PatternView view = pattern.View();

	for (const auto& [name, value] : options.prebound) {
		if (view.IndexOf(zigil::detail::Fnv1a(name)) == 0xFF) {
			printf("zigil: --set %s=%s, but the pattern has no $%s\n",
				name.c_str(), value.c_str(), name.c_str());
			return 2;
		}
	}
	if (!options.quiet) {
		printf("pattern:\n");
		view.Print();
		for (const auto& [name, value] : options.prebound) {
			printf("  $%s is pre-bound to %s\n", name.c_str(), value.c_str());
		}
		printf("\n");
	}

	std::error_code error;
	const fs::path root(options.path);
	if (!fs::exists(root, error)) {
		printf("zigil: %s does not exist\n", options.path.c_str());
		return 2;
	}

	std::vector<std::pair<fs::path, std::string>> targets;
	if (fs::is_directory(root, error)) {
		for (fs::recursive_directory_iterator it(root,
			fs::directory_options::skip_permission_denied, error), end; it != end; it.increment(error)) {
			if (error) {
				error.clear();
				continue;
			}
			if (!it->is_regular_file(error) || !WantedExtension(it->path(), options)) {
				continue;
			}
			if (!LooksLikePe(it->path())) {
				continue;
			}
			targets.emplace_back(it->path(),
				fs::relative(it->path(), root, error).string());
		}
	}
	else {
		targets.emplace_back(root, root.filename().string());
	}

	if (targets.empty()) {
		printf("zigil: no PE images found under %s\n", options.path.c_str());
		return 1;
	}

	const auto start = std::chrono::steady_clock::now();
	size_t total_matches = 0;
	size_t matched_files = 0;
	size_t analyzed = 0;
	for (const auto& [path, label] : targets) {
		const FileResult result = ScanFile(path, label, view, options);
		analyzed += result.analyzed ? 1 : 0;
		total_matches += result.matches;
		matched_files += result.matches ? 1 : 0;
	}
	const double seconds =
		std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

	if (targets.size() > 1 || !options.quiet) {
		printf("\nanalyzed %zu of %zu file%s, %zu matched, %zu match%s total, %.1fs\n",
			analyzed, targets.size(), targets.size() == 1 ? "" : "s",
			matched_files, total_matches, total_matches == 1 ? "" : "es", seconds);
	}
	return total_matches ? 0 : 1;
}
