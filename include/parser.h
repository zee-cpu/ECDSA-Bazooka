#pragma once

#include "types.h"
#include <string>
#include <vector>
#include <fstream>
#include <optional>

class SignatureParser {
public:
    // Parse entire file into vector of Signature. Streams for large files.
    static std::vector<Signature> parse_file(const std::string& filepath, Telemetry* telemetry = nullptr);

    // Parse single block (for testing / streaming)
    static std::optional<Signature> parse_block(const std::string& block_text);

private:
    static bool parse_hex_to_mpz(const std::string& hex_str, mpz& out);
    static bool validate_signature(const Signature& sig);
    static std::string trim(const std::string& str);
    static std::vector<std::string> split_lines(const std::string& text);
};
