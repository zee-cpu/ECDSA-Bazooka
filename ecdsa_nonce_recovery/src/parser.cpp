#include "parser.h"
#include <sstream>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cctype>

std::string SignatureParser::trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

bool SignatureParser::parse_hex_to_mpz(const std::string& hex_str, mpz& out) {
    std::string h = trim(hex_str);
    if (h.empty()) return false;
    if (h.size() > 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) {
        h = h.substr(2);
    }
    for (char c : h) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    try {
        out.set_str(h, 16);
        return true;
    } catch (...) { return false; }
}

bool SignatureParser::validate_signature(const Signature& sig) {
    return (sig.r != 0 && sig.s != 0);
}

std::optional<Signature> SignatureParser::parse_block(const std::string& block_text) {
    Signature sig;
    std::istringstream iss(block_text);
    std::string line;

    while (std::getline(iss, line)) {
        std::string l = trim(line);
        if (l.empty()) continue;
        if (l.find("Signature #") == 0) continue;

        size_t eq = l.find('=');
        if (eq != std::string::npos) {
            std::string key = trim(l.substr(0, eq));
            std::string val = trim(l.substr(eq + 1));

            if (key == "R" || key == "r") parse_hex_to_mpz(val, sig.r);
            else if (key == "S" || key == "s") parse_hex_to_mpz(val, sig.s);
            else if (key == "Z" || key == "z") parse_hex_to_mpz(val, sig.z);
        } else if (l.find("PubKey") == 0) {
            size_t c = l.find(':');
            if (c != std::string::npos) parse_hex_to_mpz(trim(l.substr(c + 1)), sig.pubkey);
        } else if (l.find("TXID") == 0) {
            size_t c = l.find(':');
            if (c != std::string::npos) sig.txid = trim(l.substr(c + 1));
        } else if (l.find("Timestamp") == 0) {
            size_t c = l.find(':');
            if (c != std::string::npos) {
                try { sig.timestamp = std::stoll(trim(l.substr(c + 1))); } catch (...) {}
            }
        }
    }

    sig.valid = validate_signature(sig);
    return sig;
}

std::vector<Signature> SignatureParser::parse_file(const std::string& filepath, Telemetry* telemetry) {
    std::vector<Signature> signatures;
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        if (telemetry) telemetry->set_error("Failed to open file: " + filepath);
        return signatures;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    // Normalize all line endings to \n
    std::string normalized;
    normalized.reserve(content.size());
    for (size_t i = 0; i < content.size(); ++i) {
        if (content[i] == '\r') {
            if (i + 1 < content.size() && content[i + 1] == '\n') ++i;
            normalized.push_back('\n');
        } else {
            normalized.push_back(content[i]);
        }
    }

    // Split on "Signature #"
    std::vector<std::string> blocks;
    size_t pos = 0;
    const std::string marker = "Signature #";

    while ((pos = normalized.find(marker, pos)) != std::string::npos) {
        size_t next = normalized.find(marker, pos + 1);
        std::string blk = (next == std::string::npos)
            ? normalized.substr(pos)
            : normalized.substr(pos, next - pos);
        if (!blk.empty()) blocks.push_back(blk);
        pos = (next == std::string::npos) ? normalized.size() : next;
    }

    int block_count = 0;
    int valid_count = 0;
    int skipped = 0;

    for (const auto& blk : blocks) {
        auto opt = parse_block(blk);
        ++block_count;

        if (opt.has_value()) {
            Signature s = *opt;
            if (s.valid) {
                signatures.push_back(s);
                ++valid_count;
            } else {
                ++skipped;
            }
        } else {
            ++skipped;
        }
    }

    if (telemetry) {
        telemetry->signatures_loaded = block_count;
        telemetry->signatures_valid = valid_count;
        telemetry->signatures_skipped = skipped;
    }

    if (signatures.empty()) {
        std::cerr << "\n[PARSER DEBUG] 0 signatures parsed from " << filepath 
                  << " (blocks found: " << blocks.size() << ")\n";
    }

    return signatures;
}
