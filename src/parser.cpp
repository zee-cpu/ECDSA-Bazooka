#include "parser.h"
#include "secp256k1.h"
#include <sstream>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cctype>

// Input-integrity limits (Phase 2). These bound the work a hostile or corrupt
// file can force before any of it reaches the (expensive) solver. They are
// generous relative to any real wallet-history input.
namespace {
    constexpr std::uintmax_t MAX_FILE_BYTES = 512ull * 1024 * 1024;  // 512 MiB
    constexpr size_t MAX_RECORDS = 5'000'000;   // signature blocks
    constexpr size_t MAX_SCALAR_HEX = 64;       // 256-bit scalar => 64 hex digits
    constexpr size_t MAX_PUBKEY_HEX = 130;      // uncompressed SEC1 => 65 bytes

    // secp256k1 scalars r,s must lie in [1, n): 0 is degenerate and values
    // >= n are non-canonical (and break the modular-inverse assumptions).
    bool in_scalar_range(const mpz& v) {
        return v >= 1 && v < SECP256K1_N;
    }
}

std::string SignatureParser::trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

bool SignatureParser::parse_hex_to_mpz(const std::string& hex_str, mpz& out, size_t max_hex_len) {
    std::string h = trim(hex_str);
    if (h.empty()) return false;
    if (h.size() > 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) {
        h = h.substr(2);
    }
    // Reject over-length fields before touching GMP: an unbounded hex string
    // would otherwise allocate/convert an arbitrarily large integer.
    if (h.empty() || h.size() > max_hex_len) return false;
    for (char c : h) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    try {
        out.set_str(h, 16);
        return true;
    } catch (...) { return false; }
}

bool SignatureParser::validate_signature(Signature& sig) {
    if (!in_scalar_range(sig.r)) { sig.reject_reason = "r out of range [1, n)"; return false; }
    if (!in_scalar_range(sig.s)) { sig.reject_reason = "s out of range [1, n)"; return false; }
    // z is the (possibly truncated) message hash. Canonicalize into [0, n):
    // reducing mod n is mathematically identical downstream (w = z*s^-1 mod n)
    // and tolerates hashes that were not pre-reduced.
    sig.z %= SECP256K1_N;
    // If a PubKey was supplied it must be a genuine curve point. Absence is a
    // policy decision handled at the input boundary (validate_and_group),
    // not here.
    if (sig.pubkey != 0 && !secp256k1::pubkey_to_point(sig.pubkey).has_value()) {
        sig.reject_reason = "PubKey is not a valid secp256k1 point";
        return false;
    }
    // Phase 6b: if a known low-bit leak was supplied, it must be well-formed --
    // a positive width no wider than the scalar, and a residue that actually
    // fits in that width (0 <= value < 2^bits). We can't check it against the
    // real nonce (k is secret), so a bad range is the only detectable error.
    if (sig.known_low_bits != 0) {
        if (sig.known_low_bits < 1 || sig.known_low_bits > 64) {
            sig.reject_reason = "KnownLow bit width out of range [1, 64]";
            return false;
        }
        if (sig.known_low_value < 0 || sig.known_low_value >= (mpz(1) << sig.known_low_bits)) {
            sig.reject_reason = "KnownLow value does not fit in the given bit width";
            return false;
        }
    }
    sig.reject_reason.clear();
    return true;
}

std::optional<Signature> SignatureParser::parse_block(const std::string& block_text) {
    Signature sig;
    bool r_seen = false, s_seen = false, z_seen = false, pk_seen = false;
    bool r_ok = false, s_ok = false, z_ok = false, pk_ok = false;
    bool timestamp_seen = false, timestamp_ok = false;
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

            if (key == "R" || key == "r") { r_seen = true; r_ok = parse_hex_to_mpz(val, sig.r, MAX_SCALAR_HEX); }
            else if (key == "S" || key == "s") { s_seen = true; s_ok = parse_hex_to_mpz(val, sig.s, MAX_SCALAR_HEX); }
            else if (key == "Z" || key == "z") { z_seen = true; z_ok = parse_hex_to_mpz(val, sig.z, MAX_SCALAR_HEX); }
        } else if (l.find("PubKey") == 0) {
            size_t c = l.find(':');
            if (c != std::string::npos) { pk_seen = true; pk_ok = parse_hex_to_mpz(trim(l.substr(c + 1)), sig.pubkey, MAX_PUBKEY_HEX); }
        } else if (l.find("KnownLow") == 0) {
            // Phase 6b: known leaked low bits of this signature's nonce, from a
            // side channel. Format: "KnownLow: <bits> <value_hex>", e.g.
            // "KnownLow: 8 0xab" meaning k ≡ 0xab (mod 2^8). Range-checked in
            // validate_signature; a malformed field leaves the default (none).
            size_t c = l.find(':');
            if (c != std::string::npos) {
                std::istringstream ks(trim(l.substr(c + 1)));
                std::string bstr, vstr;
                if (ks >> bstr >> vstr) {
                    mpz v;
                    try {
                        int b = std::stoi(bstr);
                        if (parse_hex_to_mpz(vstr, v, MAX_SCALAR_HEX)) {
                            sig.known_low_bits = b;
                            sig.known_low_value = v;
                        }
                    } catch (...) {}
                }
            }
        } else if (l.find("TXID") == 0) {
            size_t c = l.find(':');
            if (c != std::string::npos) sig.txid = trim(l.substr(c + 1));
        } else if (l.find("Timestamp") == 0) {
            timestamp_seen = true;
            size_t c = l.find(':');
            if (c != std::string::npos) {
                try {
                    std::string value = trim(l.substr(c + 1));
                    size_t consumed = 0;
                    int64_t parsed = std::stoll(value, &consumed);
                    if (consumed == value.size()) {
                        sig.timestamp = parsed;
                        sig.timestamp_present = true;
                        timestamp_ok = true;
                    }
                } catch (...) {}
            }
        }
    }

    // Required-field integrity: distinguish missing from malformed so the
    // diagnostic names the actual problem in the source record.
    auto reject = [&](const std::string& why) {
        sig.valid = false;
        sig.reject_reason = why;
        return std::make_optional(sig);
    };
    if (!r_seen) return reject("missing R field");
    if (!r_ok)   return reject("malformed R (non-hex or over-length)");
    if (!s_seen) return reject("missing S field");
    if (!s_ok)   return reject("malformed S (non-hex or over-length)");
    if (!z_seen) return reject("missing Z field");
    if (!z_ok)   return reject("malformed Z (non-hex or over-length)");
    if (pk_seen && !pk_ok) return reject("malformed PubKey (non-hex or over-length)");
    if (timestamp_seen && !timestamp_ok) return reject("malformed Timestamp");

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

    // Bound the read up front: a hostile/corrupt file must not be able to
    // slurp an unbounded amount into memory before we even parse it.
    file.seekg(0, std::ios::end);
    std::streamoff file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (file_size < 0 || static_cast<std::uintmax_t>(file_size) > MAX_FILE_BYTES) {
        if (telemetry) telemetry->set_error("Input file exceeds size limit (" +
            std::to_string(MAX_FILE_BYTES) + " bytes)");
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

    if (blocks.size() > MAX_RECORDS) {
        if (telemetry) telemetry->set_error("Input exceeds record limit (" +
            std::to_string(MAX_RECORDS) + " signature blocks)");
        return signatures;
    }

    int block_count = 0;
    int valid_count = 0;
    int skipped = 0;
    std::vector<std::pair<size_t, std::string>> rejects;  // (index, reason), capped

    for (const auto& blk : blocks) {
        auto opt = parse_block(blk);
        ++block_count;

        if (opt.has_value()) {
            Signature s = *opt;
            s.index = static_cast<size_t>(block_count);  // 1-based source position
            if (s.valid) {
                signatures.push_back(s);
                ++valid_count;
            } else {
                ++skipped;
                if (rejects.size() < 10)
                    rejects.emplace_back(s.index, s.reject_reason.empty() ? "invalid" : s.reject_reason);
            }
        } else {
            ++skipped;
        }
    }

    // Actionable diagnostics: name a bounded sample of rejected records and
    // why, rather than silently dropping them.
    if (skipped > 0) {
        std::cerr << "[parser] rejected " << skipped << " of " << block_count
                  << " records:\n";
        for (const auto& [idx, why] : rejects)
            std::cerr << "  - signature #" << idx << ": " << why << "\n";
        if (static_cast<size_t>(skipped) > rejects.size())
            std::cerr << "  - ... and " << (skipped - static_cast<int>(rejects.size()))
                      << " more\n";
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

ValidatedGroup SignatureParser::validate_and_group(const std::vector<Signature>& valid_sigs,
                                                   bool allow_no_pubkey) {
    ValidatedGroup g;
    if (valid_sigs.empty()) {
        g.error = "no valid signatures to recover from";
        return g;
    }

    // Collect the distinct non-zero public keys and count keyless records.
    std::vector<mpz> distinct;
    size_t missing = 0;
    for (const auto& s : valid_sigs) {
        if (s.pubkey == 0) { ++missing; continue; }
        if (std::find(distinct.begin(), distinct.end(), s.pubkey) == distinct.end())
            distinct.push_back(s.pubkey);
    }

    // Multiple distinct keys can never be recovered together in one lattice.
    if (distinct.size() > 1) {
        g.error = "input mixes " + std::to_string(distinct.size()) +
                  " distinct public keys; recovery requires a single key "
                  "(split the input by PubKey and run each group separately)";
        return g;
    }

    // Missing-pubkey policy: strict by default, opt-in best-effort.
    if (missing > 0 && !allow_no_pubkey) {
        g.error = std::to_string(missing) + " of " + std::to_string(valid_sigs.size()) +
                  " signatures are missing a PubKey; recovery requires PubKey by default "
                  "(pass --allow-no-pubkey for best-effort, unverifiable recovery)";
        return g;
    }

    g.signatures = valid_sigs;
    g.pubkey = distinct.empty() ? mpz(0) : distinct.front();
    g.ok = true;
    if (distinct.empty()) {
        g.policy = "best-effort: no PubKey present (result cannot be pubkey-verified)";
    } else if (missing > 0) {
        g.policy = "best-effort: single PubKey; " + std::to_string(missing) +
                   " keyless record(s) assumed same-key";
    } else {
        g.policy = "strict: all " + std::to_string(valid_sigs.size()) +
                   " signatures share one PubKey";
    }
    return g;
}
