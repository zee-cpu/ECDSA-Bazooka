#pragma once

#include "types.h"
#include <string>
#include <vector>
#include <fstream>
#include <optional>

// Result of the input-integrity boundary check (Phase 2): the accepted,
// single-public-key signature group plus the policy that was applied, or a
// populated `error` explaining why the input was rejected.
struct ValidatedGroup {
    std::vector<Signature> signatures;  // all attributable to one pubkey
    mpz pubkey = 0;                     // shared pubkey (0 => none; best-effort)
    std::string policy;                 // human-readable policy applied
    std::string error;                  // non-empty => rejected
    bool ok = false;
};

class SignatureParser {
public:
    // Parse entire file into vector of Signature. Streams for large files.
    static std::vector<Signature> parse_file(const std::string& filepath, Telemetry* telemetry = nullptr);

    // Parse single block (for testing / streaming)
    static std::optional<Signature> parse_block(const std::string& block_text);

    // Input-integrity boundary: enforce that all signatures identify a single
    // public key, and apply the missing-pubkey policy. With allow_no_pubkey
    // false (default), every signature must carry a PubKey; with it true,
    // keyless input is accepted best-effort (unverifiable). Multiple distinct
    // public keys are always rejected. Returns a ValidatedGroup whose `error`
    // is non-empty iff the input was rejected.
    static ValidatedGroup validate_and_group(const std::vector<Signature>& valid_sigs,
                                             bool allow_no_pubkey);

private:
    // max_hex_len caps the accepted hex length (excluding any 0x prefix) so a
    // hostile file cannot force an unbounded bignum allocation; over-length or
    // non-hex input is rejected.
    static bool parse_hex_to_mpz(const std::string& hex_str, mpz& out, size_t max_hex_len);
    // Validates scalar ranges / pubkey encoding; on failure records a
    // human-readable sig.reject_reason. Non-const because it populates that.
    static bool validate_signature(Signature& sig);
    static std::string trim(const std::string& str);
    static std::vector<std::string> split_lines(const std::string& text);
};
