#include "types.h"
#include "parser.h"
#include "pair_computation.h"
#include "recovery_engine.h"
#include "telemetry.h"
#include "utils.h"
#include <iostream>
#include <string>
#include <chrono>
#include <getopt.h>
#include <cstdlib>

static void print_usage(const char* prog) {
    std::cout << "ECDSA Nonce-Bias Key Recovery Engine (Lattice HNP: LLL/BKZ)\n\n";
    std::cout << "Usage: " << prog << " [options] <input.txt>\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i, --input FILE       Input signature file (required)\n";
    std::cout << "  -m, --method METHOD    Force method: auto | lattice | fallback | modulo | linear (default: auto)\n";
    std::cout << "  -s, --max-sigs N       Maximum signatures to use\n";
    std::cout << "  -t, --max-time SEC     Max time budget (seconds)\n";
    std::cout << "  -v, --verbose          Enable live telemetry dashboard\n";
    std::cout << "  -q, --quiet            Disable live updates (for logs)\n";
    std::cout << "      --allow-no-pubkey  Permit best-effort recovery when signatures\n";
    std::cout << "                         lack a PubKey (result cannot be verified)\n";
    std::cout << "      --seed N           Sampling RNG seed (default fixed; for reproducibility)\n";
    std::cout << "      --modulo-omega N   Modulo/EHNP hint: period omega (k mod omega in [0,bound))\n";
    std::cout << "      --modulo-bound N   Modulo/EHNP hint: residue bound (use with --modulo-omega)\n";
    std::cout << "      --lcg-a N          Linear-nonce hint: LCG multiplier a (k_{i+1}=a*k_i+b mod n)\n";
    std::cout << "      --lcg-b N          Linear-nonce hint: LCG increment b (default 0; use with --lcg-a)\n";
    std::cout << "  -h, --help             Show this help\n";
    std::cout << "\n";
    std::cout << "Example:\n";
    std::cout << "  " << prog << " -i data/test_msb_16b_2k.txt -v\n";
}

RecoveryMethod parse_method(const std::string& s) {
    if (s == "lattice") return RecoveryMethod::LATTICE;
    if (s == "fallback") return RecoveryMethod::FALLBACK;
    if (s == "modulo") return RecoveryMethod::MODULO;
    if (s == "linear") return RecoveryMethod::LINEAR;
    return RecoveryMethod::AUTO;
}

int main(int argc, char** argv) {
    std::string input_file;
    RecoveryMethod force_method = RecoveryMethod::AUTO;
    size_t max_sigs = 0;
    double max_time = 0.0;
    bool verbose = true;
    bool quiet = false;
    bool allow_no_pubkey = false;
    uint64_t sampling_seed = DEFAULT_SAMPLING_SEED;
    mpz modulo_omega = 0;   // Phase 6c hint
    mpz modulo_bound = 0;
    mpz lcg_a = 0;          // Phase 6d hint
    mpz lcg_b = 0;

    enum { OPT_ALLOW_NO_PUBKEY = 1000, OPT_SEED = 1001,
           OPT_MOD_OMEGA = 1002, OPT_MOD_BOUND = 1003,
           OPT_LCG_A = 1004, OPT_LCG_B = 1005 };
    static struct option long_opts[] = {
        {"input", required_argument, 0, 'i'},
        {"method", required_argument, 0, 'm'},
        {"max-sigs", required_argument, 0, 's'},
        {"max-time", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"quiet", no_argument, 0, 'q'},
        {"allow-no-pubkey", no_argument, 0, OPT_ALLOW_NO_PUBKEY},
        {"seed", required_argument, 0, OPT_SEED},
        {"modulo-omega", required_argument, 0, OPT_MOD_OMEGA},
        {"modulo-bound", required_argument, 0, OPT_MOD_BOUND},
        {"lcg-a", required_argument, 0, OPT_LCG_A},
        {"lcg-b", required_argument, 0, OPT_LCG_B},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int idx = 0;
    while ((opt = getopt_long(argc, argv, "i:m:s:t:vqh", long_opts, &idx)) != -1) {
        switch (opt) {
            case 'i':
                input_file = optarg;
                break;
            case 'm':
                force_method = parse_method(optarg);
                break;
            case 's':
                max_sigs = std::stoull(optarg);
                break;
            case 't':
                max_time = std::stod(optarg);
                break;
            case 'v':
                verbose = true;
                quiet = false;
                break;
            case 'q':
                quiet = true;
                verbose = false;
                break;
            case OPT_ALLOW_NO_PUBKEY:
                allow_no_pubkey = true;
                break;
            case OPT_SEED:
                sampling_seed = std::stoull(optarg, nullptr, 0);  // accepts 0x.. or decimal
                break;
            case OPT_MOD_OMEGA:
                if (modulo_omega.set_str(optarg, 0) != 0) {  // 0 = auto-detect base (0x/dec)
                    std::cerr << "Error: invalid --modulo-omega value\n"; return 1;
                }
                break;
            case OPT_MOD_BOUND:
                if (modulo_bound.set_str(optarg, 0) != 0) {
                    std::cerr << "Error: invalid --modulo-bound value\n"; return 1;
                }
                break;
            case OPT_LCG_A:
                if (lcg_a.set_str(optarg, 0) != 0) {
                    std::cerr << "Error: invalid --lcg-a value\n"; return 1;
                }
                break;
            case OPT_LCG_B:
                if (lcg_b.set_str(optarg, 0) != 0) {
                    std::cerr << "Error: invalid --lcg-b value\n"; return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (input_file.empty() && optind < argc) {
        input_file = argv[optind];
    }

    if (input_file.empty()) {
        std::cerr << "Error: input file required\n";
        print_usage(argv[0]);
        return 1;
    }

    // Phase 6c: the modulo hint is a pair -- one without the other is a usage
    // error (a lone omega has no residue bound to constrain against).
    if ((modulo_omega > 0) != (modulo_bound > 0)) {
        std::cerr << "Error: --modulo-omega and --modulo-bound must be given together\n";
        return 1;
    }
    if (modulo_omega > 0 && modulo_bound >= modulo_omega) {
        std::cerr << "Error: --modulo-bound must be smaller than --modulo-omega\n";
        return 1;
    }

    Telemetry telemetry;
    telemetry.reset();

    // Parse
    std::cout << "[*] Parsing " << input_file << " ...\n";
    auto signatures = SignatureParser::parse_file(input_file, &telemetry);

    if (signatures.empty()) {
        std::cerr << "No signatures parsed from " << input_file << std::endl;
        return 1;
    }

    std::cout << "[+] Parsed " << signatures.size() << " signatures ("
              << telemetry.signatures_valid.load() << " valid)\n";

    // Input-integrity boundary: enforce a single public key and the
    // missing-pubkey policy before any expensive work begins.
    ValidatedGroup group = SignatureParser::validate_and_group(signatures, allow_no_pubkey);
    if (!group.ok) {
        std::cerr << "[input] REJECTED: " << group.error << "\n";
        return 1;
    }
    std::cout << "[+] Input policy: " << group.policy << "\n";

    // Compute pairs (from the validated, single-key group)
    auto pairs = PairComputer::compute_pairs(group.signatures, &telemetry);
    std::cout << "[+] Computed " << pairs.size() << " (w, x) pairs\n";

    if (pairs.empty()) {
        std::cerr << "No valid pairs.\n";
        return 1;
    }

    // Engine
    RecoveryEngine engine(telemetry);

    // Start live dashboard if requested
    TelemetryRenderer* renderer = nullptr;
    if (verbose && !quiet) {
        renderer = new TelemetryRenderer(telemetry);
        renderer->start();
    } else {
        telemetry.set_phase("Running (no live UI)");
    }

    // Run recovery (on the validated single-key group)
    RecoveryResult res = engine.run(
        group.signatures,
        pairs,
        force_method,
        max_sigs,
        max_time,
        sampling_seed,
        modulo_omega,
        modulo_bound,
        lcg_a,
        lcg_b
    );

    // Stop renderer
    if (renderer) {
        renderer->stop();
        delete renderer;
    }

    // Final report
    std::cout << "\n\n=== RECOVERY RESULT ===\n";
    std::cout << "Input: " << input_file << "\n";
    std::cout << "Input policy: " << group.policy << "\n";
    std::cout << "Sampling seed: 0x" << std::hex << sampling_seed << std::dec
              << " (reproduce with --seed 0x" << std::hex << sampling_seed << std::dec << ")\n";
    std::cout << "Signatures processed: " << res.signatures_used << "\n";
    std::cout << "Bias profile: " << (res.bias_profile.bias_detected ? "DETECTED" : "NONE/UNKNOWN") << "\n";
    auto bias_type_name = [](BiasType t) {
        switch (t) {
            case BiasType::MSB: return "MSB";
            case BiasType::LSB: return "LSB";
            case BiasType::MODULO: return "MODULO";
            case BiasType::NONE: return "NONE";
            default: return "UNKNOWN";
        }
    };
    std::cout << "  Type: " << bias_type_name(res.bias_profile.type) << "\n";
    std::cout << "  Leaked bits est: " << res.bias_profile.estimated_leaked_bits << "\n";
    std::cout << "  Confidence: p < 10^-" << res.bias_profile.neg_log10_p << "\n";
    std::cout << "  Description: " << res.bias_profile.description << "\n";

    if (res.success) {
        std::cout << "\n[SUCCESS] Private key recovered and VERIFIED:\n";
        std::cout << "  d = 0x" << res.private_key_hex << "\n";
        auto method_name = [](RecoveryMethod m) {
            switch (m) {
                case RecoveryMethod::LATTICE: return "LATTICE";
                case RecoveryMethod::FALLBACK: return "FALLBACK";
                case RecoveryMethod::REPEATED_NONCE: return "REPEATED_NONCE";
                case RecoveryMethod::MODULO: return "MODULO (Extended-HNP)";
                case RecoveryMethod::LINEAR: return "LINEAR (LCG nonces)";
                default: return "UNKNOWN";
            }
        };
        std::cout << "  Method: " << method_name(res.method_used) << "\n";
        std::cout << "  Runtime: " << std::fixed << std::setprecision(2) << res.runtime_seconds << "s\n";
        std::cout << "  Verification: " << res.verification_details << "\n";
        return 0;
    } else {
        std::cout << "\n[FAILURE] No key recovered.\n";
        std::cout << "  Details: " << res.verification_details << "\n";
        if (!telemetry.get_error().empty()) {
            std::cout << "  Error: " << telemetry.get_error() << "\n";
        }
        return 3;
    }
}
