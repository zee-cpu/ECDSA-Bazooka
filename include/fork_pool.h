#pragma once
#include "types.h"        // mpz
#include <functional>
#include <optional>
#include <vector>

namespace fork_pool {

using Work = std::function<std::optional<mpz>()>;

// Run `works` with bounded concurrency until one returns a value, the units are
// exhausted, or `deadline_sec` (<=0 = none) elapses. At most `max_concurrent`
// children run at once (each a fork()ed process with its own fplll/MPFR globals
// -- invariant 2); when any child returns a non-empty result the rest are
// SIGKILLed+reaped and that result is returned. Deterministic OUTPUT for callers
// whose work-units pubkey-verify: any winner is the true key. Returns the first
// non-empty result, or nullopt.
std::optional<mpz> run_until_first(const std::vector<Work>& works,
                                   size_t max_concurrent, double deadline_sec);

// Single-child convenience: run `work` in one forked child, SIGKILL it if it
// exceeds `timeout_sec`. Equivalent to run_until_first({work}, 1, timeout_sec).
std::optional<mpz> fork_reduce(const Work& work, double timeout_sec);

}  // namespace fork_pool
