#pragma once

#include "types.h"
#include <vector>

class PairComputer {
public:
    // Compute w, x for each valid signature
    static std::vector<Pair> compute_pairs(const std::vector<Signature>& sigs, Telemetry* telemetry = nullptr);
};
