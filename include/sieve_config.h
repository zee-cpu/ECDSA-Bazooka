#pragma once

#include <map>
#include <optional>
#include <string>

// Zero-config resolution of the sieve worker environment. The bootstrap writes
// worker/sieve-env.sh; the binary finds and reads it so the user never has to
// set BAZOOKA_SIEVE_* env vars by hand. Explicit env vars always win.
namespace sieve_config {

    // Parse `export KEY="value"` lines from a sieve-env.sh file. Missing file
    // or unreadable -> empty map (never throws).
    std::map<std::string, std::string> parse_env_file(const std::string& path);

    // Locate sieve-env.sh relative to the running executable (../worker/,
    // ./worker/, /opt/ecdsa-bazooka/worker/). nullopt if none found.
    std::optional<std::string> find_env_file();

    // If BAZOOKA_SIEVE_WORKER is not already in the environment, find sieve-env.sh
    // and setenv() its vars (without overwriting any already set). No-op if the
    // env is already configured or no file is found.
    void ensure_env();

    // Compose the PYTHONPATH value for the worker from a sieve-env.sh value that
    // may use the shell idiom `DIR${PYTHONPATH:+:$PYTHONPATH}`: take the literal
    // prefix before the first '$', then prepend it to `current` (the process's
    // existing PYTHONPATH), matching what sourcing the file in a shell would do.
    std::string resolve_pythonpath(const std::string& file_value, const std::string& current);

} // namespace sieve_config
