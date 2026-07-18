#include "sieve_config.h"

#include <cstdlib>
#include <fstream>
#include <unistd.h>
#include <limits.h>

namespace sieve_config {

std::map<std::string, std::string> parse_env_file(const std::string& path) {
    std::map<std::string, std::string> out;
    std::ifstream f(path);
    if (!f) return out;
    std::string line;
    while (std::getline(f, line)) {
        // Match: [export ]KEY="value"   (ignore comments/blank)
        auto pos = line.find('#');
        std::string l = (pos == std::string::npos) ? line : line.substr(0, pos);
        auto eq = l.find('=');
        if (eq == std::string::npos) continue;
        std::string key = l.substr(0, eq);
        // strip leading "export " and whitespace from key
        auto ks = key.find_first_not_of(" \t");
        if (ks == std::string::npos) continue;
        key = key.substr(ks);
        const std::string kw = "export ";
        if (key.rfind(kw, 0) == 0) key = key.substr(kw.size());
        auto ke = key.find_last_not_of(" \t");
        key = key.substr(0, ke + 1);
        if (key.empty()) continue;
        // value: strip surrounding quotes/whitespace
        std::string val = l.substr(eq + 1);
        auto vs = val.find_first_not_of(" \t");
        if (vs == std::string::npos) { out[key] = ""; continue; }
        val = val.substr(vs);
        auto ve = val.find_last_not_of(" \t");
        val = val.substr(0, ve + 1);
        if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
            val = val.substr(1, val.size() - 2);
        out[key] = val;
    }
    return out;
}

std::optional<std::string> find_env_file() {
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    std::string exedir;
    if (n > 0) {
        buf[n] = '\0';
        std::string exe(buf);
        auto slash = exe.find_last_of('/');
        exedir = (slash == std::string::npos) ? "." : exe.substr(0, slash);
    } else {
        exedir = ".";
    }
    const std::string candidates[] = {
        exedir + "/../worker/sieve-env.sh",
        exedir + "/worker/sieve-env.sh",
        "/opt/ecdsa-bazooka/worker/sieve-env.sh",
    };
    for (const auto& c : candidates) {
        std::ifstream f(c);
        if (f.good()) return c;
    }
    return std::nullopt;
}

void ensure_env() {
    if (const char* w = std::getenv("BAZOOKA_SIEVE_WORKER"); w && *w) return;
    auto path = find_env_file();
    if (!path) return;
    auto vars = parse_env_file(*path);
    for (const auto& [k, v] : vars) {
        // do not overwrite anything already explicitly set
        setenv(k.c_str(), v.c_str(), /*overwrite=*/0);
    }
}

} // namespace sieve_config
