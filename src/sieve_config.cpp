#include "sieve_config.h"

#include <array>
#include <cstdio>
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
        auto s = line.find_first_not_of(" \t");
        if (s == std::string::npos || line[s] == '#') continue;
        std::string l = line.substr(s);
        const std::string kw = "export ";
        if (l.rfind(kw, 0) == 0) l = l.substr(kw.size());
        auto eq = l.find('=');
        if (eq == std::string::npos) continue;
        std::string key = l.substr(0, eq);
        auto ke = key.find_last_not_of(" \t");
        if (ke == std::string::npos) continue;
        key = key.substr(0, ke + 1);
        std::string rest = l.substr(eq + 1);
        auto vs = rest.find_first_not_of(" \t");
        if (vs == std::string::npos) { out[key] = ""; continue; }
        rest = rest.substr(vs);
        std::string val;
        if (rest.front() == '"') {
            auto close = rest.find('"', 1);
            val = (close == std::string::npos) ? rest.substr(1) : rest.substr(1, close - 1);
        } else {
            auto hash = rest.find('#');
            if (hash != std::string::npos) rest = rest.substr(0, hash);
            auto ve = rest.find_last_not_of(" \t");
            val = (ve == std::string::npos) ? "" : rest.substr(0, ve + 1);
        }
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

std::string resolve_pythonpath(const std::string& file_value, const std::string& current) {
    std::string prefix = file_value;
    auto dollar = prefix.find('$');
    if (dollar != std::string::npos) prefix = prefix.substr(0, dollar);
    while (!prefix.empty() && (prefix.back() == ':' || prefix.back() == ' ' || prefix.back() == '\t'))
        prefix.pop_back();
    if (current.empty()) return prefix;
    if (prefix.empty()) return current;
    return prefix + ":" + current;
}

void ensure_env() {
    if (const char* w = std::getenv("BAZOOKA_SIEVE_WORKER"); w && *w) return;
    auto path = find_env_file();
    if (!path) return;
    auto vars = parse_env_file(*path);
    for (const auto& [k, v] : vars) {
        if (k == "PYTHONPATH") {
            const char* cur = std::getenv("PYTHONPATH");
            std::string composed = resolve_pythonpath(v, cur ? cur : "");
            setenv("PYTHONPATH", composed.c_str(), /*overwrite=*/1);
        } else {
            // do not overwrite anything already explicitly set
            setenv(k.c_str(), v.c_str(), /*overwrite=*/0);
        }
    }
}

namespace {
    bool file_exists(const std::string& p) { std::ifstream f(p); return f.good(); }
    // Best-effort: does `python -c "import g6k"` succeed? Empty python -> unknown.
    bool python_has_g6k(const std::string& py, const std::string& pythonpath) {
        if (py.empty()) return false;
        std::string cmd = (pythonpath.empty() ? "" : "PYTHONPATH=\"" + pythonpath + "\" ")
                        + py + " -c \"import g6k\" >/dev/null 2>&1";
        return std::system(cmd.c_str()) == 0;
    }
}

std::string check_report() {
    std::string r = "core recovery : ready\n";
    auto path = find_env_file();
    if (const char* w = std::getenv("BAZOOKA_SIEVE_WORKER"); (!w || !*w) && !path) {
        r += "sieve route   : NOT set up (no worker/sieve-env.sh found)\n";
        r += "                fix: run worker/bootstrap.sh  (or use the Docker image)\n";
        return r;
    }
    auto vars = path ? parse_env_file(*path) : std::map<std::string, std::string>{};
    auto val = [&](const char* k) -> std::string {
        if (const char* e = std::getenv(k); e && *e) return e;
        auto it = vars.find(k); return it == vars.end() ? "" : it->second;
    };
    std::string worker = val("BAZOOKA_SIEVE_WORKER");
    std::string py = val("BAZOOKA_SIEVE_PYTHON");
    std::string so = val("BAZOOKA_PREDICATE_SO");
    std::string pp = val("PYTHONPATH");
    std::string bdd = val("BDD_PREDICATE_DIR");

    if (worker.empty() || !file_exists(worker))
        return r + "sieve route   : NOT set up (worker_cli.py not found)\n                fix: run worker/bootstrap.sh\n";
    if (!so.empty() && !file_exists(so))
        return r + "sieve route   : NOT set up (predicate shim not built)\n                fix: cmake --build --preset release --target bazooka_predicate\n";
    if (!bdd.empty() && !file_exists(bdd + "/usvp.py"))
        return r + "sieve route   : NOT set up (bdd-predicate missing)\n                fix: run worker/bootstrap.sh\n";
    if (!python_has_g6k(py, pp))
        return r + "sieve route   : NOT set up (g6k not importable)\n                fix: run worker/bootstrap.sh --build-g6k\n";
    r += "sieve route   : ready\n";
    return r;
}

} // namespace sieve_config
