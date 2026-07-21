#include "fork_pool.h"
#include <chrono>
#include <string>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fork_pool {
namespace {

double elapsed_since(std::chrono::steady_clock::time_point t) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t).count();
}

struct Child { pid_t pid; int fd; std::string buf; };

}  // namespace

std::optional<mpz> run_until_first(const std::vector<Work>& works,
                                   size_t max_concurrent, double deadline_sec) {
    if (works.empty()) return std::nullopt;
    if (max_concurrent < 1) max_concurrent = 1;
    std::vector<Child> live;
    size_t next = 0;
    auto start = std::chrono::steady_clock::now();

    auto spawn = [&](size_t idx) {
        int pp[2];
        if (pipe(pp) != 0) return;
        pid_t pid = fork();
        if (pid < 0) { close(pp[0]); close(pp[1]); return; }
        if (pid == 0) {                       // child: run the work-unit, pipe key hex
            close(pp[0]);
            std::optional<mpz> r = works[idx]();
            std::string s = r.has_value() ? r->get_str(16) : "";
            ssize_t w = write(pp[1], s.data(), s.size()); (void)w;
            close(pp[1]);
            _exit(0);
        }
        close(pp[1]);
        int fl = fcntl(pp[0], F_GETFL, 0);
        fcntl(pp[0], F_SETFL, fl | O_NONBLOCK);
        live.push_back({pid, pp[0], std::string()});
    };

    auto reap_all = [&]() {
        for (auto& c : live) { kill(c.pid, SIGKILL); waitpid(c.pid, nullptr, 0); close(c.fd); }
        live.clear();
    };

    while (live.size() < max_concurrent && next < works.size()) spawn(next++);

    while (!live.empty()) {
        if (deadline_sec > 0.0 && elapsed_since(start) >= deadline_sec) { reap_all(); return std::nullopt; }
        bool progressed = false;
        for (size_t i = 0; i < live.size();) {
            char b[256];
            ssize_t n = read(live[i].fd, b, sizeof b);
            if (n > 0) { live[i].buf.append(b, (size_t)n); progressed = true; }
            int st = 0;
            if (waitpid(live[i].pid, &st, WNOHANG) == live[i].pid) {
                while ((n = read(live[i].fd, b, sizeof b)) > 0) live[i].buf.append(b, (size_t)n);
                close(live[i].fd);
                std::string res = live[i].buf;
                live.erase(live.begin() + i);          // this child already reaped
                if (!res.empty()) {                    // winner
                    mpz d; d.set_str(res, 16);
                    reap_all();
                    return d;
                }
                if (next < works.size()) spawn(next++); // fill the freed slot
                progressed = true;
            } else {
                ++i;
            }
        }
        if (!progressed) { struct timespec ts{0, 10 * 1000 * 1000}; nanosleep(&ts, nullptr); }
    }
    return std::nullopt;
}

std::optional<mpz> fork_reduce(const Work& work, double timeout_sec) {
    return run_until_first(std::vector<Work>{work}, 1, timeout_sec);
}

}  // namespace fork_pool
