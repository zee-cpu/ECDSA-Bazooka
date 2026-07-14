#include "telemetry.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <thread>
#include <cmath>
#include <vector>
#include <cstdint>

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#include <sys/ioctl.h>
#endif

namespace {

// ANSI SGR codes. Only ever emitted when the renderer has confirmed stdout
// is an interactive TTY (see TelemetryRenderer::TelemetryRenderer), so
// piping output to a file or another process never gets escape-code noise.
constexpr const char* RESET   = "\033[0m";
constexpr const char* BOLD    = "\033[1m";
constexpr const char* DIM     = "\033[2m";
constexpr const char* CYAN    = "\033[36m";
constexpr const char* GREEN   = "\033[32m";
constexpr const char* YELLOW  = "\033[33m";
constexpr const char* RED     = "\033[31m";
constexpr const char* BLUE    = "\033[34m";
constexpr const char* MAGENTA = "\033[35m";

// Decode one UTF-8 codepoint starting at s[i], advance i past it, and
// return its display width (0 for combining marks, 1 for most codepoints,
// 2 for wide CJK/emoji ranges). This is the actual fix for the box-drawing
// misalignment bug class: std::string::size() counts *bytes*, not terminal
// columns, so any multi-byte UTF-8 character (even a plain checkmark, 3
// bytes) silently throws off a padding calculation that used .size() or
// .length() to align a fixed-width box border. Padding here is always
// computed from this function's return value instead.
int utf8_codepoint_width(const std::string& s, size_t& i) {
    unsigned char c = s[i];
    uint32_t cp = 0;
    int len = 1;

    if ((c & 0x80) == 0x00) { cp = c; len = 1; }
    else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
    else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
    else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
    else { i += 1; return 1; } // invalid lead byte, treat as width 1

    if (i + len > s.size()) { i += 1; return 1; }
    for (int k = 1; k < len; ++k) {
        cp = (cp << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3F);
    }
    i += len;

    if (cp == 0) return 0;
    // Combining marks: zero width.
    if ((cp >= 0x0300 && cp <= 0x036F) || (cp >= 0x1AB0 && cp <= 0x1AFF)) return 0;
    // Wide ranges: CJK, Hangul, fullwidth forms, common emoji blocks.
    bool wide =
        (cp >= 0x1100 && cp <= 0x115F) ||
        (cp >= 0x2E80 && cp <= 0xA4CF) ||
        (cp >= 0xAC00 && cp <= 0xD7A3) ||
        (cp >= 0xF900 && cp <= 0xFAFF) ||
        (cp >= 0xFF00 && cp <= 0xFF60) ||
        (cp >= 0x1F300 && cp <= 0x1FAFF) ||
        (cp >= 0x20000 && cp <= 0x3FFFD);
    return wide ? 2 : 1;
}

int utf8_display_width(const std::string& s) {
    int width = 0;
    size_t i = 0;
    while (i < s.size()) width += utf8_codepoint_width(s, i);
    return width;
}

// Pad `s` (which may contain ANSI color codes) to exactly `width` visual
// columns, ignoring escape sequences and using real display width for
// everything else.
std::string pad_display(const std::string& s, int width) {
    int visual = 0;
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '\033') {
            size_t j = i;
            while (j < s.size() && s[j] != 'm') j++;
            i = (j < s.size()) ? j + 1 : s.size();
            continue;
        }
        visual += utf8_codepoint_width(s, i);
    }
    std::string out = s;
    if (visual < width) out += std::string(width - visual, ' ');
    return out;
}

std::string progress_bar(double frac, int width, const char* color) {
    frac = std::max(0.0, std::min(1.0, frac));
    int filled = static_cast<int>(std::round(frac * width));
    std::ostringstream oss;
    oss << color << std::string(filled, '#') << DIM << std::string(width - filled, '-') << RESET;
    return oss.str();
}

} // namespace

TelemetryRenderer::TelemetryRenderer(Telemetry& tel) : tel_(tel) {
#if defined(__unix__) || defined(__APPLE__)
    use_ansi_ = ::isatty(STDOUT_FILENO) != 0;
#else
    use_ansi_ = false;
#endif
    term_width_ = terminal_width();
}

TelemetryRenderer::~TelemetryRenderer() {
    stop();
}

int TelemetryRenderer::terminal_width() const {
#if defined(__unix__) || defined(__APPLE__)
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        return std::max(60, std::min(static_cast<int>(ws.ws_col), 110));
    }
#endif
    return 78;
}

void TelemetryRenderer::start() {
    if (running_) return;
    running_ = true;
    render_thread_ = std::thread(&TelemetryRenderer::render_loop, this);
}

void TelemetryRenderer::stop() {
    running_ = false;
    if (render_thread_.joinable()) {
        render_thread_.join();
    }
    render_once();
    std::cout << std::endl;
}

void TelemetryRenderer::render_loop() {
    while (running_) {
        render_once();
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
}

void TelemetryRenderer::render_once() {
    if (use_ansi_) {
        render_dashboard();
    } else {
        render_plain();
    }
}

std::string TelemetryRenderer::format_time(double seconds) const {
    int mins = static_cast<int>(seconds) / 60;
    int secs = static_cast<int>(seconds) % 60;
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << mins << ":" << std::setw(2) << secs;
    return oss.str();
}

void TelemetryRenderer::render_dashboard() {
    using namespace std::chrono;

    int W = term_width_;
    int inner = W - 2; // between the border verticals

    auto now = steady_clock::now();
    double elapsed = duration<double>(now - tel_.start_time).count();

    size_t loaded = tel_.signatures_loaded.load();
    size_t valid = tel_.signatures_valid.load();
    size_t skipped = tel_.signatures_skipped.load();

    double leaked = tel_.leaked_bits_est.load();
    double conf = tel_.confidence.load();
    int btype = tel_.bias_type.load();
    const char* bname = "UNKNOWN";
    const char* bcolor = DIM;
    if (btype == static_cast<int>(BiasType::MSB)) { bname = "MSB"; bcolor = GREEN; }
    else if (btype == static_cast<int>(BiasType::LSB)) { bname = "LSB"; bcolor = GREEN; }
    else if (btype == static_cast<int>(BiasType::MODULO)) { bname = "MODULO"; bcolor = GREEN; }
    else if (btype == static_cast<int>(BiasType::NONE)) { bname = "NONE"; bcolor = YELLOW; }

    bool method_chosen = tel_.method_chosen.load();
    int meth = tel_.active_method.load();
    const char* mname = "-";
    if (method_chosen) {
        mname = "AUTO";
        if (meth == static_cast<int>(RecoveryMethod::LATTICE)) mname = "LATTICE";
        else if (meth == static_cast<int>(RecoveryMethod::FFT)) mname = "FFT";
        else if (meth == static_cast<int>(RecoveryMethod::FALLBACK)) mname = "FALLBACK";
    }

    size_t attempt = tel_.current_attempt.load();
    size_t total = tel_.total_attempts.load();
    double attempt_frac = total > 0 ? static_cast<double>(attempt) / total : 0.0;

    bool lattice_active = tel_.lattice_in_progress.load();
    bool fft_active = tel_.fft_in_progress.load();

    std::string phase = tel_.get_phase();
    std::string status = tel_.get_status();

    bool complete = tel_.recovery_complete.load();
    bool verified = tel_.verification_passed.load();

    std::vector<std::string> lines;

    auto simple_top = [&]() {
        std::string title = "ECDSA Nonce-Bias Recovery";
        int fill = std::max(0, inner - 3 - utf8_display_width(title));
        return std::string(CYAN) + "+- " + BOLD + title + RESET + CYAN + " " + std::string(fill, '-') + "+" + RESET;
    };
    auto border_mid = [&]() {
        return std::string(CYAN) + "+" + std::string(inner, '-') + "+" + RESET;
    };
    auto border_bot = [&]() {
        return std::string(CYAN) + "+" + std::string(inner, '-') + "+" + RESET;
    };
    auto row = [&](const std::string& content) {
        std::string body = " " + content;
        return std::string(CYAN) + "|" + RESET + pad_display(body, inner) + std::string(CYAN) + "|" + RESET;
    };

    lines.push_back(simple_top());

    {
        std::ostringstream oss;
        oss << BOLD << "Elapsed " << RESET << format_time(elapsed)
            << "    " << BOLD << "Signatures " << RESET
            << GREEN << valid << RESET << "/" << loaded
            << (skipped ? (std::string(RED) + " (" + std::to_string(skipped) + " skipped)" + RESET) : "");
        lines.push_back(row(oss.str()));
    }

    lines.push_back(border_mid());

    {
        std::ostringstream oss;
        oss << BOLD << "Bias Profile" << RESET;
        lines.push_back(row(oss.str()));
    }
    {
        std::ostringstream oss;
        oss << "  Type " << bcolor << BOLD << bname << RESET;
        if (leaked > 0) {
            oss << "    ~" << std::fixed << std::setprecision(1) << leaked << " bits";
        }
        if (conf > 0) {
            oss << "    " << DIM << "p < 10^-" << std::setprecision(1) << conf << RESET;
        }
        lines.push_back(row(oss.str()));
    }

    lines.push_back(border_mid());

    {
        std::ostringstream oss;
        oss << BOLD << "Recovery" << RESET << "    method " << (method_chosen ? MAGENTA : DIM) << mname << RESET;
        lines.push_back(row(oss.str()));
    }
    {
        std::ostringstream oss;
        if (total > 0) {
            oss << "  [" << progress_bar(attempt_frac, std::max(10, inner - 30), BLUE) << "] "
                << attempt << "/" << total << " attempts";
        } else {
            oss << "  [" << progress_bar(0.0, std::max(10, inner - 30), BLUE) << "]";
        }
        lines.push_back(row(oss.str()));
    }
    {
        std::ostringstream oss;
        if (lattice_active) {
            oss << "  " << DIM << "dim=" << tel_.lattice_dim.load()
                << " sigs=" << tel_.signatures_used.load() << RESET;
        } else if (fft_active) {
            oss << "  " << DIM << "FFT peak=" << std::fixed << std::setprecision(0)
                << tel_.fft_peak_magnitude.load() << " sweep=" << tel_.fft_sweep_progress.load() << "%" << RESET;
        } else {
            oss << "  " << DIM << "-" << RESET;
        }
        lines.push_back(row(oss.str()));
    }

    lines.push_back(border_mid());

    {
        std::ostringstream oss;
        oss << BOLD << "Status  " << RESET;
        if (!phase.empty()) oss << YELLOW << phase << RESET;
        if (!status.empty()) oss << "  " << DIM << status << RESET;
        if (phase.empty() && status.empty()) oss << DIM << "-" << RESET;
        lines.push_back(row(oss.str()));
    }

    if (complete) {
        std::ostringstream oss;
        if (verified) {
            std::string key = tel_.get_recovered_key();
            oss << BOLD << GREEN << "SUCCESS " << RESET << DIM
                << key.substr(0, std::min<size_t>(20, key.size())) << "..." << RESET;
        } else {
            oss << BOLD << RED << "FAILED" << RESET;
        }
        lines.push_back(row(oss.str()));
    }

    lines.push_back(border_bot());

    // Redraw in place: move the cursor back up over the previous frame
    // (each line individually cleared first, so a shorter new frame never
    // leaves stale characters behind), then print the new frame.
    if (!first_frame_ && last_frame_lines_ > 0) {
        std::cout << "\033[" << last_frame_lines_ << "A";
    }
    for (auto& l : lines) {
        std::cout << "\r\033[K" << l << "\n";
    }
    std::cout << std::flush;

    last_frame_lines_ = static_cast<int>(lines.size());
    first_frame_ = false;
}

void TelemetryRenderer::render_plain() {
    // Non-interactive output (piped/redirected): a single evolving line
    // with no ANSI cursor movement, so logs stay clean and append-only
    // per refresh rather than accumulating escape-code noise.
    using namespace std::chrono;

    auto now = steady_clock::now();
    double elapsed = duration<double>(now - tel_.start_time).count();

    size_t loaded = tel_.signatures_loaded.load();
    size_t valid = tel_.signatures_valid.load();

    double leaked = tel_.leaked_bits_est.load();
    int btype = tel_.bias_type.load();
    const char* bname = "UNKNOWN";
    if (btype == static_cast<int>(BiasType::MSB)) bname = "MSB";
    else if (btype == static_cast<int>(BiasType::LSB)) bname = "LSB";
    else if (btype == static_cast<int>(BiasType::MODULO)) bname = "MODULO";
    else if (btype == static_cast<int>(BiasType::NONE)) bname = "NONE";

    std::string phase = tel_.get_phase();

    std::cout << "[" << format_time(elapsed) << "] valid=" << valid << "/" << loaded
              << " bias=" << bname << " ~" << std::fixed << std::setprecision(1) << leaked << "bits";
    if (!phase.empty()) std::cout << " phase=\"" << phase << "\"";
    std::cout << std::endl;
}
