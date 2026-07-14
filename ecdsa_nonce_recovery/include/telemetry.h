#pragma once

#include "types.h"
#include <thread>
#include <atomic>
#include <functional>
#include <string>

class TelemetryRenderer {
public:
    explicit TelemetryRenderer(Telemetry& tel);
    ~TelemetryRenderer();

    void start();
    void stop();

    // Call periodically from main thread if not using background renderer
    void render_once();

private:
    Telemetry& tel_;
    std::thread render_thread_;
    std::atomic<bool> running_{false};
    bool use_ansi_ = false;   // true only for an interactive TTY
    int term_width_ = 78;
    int last_frame_lines_ = 0;
    bool first_frame_ = true;

    void render_loop();
    void render_dashboard();
    void render_plain();
    std::string format_time(double seconds) const;
    int terminal_width() const;
};
