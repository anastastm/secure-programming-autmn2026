#pragma once

#include "input_validation.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string_view>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

constexpr int CLIPBOARD_CLEAR_SECONDS = 30;

#ifdef _WIN32
inline bool setClipboardDword(UINT format, DWORD value)
{
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, sizeof value);
    if (!memory) return false;
    void* data = GlobalLock(memory);
    if (!data)
    {
        GlobalFree(memory);
        return false;
    }
    CopyMemory(data, &value, sizeof value);
    GlobalUnlock(memory);
    if (!SetClipboardData(format, memory))
    {
        GlobalFree(memory);
        return false;
    }
    return true;
}

class ClipboardWriter
{
public:
    bool write(std::string_view text)
    {
        if (!OpenClipboard(nullptr)) return false;
        bool ok = EmptyClipboard() != 0;
        if (ok)
        {
            const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
            HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
            wchar_t* data = memory ? static_cast<wchar_t*>(GlobalLock(memory)) : nullptr;
            ok = data != nullptr;
            if (ok)
            {
                for (std::size_t i = 0; i < text.size(); ++i)
                {
                    data[i] = static_cast<wchar_t>(static_cast<unsigned char>(text[i]));
                }
                data[text.size()] = L'\0';
                GlobalUnlock(memory);
                if (!SetClipboardData(CF_UNICODETEXT, memory))
                {
                    data = static_cast<wchar_t*>(GlobalLock(memory));
                    if (data) SecureZeroMemory(data, bytes);
                    GlobalUnlock(memory);
                    GlobalFree(memory);
                    ok = false;
                }
            }
            else if (memory)
            {
                GlobalFree(memory);
            }
            if (ok)
            {
                setClipboardDword(RegisterClipboardFormatW(L"ExcludeClipboardContentFromMonitorProcessing"), 0);
                setClipboardDword(RegisterClipboardFormatW(L"CanIncludeInClipboardHistory"), 0);
                setClipboardDword(RegisterClipboardFormatW(L"CanUploadToCloudClipboard"), 0);
            }
        }
        if (ok) sequence_ = GetClipboardSequenceNumber();
        CloseClipboard();
        return ok;
    }

    void clear()
    {
        if (sequence_ == 0 || GetClipboardSequenceNumber() != sequence_) return;
        if (OpenClipboard(nullptr))
        {
            EmptyClipboard();
            CloseClipboard();
        }
        sequence_ = 0;
    }

    bool available() const { return true; }

private:
    DWORD sequence_ = 0;
};
#else
struct ClipboardTool
{
    const char* path;
    const char* environment;
    const char* const* copyArguments;
    const char* const* clearArguments;
};

inline const ClipboardTool* findClipboardTool()
{
    static const char* const clipCopy[] = {"clip.exe", nullptr};
    static const char* const waylandCopy[] = {"wl-copy", nullptr};
    static const char* const waylandClear[] = {"wl-copy", "--clear", nullptr};
    static const char* const xclipCopy[] = {"xclip", "-selection", "clipboard", nullptr};
    static const char* const xselCopy[] = {"xsel", "--clipboard", "--input", nullptr};
    static const char* const xselClear[] = {"xsel", "--clipboard", "--clear", nullptr};
    static const ClipboardTool tools[] = {
        {"/mnt/c/Windows/System32/clip.exe", nullptr, clipCopy, nullptr},
        {"/usr/bin/wl-copy", "WAYLAND_DISPLAY", waylandCopy, waylandClear},
        {"/usr/bin/xclip", "DISPLAY", xclipCopy, nullptr},
        {"/usr/bin/xsel", "DISPLAY", xselCopy, xselClear},
    };
    for (const ClipboardTool& tool : tools)
    {
        struct stat info{};
        if (tool.environment && !getenv(tool.environment)) continue;
        if (stat(tool.path, &info) == 0 && S_ISREG(info.st_mode) && access(tool.path, X_OK) == 0)
        {
            return &tool;
        }
    }
    return nullptr;
}

inline bool runClipboardTool(const ClipboardTool& tool, const char* const* arguments, std::string_view text)
{
    int input[2];
    if (pipe(input) != 0) return false;
    fcntl(input[1], F_SETFD, FD_CLOEXEC);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, input[0], STDIN_FILENO);
    posix_spawn_file_actions_addclose(&actions, input[0]);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t child = 0;
    const int spawned = posix_spawn(&child, tool.path, &actions, nullptr,
        const_cast<char* const*>(arguments), environ);
    posix_spawn_file_actions_destroy(&actions);
    close(input[0]);
    if (spawned != 0)
    {
        close(input[1]);
        return false;
    }

    bool written = true;
    std::size_t offset = 0;
    while (offset < text.size())
    {
        const ssize_t count = write(input[1], text.data() + offset, text.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0)
        {
            written = false;
            break;
        }
        offset += static_cast<std::size_t>(count);
    }
    close(input[1]);

    int status = 0;
    for (int waited = 0; waited < 100; ++waited)
    {
        const pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child) return written && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (done < 0 && errno != EINTR) return false;
        poll(nullptr, 0, 50);
    }
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    return false;
}

class ClipboardWriter
{
public:
    bool write(std::string_view text)
    {
        const ClipboardTool* tool = findClipboardTool();
        if (!tool) return false;
        const bool ok = runClipboardTool(*tool, tool->copyArguments, text);
        if (ok) tool_ = tool;
        return ok;
    }

    void clear()
    {
        if (!tool_) return;
        if (tool_->clearArguments)
        {
            runClipboardTool(*tool_, tool_->clearArguments, {});
        }
        else
        {
            runClipboardTool(*tool_, tool_->copyArguments, {});
        }
        tool_ = nullptr;
    }

    bool available() const { return findClipboardTool() != nullptr; }

private:
    const ClipboardTool* tool_ = nullptr;
};
#endif

class ClipboardGuard
{
public:
    ClipboardGuard() = default;
    ClipboardGuard(const ClipboardGuard&) = delete;
    ClipboardGuard& operator=(const ClipboardGuard&) = delete;

    ~ClipboardGuard()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
            if (pending_)
            {
                writer_.clear();
                pending_ = false;
            }
        }
        wake_.notify_all();
        if (worker_.joinable()) worker_.join();
    }

    bool copy(std::string_view secret)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!writer_.write(secret)) return false;
        pending_ = true;
        deadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(CLIPBOARD_CLEAR_SECONDS);
        if (!worker_.joinable()) worker_ = std::thread([this] { run(); });
        wake_.notify_all();
        return true;
    }

    void clearNow()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pending_)
        {
            writer_.clear();
            pending_ = false;
        }
    }

private:
    void run()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        while (!stopping_)
        {
            if (!pending_)
            {
                wake_.wait(lock);
                continue;
            }
            wake_.wait_until(lock, deadline_);
            if (!stopping_ && pending_ && std::chrono::steady_clock::now() >= deadline_)
            {
                writer_.clear();
                pending_ = false;
            }
        }
    }

    std::mutex mutex_;
    std::condition_variable wake_;
    std::thread worker_;
    ClipboardWriter writer_;
    std::chrono::steady_clock::time_point deadline_{};
    bool pending_ = false;
    bool stopping_ = false;
};
