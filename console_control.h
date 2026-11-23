#pragma once

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

inline volatile LONG stopRequested = 0;
inline bool interrupted() { return InterlockedCompareExchange(&stopRequested, 0, 0) != 0; }

inline BOOL WINAPI handleConsoleInterrupt(DWORD reason)
{
    if (reason != CTRL_C_EVENT && reason != CTRL_BREAK_EVENT) return FALSE;
    InterlockedExchange(&stopRequested, 1);
    // Wake a pending console read so the main thread can clean up.
    INPUT_RECORD enter{};
    enter.EventType = KEY_EVENT;
    enter.Event.KeyEvent.bKeyDown = TRUE;
    enter.Event.KeyEvent.wRepeatCount = 1;
    enter.Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
    enter.Event.KeyEvent.uChar.UnicodeChar = L'\r';
    DWORD written;
    WriteConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), &enter, 1, &written);
    return TRUE;
}

class ConsoleControl
{
public:
    bool start() { return SetConsoleCtrlHandler(handleConsoleInterrupt, TRUE) != 0; }
    ~ConsoleControl() { SetConsoleCtrlHandler(handleConsoleInterrupt, FALSE); }
};
#else
#include <csignal>
#include <cerrno>
#include <termios.h>
#include <unistd.h>

inline volatile std::sig_atomic_t stopRequested = 0;
inline bool interrupted() { return stopRequested != 0; }

inline void handleConsoleInterrupt(int)
{
    const int savedError = errno;
    if (!stopRequested)
    {
        stopRequested = 1;
        close(STDIN_FILENO);
    }
    errno = savedError;
}

class ConsoleControl
{
public:
    bool start()
    {
        if (isatty(STDIN_FILENO))
        {
            terminal = dup(STDIN_FILENO);
            if (terminal < 0 || tcgetattr(terminal, &original) != 0) return false;
            restoreTerminal = true;
        }
        struct sigaction action{};
        action.sa_handler = handleConsoleInterrupt;
        sigemptyset(&action.sa_mask);
        return sigaction(SIGINT, &action, nullptr) == 0;
    }

    ~ConsoleControl()
    {
        if (restoreTerminal) tcsetattr(terminal, interrupted() ? TCSAFLUSH : TCSANOW, &original);
        if (terminal >= 0) close(terminal);
    }

private:
    int terminal = -1;
    termios original{};
    bool restoreTerminal = false;
};
#endif
