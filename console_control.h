#pragma once

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

inline volatile LONG stopRequested = 0;
inline volatile LONG cleanupFinished = 0;
inline bool interrupted() { return InterlockedCompareExchange(&stopRequested, 0, 0) != 0; }

inline BOOL WINAPI handleConsoleInterrupt(DWORD reason)
{
    const bool closing = reason == CTRL_CLOSE_EVENT || reason == CTRL_LOGOFF_EVENT ||
        reason == CTRL_SHUTDOWN_EVENT;
    if (reason != CTRL_C_EVENT && reason != CTRL_BREAK_EVENT && !closing) return FALSE;
    InterlockedExchange(&stopRequested, 1);
    INPUT_RECORD enter{};
    enter.EventType = KEY_EVENT;
    enter.Event.KeyEvent.bKeyDown = TRUE;
    enter.Event.KeyEvent.wRepeatCount = 1;
    enter.Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
    enter.Event.KeyEvent.uChar.UnicodeChar = L'\r';
    DWORD written;
    WriteConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), &enter, 1, &written);
    if (closing)
        for (int waited = 0; waited < 4500 &&
            InterlockedCompareExchange(&cleanupFinished, 0, 0) == 0; waited += 50)
        {
            Sleep(50);
        }
    }
    return TRUE;
}

class ConsoleControl
{
public:
    bool start() { return SetConsoleCtrlHandler(handleConsoleInterrupt, TRUE) != 0; }
    ~ConsoleControl()
    {
        InterlockedExchange(&cleanupFinished, 1);
        SetConsoleCtrlHandler(handleConsoleInterrupt, FALSE);
    }
};
#else
#include <csignal>
#include <cerrno>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

inline volatile std::sig_atomic_t stopRequested = 0;
inline int emptyInput = -1;
inline bool interrupted() { return stopRequested != 0; }

inline void handleConsoleInterrupt(int)
{
    const int savedError = errno;
    if (!stopRequested)
    {
        stopRequested = 1;
        dup2(emptyInput, STDIN_FILENO);
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
            termios session = original;
            session.c_lflag |= NOFLSH;
            if (tcsetattr(terminal, TCSANOW, &session) != 0) return false;
        }
        emptyInput = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (emptyInput < 0) return false;
        struct sigaction action{};
        action.sa_handler = handleConsoleInterrupt;
        action.sa_flags = SA_RESTART;
        sigemptyset(&action.sa_mask);
        for (int signalNumber : {SIGINT, SIGQUIT, SIGTERM, SIGHUP})
        {
            sigaddset(&action.sa_mask, signalNumber);
        }
        for (int signalNumber : {SIGINT, SIGQUIT, SIGTERM, SIGHUP})
        {
            if (sigaction(signalNumber, &action, nullptr) != 0) return false;
        }
        struct sigaction ignore{};
        ignore.sa_handler = SIG_IGN;
        sigemptyset(&ignore.sa_mask);
        return sigaction(SIGTSTP, &ignore, nullptr) == 0;
    }

    ~ConsoleControl()
    {
        if (restoreTerminal) tcsetattr(terminal, interrupted() ? TCSAFLUSH : TCSANOW, &original);
        if (terminal >= 0) close(terminal);
        if (emptyInput >= 0) close(emptyInput);
    }

private:
    int terminal = -1;
    termios original{};
    bool restoreTerminal = false;
};
#endif
