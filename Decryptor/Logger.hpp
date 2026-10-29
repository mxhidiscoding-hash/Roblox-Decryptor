#pragma once

#include <iostream>
#include <string>
#include <cstdarg>
#include <cstdio>
#include <windows.h>

namespace Logger
{
    static bool Muted = false;
    static bool Trace = false;
    static bool Verbose = false;
    static bool Debug = false;

    static void Flush()
    {
        fflush(stdout);
        fflush(stderr);
    }

    static void Colors()
    {
        HANDLE Console = GetStdHandle(STD_OUTPUT_HANDLE);
        if (Console == INVALID_HANDLE_VALUE)
            return;

        DWORD Mode = 0;
        if (!GetConsoleMode(Console, &Mode))
            return;

        Mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(Console, Mode);
    }

    static void Time()
    {
        time_t Now = time(nullptr);
        tm* Local = localtime(&Now);
        printf("\033[90m%02d:%02d:%02d\033[0m ", Local->tm_hour, Local->tm_min, Local->tm_sec);
    }

    static void Log(const char* Format, ...)
    {
        if (Muted)
            return;

        Time();
        printf("\033[36m[INFO]\033[0m ");

        va_list Args;
        va_start(Args, Format);
        vprintf(Format, Args);
        va_end(Args);

        printf("\n");
    }

    static void Progress(const char* Format, ...)
    {
        if (Muted)
            return;

        Time();
        printf("\033[36m[INFO]\033[0m ");

        va_list Args;
        va_start(Args, Format);
        vprintf(Format, Args);
        va_end(Args);

        printf("\n");
        Flush();
    }

    static void Error(const char* Format, ...)
    {
        if (Muted)
            return;

        Time();
        printf("\033[91m[ERROR]\033[0m ");

        va_list Args;
        va_start(Args, Format);
        vprintf(Format, Args);
        va_end(Args);

        printf("\n");
        Flush();
    }

    static void Success(const char* Format, ...)
    {
        if (Muted)
            return;

        Time();
        printf("\033[92m[SUCCESS]\033[0m ");

        va_list Args;
        va_start(Args, Format);
        vprintf(Format, Args);
        va_end(Args);

        printf("\n");
        Flush();
    }

    static void LogDebug(const char* Format, ...)
    {
        if (Muted || !Debug)
            return;

        Time();
        printf("\033[35m[DEBUG]\033[0m ");

        va_list Args;
        va_start(Args, Format);
        vprintf(Format, Args);
        va_end(Args);

        printf("\n");
    }

    static void LogTrace(const char* Format, ...)
    {
        if (Muted || !Trace)
            return;

        Time();
        printf("\033[33m[TRACE]\033[0m ");

        va_list Args;
        va_start(Args, Format);
        vprintf(Format, Args);
        va_end(Args);

        printf("\n");
    }

    static void LogVerbose(const char* Format, ...)
    {
        if (Muted || !Verbose)
            return;

        Time();
        printf("\033[33m[TRACE]\033[0m ");

        va_list Args;
        va_start(Args, Format);
        vprintf(Format, Args);
        va_end(Args);

        printf("\n");
    }
}
