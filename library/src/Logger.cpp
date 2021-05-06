#include "Logger.h"

#include <Windows.h>

namespace hookftw
{
	bool Logger::enableFileLogging_ = true;
	FILE* Logger::logfile_;


	/**
	 * Writes a messages to the log.
	 *
	 * @param format The format used for logging (printf syntax).
	 * @param ... Data to be logged
	 */
	void Logger::Log(const char* format, ...)
	{
		va_list arguments;
		va_start(arguments, format);
		if (Logger::enableFileLogging_)
		{
 			fopen_s(&logfile_, "C:/logs/hookftw.log", "a");
			fprintf(logfile_, format, arguments);
			fclose(logfile_);
		}
		printf(format, arguments);
		va_end(arguments);
	}

	/**
	 * Creates a console window to use for debug messages.
	 *
	 * @param title Title of the console window
	 * @param enableFileLogging decide if log should be written to file, <code>true</code> by default.
	 */
	void Logger::OpenDebuggingConsole(std::string title, bool enableFileLogging)
	{
		Logger::enableFileLogging_ = enableFileLogging;
		if (enableFileLogging)
		{
			//clear file
			fopen_s(&logfile_, "C:/logs/hookftw.log", "w");
			fclose(logfile_);
		}
		AllocConsole();
		freopen_s(reinterpret_cast<FILE**>stdin, "CONIN$", "r", stdin);
		freopen_s(reinterpret_cast<FILE**>stdout, "CONOUT$", "w", stdout);
		SetConsoleTitleA(title.c_str());
		Log("Created debugging console\n");
	}

	/**
	 * Closes the console window used for debugging
	 * 
	 */
	void Logger::CloseDebuggingConsole()
	{
		Log("Closing debugging console\n");
		fclose(logfile_);
		fclose(reinterpret_cast<FILE*>stdin);
		fclose(reinterpret_cast<FILE*>stdout);

		HWND hw_ConsoleHwnd = GetConsoleWindow();
		FreeConsole();
		PostMessageW(hw_ConsoleHwnd, WM_CLOSE, 0, 0);
	}
}