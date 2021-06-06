#pragma once

#include <string>
#include <fstream>


namespace hookftw
{
	/**
	 * \brief Handles logging
	 * 
	 * Provides utilities to write log data. It is possible to write to a console window and also write to a file.
	 */
	class Logger
	{
		static bool enableFileLogging_;
		static FILE* logfile_;
	public:
		static void Log(const char* format, ...);
		static void OpenDebuggingConsole(std::string title, bool enableFileLogging = true);
		static void CloseDebuggingConsole();
	};
}