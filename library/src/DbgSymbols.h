#pragma once

#include <vector>


namespace hookftw
{
	/**
	 *  \brief Loads debug symbols of the target binary and provides functionality to make use of them
	 *
	 *  
	 */
	class DbgSymbols
	{
		static bool symbolsLoaded_;
		
		bool LoadSymbols();
	public:
		DbgSymbols();
		int8_t* GetAddressBySymbolName(const char* name);
		void EnumerateSymbols();
	};
}
