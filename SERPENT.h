#ifndef _SERPENT_h
#define _SERPENT_h

#include <string>

class SERPENT : virtual private SPEAR{
	public:
		SERPENT(void);
		std::string serpent(std::string msg, std::string password, std::string choice);
		~SERPENT(void);
};

#endif
