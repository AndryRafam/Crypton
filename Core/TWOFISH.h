#ifndef _TWOFISH_h
#define _TWOFISH_h

#include <string>

class TWOFISH : virtual private SPEAR{
	public:
		TWOFISH(void);
		std::string twofish(std::string msg, std::string password, std::string choice);
		~TWOFISH(void);
};

#endif
