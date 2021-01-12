#ifndef _AES_h
#define _AES_h

#include <string>

class AES : virtual private SPEAR{
	public:
		AES(void);
		std::string aes(std::string msg, std::string password, std::string choice);
		~AES(void);
};

#endif
