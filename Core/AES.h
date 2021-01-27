#ifndef _AES_h
#define _AES_h

#include <string>

class AES_256 : virtual private IMPALA{
	public:
		AES_256(void);
		std::string aes(std::string msg, std::string password, std::string choice);
		~AES_256(void);
};

#endif
