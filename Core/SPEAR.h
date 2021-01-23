#ifndef _Core_h
#define _Core_h

#include <string>

class SPEAR{
	private:
		bool file_check(std::string filename);
		bool checkDigit(std::string str);
		bool checkUpper(std::string str);
		bool checkLower(std::string str);
		bool checkSpecChar(std::string str);
		bool checkPassword(std::string str);
		
	public:
		SPEAR(void);
		std::string AES_256(std::string clr_msg, std::string password, std::string choice);
		void about();
		void run(std::string choice);
		~SPEAR(void);
};

#endif
