#ifndef _Core_h
#define _Core_h

#include <string>

class IMPALA{
	private:
		bool file_check(std::string filename);
		bool checkDigit(std::string str);
		bool checkUpper(std::string str);
		bool checkLower(std::string str);
		bool checkSpecChar(std::string str);
		bool checkPassword(std::string str);
		void about();
		
	public:
		IMPALA(void);
		std::string aes(std::string clr_msg, std::string password, std::string choice);
		void run();
		~IMPALA(void);
};

#endif
