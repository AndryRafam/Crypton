#ifndef _Core_h
#define _Core_h

#include <string>

class IMPALA{
	private:
		inline bool fileCheck(const std::string &filename);
		inline bool checkDigit(std::string str);
		inline bool checkUpper(std::string str);
		inline bool checkLower(std::string str);
		inline bool checkSpecChar(std::string str);
		inline bool checkPassword(std::string str);
		inline void about();
		
	public:
		IMPALA(void);
		std::string aes(std::string clr_msg, std::string password, std::string choice);
		void run();
		~IMPALA(void);
};

#endif
