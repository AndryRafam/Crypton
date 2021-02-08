#ifndef _CRYPTON_h
#define _CRYPTON_h

#include <string>

class CRYPTON{
	private:
		inline bool fileCheck(const std::string &filename);
		inline bool checkDigit(std::string str);
		inline bool checkUpper(std::string str);
		inline bool checkLower(std::string str);
		inline bool checkSpecChar(std::string str);
		inline bool checkPassword(std::string str);
		std::string scramble(std::string passphrase);
		std::string aserp(std::string clr_msg, std::string password, std::string choice);
		inline void about();
		
	public:
		CRYPTON(void);
		void run();
		~CRYPTON(void);
};

#endif
