#ifndef _Core_h
#define _Core_h

#include <string>

class SPEAR{
	private:
		void about();
		void folder();
		void file();
		bool file_check(std::string filename);
	public:
		SPEAR(void);
		std::string AES_256(std::string clr_msg, std::string password, std::string choice);
		void run();
		~SPEAR(void);
};

#endif
