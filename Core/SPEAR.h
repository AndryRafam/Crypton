#ifndef _Core_h
#define _Core_h

#include <string>

class SPEAR{
	private:
		void about();
		void folder();
	public:
		SPEAR(void);
		std::string AES_256(std::string clr_msg);
		std::string SERPENT_256(std::string clr_msg);
		std::string TWOFISH_256(std::string clr_msg);
		void run();
		~SPEAR(void);
};

#endif
