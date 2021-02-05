#include <iostream>

#include "../Core/CRYPTON.h"

int main(int argc, char** argv){
	#ifdef __linux__
		system("clear");
		CRYPTON crypt;
		crypt.run();
		return 0;
	#else
		std::cout << "\n\n";
		return 0;
	#endif
}
