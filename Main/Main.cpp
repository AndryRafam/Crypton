#include <iostream>

#include "../Core/IMPALA.h"

int main(int argc, char** argv){

	// Checking the OS first

	#ifdef __linux__
		system("clear");
		IMPALA ip;
		ip.run();
		return 0;
	#else
		std::cout << "\n";
		std::cout << "OS IS NOT LINUX." << "\n\n";
		return 0;
	#endif
}