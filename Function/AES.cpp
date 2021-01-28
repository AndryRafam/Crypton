#include <string>

#include "../Core/IMPALA.h"
#include "../Core/AES.h"

AES_256::AES_256(void){ }

std::string AES_256::aes(std::string msg, std::string password, std::string choice){
	IMPALA ip;
	std::string result = ip.aes(msg,password,choice);
	return result;
}

AES_256::~AES_256(void) { }
