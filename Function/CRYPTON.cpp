#include <iostream>
#include <string>
#include <exception>
#include <fstream>
#include <iomanip>
#include <limits>
#include <unistd.h>
#include <cctype>
#include <algorithm>
#include <sys/types.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/eax.h>
#include <cryptopp/sha.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/aes.h>
#include <cryptopp/serpent.h>

#include "../Core/CRYPTON.h"
#include "../Core/Colors.h"

using namespace CryptoPP;

CRYPTON::CRYPTON(void){ }

inline bool CRYPTON::checkDigit(std::string str){
	return (std::any_of(str.begin(),str.end(), ::isdigit) ? true:false);
}

inline bool CRYPTON::checkLower(std::string str){
	return (std::any_of(str.begin(),str.end(), ::islower) ? true:false);
}

inline bool CRYPTON::checkUpper(std::string str){
	return (std::any_of(str.begin(),str.end(), ::isupper) ? true:false);
}

inline bool CRYPTON::checkSpecChar(std::string str){
	bool flag = false;
	for(auto i = 0; str[i]; i++){
		if((str[i]>=32 and str[i]<=47)||(str[i]>=58 and str[i]<=64)||(str[i]>=91 and str[i]<=96)||(str[i]>=123 and str[i]<=126)){
			flag = true;
			break;
		}
	}
	return flag;
}

inline bool CRYPTON::checkPassword(std::string str){
	return((checkDigit(str) && checkLower(str) && checkUpper(str) && checkSpecChar(str) && str.length()>=12) ? true:false);
}

inline bool CRYPTON::fileCheck(const std::string &filename){
	for(auto i = 0; filename[i]; i++){
		if(filename[i]=='.')
			return true;
	}
	return false;
}

std::string CRYPTON::aserpCrypt(std::string text, std::string password){
	std::string inter, ciphertext;
	std::string iv(password+password);

	try{
		SecByteBlock key1(AES::MAX_KEYLENGTH+AES::BLOCKSIZE);
		SecByteBlock key2(Serpent::MAX_KEYLENGTH+Serpent::BLOCKSIZE);
		HKDF<SHA256> hkdf;
		hkdf.DeriveKey(key1, key1.size(), (const byte*)password.data(), password.size(), (const byte*)iv.data(), iv.size(), NULL, 0);
		hkdf.DeriveKey(key2, key2.size(), (const byte*)password.data(), password.size(), (const byte*)iv.data(), iv.size(), NULL, 0);
		EAX<AES>::Encryption enc1;
		EAX<Serpent>::Encryption enc2;
		enc1.SetKeyWithIV(key1, AES::MAX_KEYLENGTH, key1+AES::MAX_KEYLENGTH);
		enc2.SetKeyWithIV(key2, Serpent::MAX_KEYLENGTH, key2+Serpent::MAX_KEYLENGTH);
		StringSource(text, true, new AuthenticatedEncryptionFilter(enc2, new StringSink(inter)));
		StringSource(inter, true, new AuthenticatedEncryptionFilter(enc1, new StringSink(ciphertext)));
	}
	catch(Exception& ex){
		std::cerr << "ERROR: " << ex.what() << "\n";
		return 0;
	}
	return ciphertext;
}

std::string CRYPTON::aserpDcrypt(std::string text, std::string password){
	std::string inter, recovered;
	std::string iv(password+password);

	SecByteBlock key1(AES::MAX_KEYLENGTH+AES::BLOCKSIZE);
	SecByteBlock key2(Serpent::MAX_KEYLENGTH+Serpent::BLOCKSIZE);
	HKDF<SHA256> hkdf;
	hkdf.DeriveKey(key1, key1.size(), (const byte*)password.data(), password.size(), (const byte*)iv.data(), iv.size(), NULL, 0);
	hkdf.DeriveKey(key2, key2.size(), (const byte*)password.data(), password.size(), (const byte*)iv.data(), iv.size(), NULL, 0);
	EAX<AES>::Decryption dec1;
	EAX<Serpent>::Decryption dec2;
	dec1.SetKeyWithIV(key1, AES::MAX_KEYLENGTH, key1+AES::MAX_KEYLENGTH);
	dec2.SetKeyWithIV(key2, Serpent::MAX_KEYLENGTH, key2+Serpent::MAX_KEYLENGTH);
	StringSource(text, true, new AuthenticatedDecryptionFilter(dec1, new StringSink(inter), AuthenticatedDecryptionFilter::THROW_EXCEPTION));
	StringSource(inter, true, new AuthenticatedDecryptionFilter(dec2, new StringSink(recovered), AuthenticatedDecryptionFilter::THROW_EXCEPTION));

	return recovered;
}

inline void CRYPTON::about(){
	std::ifstream infile;
	std::string line;
	infile.open("About.txt");

	while(std::getline(infile,line)){
		std::cout << line << std::endl;
	}
	infile.close();
	return;
}

void CRYPTON::run(){

	about();
	
	std::string filename;
	std::string clr_msg = "";
	std::string choice;
	std::string password;
	char car;

	std::cout << "\n";
	std::cout << std::setw(10) << "" << Red << "[ PRESS ENTER TO RUN ]" << Reset;
	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	system("clear");
	about();

	validChoice:
		std::cout << "\n";
		std::cout << std::setw(10) << "" << "(ENCRYPT OR DECRYPT ? (e or d)) > ";
		std::cin >> choice;
		std::cin.ignore();

	if(choice == "e"){

		label:
			std::cout << "\n";
			std::cout << std::setw(10) << "" << "(FILE TO ENCRYPT (Input: /Absolute/path/to/file.extension)) > ";
			std::getline(std::cin,filename);

		std::ifstream infile;

		if(!fileCheck(filename)){
			system("clear");
			about();
			std::cout << "\n";
			std::cout << Red << std::setw(10) << "" << " FILE DOESN'T EXIST. PLEASE TRY AGAIN." << Reset;
			goto label; 
		}
		infile.open(filename);
		std::cout << "\n";
		condition:
			std::cout << std::setw(10) << "" << "(PASSWORD) > "; 
			password = getpass("");
			if(!checkPassword(password)){
				system("clear");
				about();
				std::cout << "\n";
				std::cout << Red << std::setw(10) << " SORRY, PASSWORD NOT ENOUGH COMPLEX. TRY AGAIN. READ THE PASSWORD RULES ABOVE. " << Reset << "\n\n";
				goto condition;
			}
		while(infile.get(car)){
			clr_msg+=car;	
		}
		infile.close();
		std::ofstream ofile(filename);
		ofile << aserpCrypt(clr_msg,password);
		ofile.close();

		system("clear");
		about();
		std::cout << "\n";
		std::cout << Red << std::setw(10) << "" <<"FILE SUCCESSFULLY ENCRYPTED." << Reset << " (Check your file to see the result)" << "\n\n";
	}
	else if(choice == "d"){

		labs:
			std::cout << "\n";
			std::cout << std::setw(10) << "" << "(FILE TO DECRYPT (Input: /Absolute/path/to/file.extension)) > ";
			std::getline(std::cin,filename);

		std::ifstream infile;

		if(!fileCheck(filename)){
			system("clear");
			about();
			std::cout << "\n";
			std::cout << Red << std::setw(10) << "" << " FILE DOESN'T EXIST. PLEASE TRY AGAIN." << Reset;
			goto labs;
		}
		infile.open(filename);
		std::cout << "\n";
		std::cout << std::setw(10) << "" << "(PASSWORD) > ";
		password = getpass("");
		while(infile.get(car)){
			clr_msg+=car;
		}
		infile.close();
		std::ofstream ofile(filename);
		ofile << aserpDcrypt(clr_msg,password);
		ofile.close();

		system("clear");
		about();
		std::cout << "\n";
		std::cout << Red << std::setw(10) << "" <<"FILE SUCCESSFULLY DECRYPTED." << Reset << " (Check your file to see the result)" << "\n\n";	
	}
	else{
		system("clear");
		about();
		goto validChoice;
	}
	std::cout << "\n";
	return;
}

CRYPTON::~CRYPTON(void){ }
