// IMPALA function

#include "../Core/HEADER.h"
#include "../Core/IMPALA.h"
#include "../Core/AES.h"
#include "../Core/Colors.h"

using namespace CryptoPP;

IMPALA::IMPALA(void){ }

inline bool IMPALA::checkDigit(std::string str){
	return (std::any_of(str.begin(),str.end(), ::isdigit) ? true:false);
}

inline bool IMPALA::checkLower(std::string str){
	return (std::any_of(str.begin(),str.end(), ::islower) ? true:false);
}

inline bool IMPALA::checkUpper(std::string str){
	return (std::any_of(str.begin(),str.end(), ::isupper) ? true:false);
}

inline bool IMPALA::checkSpecChar(std::string str){
	bool flag = false;
	for(auto i = 0; str[i]; i++){
		if((str[i]>=32 and str[i]<=47)||(str[i]>=58 and str[i]<=64)||(str[i]>=91 and str[i]<=96)||(str[i]>=123 and str[i]<=126)){
			flag = true;
			break;
		}
	}
	return flag;
}

inline bool IMPALA::checkPassword(std::string str){
	// password must contains at least one Upper character, one Lower character, one Number, one Special character and must be at least 12 characters long
	return((checkDigit(str) && checkLower(str) && checkUpper(str) && checkSpecChar(str) && str.length()>=12) ? true:false);
}

inline bool IMPALA::fileCheck(const std::string &filename){
	struct stat buffer;
	return (stat (filename.c_str(), &buffer)==0);
}

std::string IMPALA::aes(std::string text, std::string password, std::string choice){
	std::string res, ciphertext, recovered;
	std::string iv(password+password);

	try{
		SecByteBlock key(AES::MAX_KEYLENGTH+AES::BLOCKSIZE);
		HKDF<SHA256> hkdf;
		hkdf.DeriveKey(key, key.size(), (const byte*)password.data(), password.size(), (const byte*)iv.data(), iv.size(), NULL, 0);

		if(choice == "e" || choice == "E"){
			EAX<AES>::Encryption enc;
			enc.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key+AES::MAX_KEYLENGTH);
			StringSource(text, true, new AuthenticatedEncryptionFilter(enc, new StringSink(ciphertext)));
			StringSource(ciphertext, true, new HexEncoder(new StringSink(res)));
		}
		else{
			EAX< AES >::Decryption dec;
			dec.SetKeyWithIV(key, AES::MAX_KEYLENGTH, key+AES::MAX_KEYLENGTH);
			StringSource(text, true, new HexDecoder(new StringSink(ciphertext)));
			StringSource(ciphertext, true, new AuthenticatedDecryptionFilter(dec, new StringSink(recovered), AuthenticatedDecryptionFilter::THROW_EXCEPTION));
		}
	}
	catch(Exception& ex){
		std::cerr << "ERROR: " << ex.what() << std::endl;
		return 0;
	}
	if(choice == "e" || choice == "E"){
		return res;
		
	}
	else{
		return recovered;
	}
}

inline void IMPALA::about(){
	std::ifstream infile;
	std::string line;
	infile.open("About.txt");

	while(std::getline(infile,line)){
		std::cout << line << std::endl;
	}
	infile.close();
	return;
}

void IMPALA::run(){

	AES_256 aes256;
	about();
	
	std::string filename;
	std::string clr_msg = "";
	std::string choice;
	std::string password;
	char car;

	std::cout << "\n";
	std::cout << std::setw(14) << "" << "[ PRESS ENTER TO RUN ]";
	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	system("clear");
	about();

	std::cout << "\n\n";
	std::cout << " [ ENCRYPT OR DECRYPT ? (e/E or d/D) ] > ";
	std::getline(std::cin,choice);

	system("clear");
	about();

	if(choice == "e" || choice == "E"){

		label:
			std::cout << "\n\n";
			std::cout << " [ FILE TO ENCRYPT (Input: /Absolute/path/to/file.extension) ] > ";
			std::getline(std::cin,filename);

		std::ifstream infile;

		if(!fileCheck(filename)){
			system("clear");
			about();
			std::cout << "\n";
			std::cout << Red << " FILE DOESN'T EXIST. PLEASE TRY AGAIN." << Reset;
			goto label; // while file doesn't exist repeat the process
		}
		infile.open(filename);
		std::cout << "\n";
		condition: 
			password = getpass(" [ PASSWORD ] > ");
			if(!checkPassword(password)){ // password conditions
				system("clear");
				about();
				std::cout << "\n\n";
				std::cout << Red << " SORRY, PASSWORD NOT ENOUGH COMPLEX. TRY AGAIN. " << Reset << "\n\n";
				goto condition;
			}
		while(infile.get(car)){
			clr_msg+=car;
		}
		infile.close();
		std::ofstream ofile(filename);
		ofile << aes256.aes(clr_msg,password,choice);
		ofile.close();

		system("clear");
		about();
		std::cout << "\n";
		std::cout << Red << " FILE SUCCESSFULLY ENCRYPTED." << Reset << " (Also check your file to see the result)" << "\n\n";

		std::ifstream Ifile;
		std::string line;
		Ifile.open(filename);
		while(getline(Ifile,line)){
			std::cout << line;
		}
		Ifile.close();
		std::cout << "\n\n";
	}
	else{

		labs:
			std::cout << "\n\n";
			std::cout << " [ FILE TO DECRYPT (Input: /Absolute/path/to/file.extension) ] > ";
			std::getline(std::cin,filename);

		std::ifstream infile;

		if(!fileCheck(filename)){
			system("clear");
			about();
			std::cout << "\n";
			std::cout << Red << " FILE DOESN'T EXIST. PLEASE TRY AGAIN." << Reset;
			goto labs; // while file doesn't exist repeat the process
		}
		infile.open(filename);
		std::cout << "\n";
		password = getpass(" [ PASSWORD ] > ");
		while(infile.get(car)){
			clr_msg+=car;
		}
		infile.close();
		std::ofstream ofile(filename);
		ofile << aes256.aes(clr_msg,password,choice);
		ofile.close();

		system("clear");
		about();
		std::cout << "\n";
		std::cout << Red << " FILE SUCCESSFULLY DECRYPTED." << Reset << " (Check your file to see the result)" << "\n\n";	
	}
	return;
}

IMPALA::~IMPALA(void){ }