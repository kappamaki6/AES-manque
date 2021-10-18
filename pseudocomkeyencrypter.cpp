#include <iostream>
#include <csignal>
#include "pseudocomkeyencrypter.h";
#include "fixedphrases.h";
#include "rijndaelmanque.h";
#include <boost/math/tools/polynomial.hpp>

using output = std::vector<std::vector<unsigned char>>;

volatile std::sig_atomic_t endAppFlg = 0;
std::string plainText;

bool validateInveseCipher(output decryptedOutput) {

	std::string decryptedText = "";

	for (int column = 0; column < 4; column++) {
		for (int row = 0; row < 4; row++) {
			if (decryptedOutput.at(row).at(column) == 0x0) continue;
			decryptedText = decryptedText + (char)decryptedOutput.at(row).at(column);
		}
	}
	if (plainText.compare(decryptedText) != 0) {
		return false;
	}
	return true;
};

int main()
{
	std::signal(SIGINT, [](int signal) {endAppFlg = signal; });
	std::cout << phrase::startApp << "終了する場合は，[Ctrl + C]を入力してください\n";

	auto rijndael = manque::Rijndael(4);
	bool inverseCipherFlg = false;

	while (true) {
		try
		{
			if (endAppFlg) {
				break;
			}
			// [START] Decrypt
			if (inverseCipherFlg) {
				std::string cipherKey;
				std::cout << "復号鍵(16進数)を入力してください\n";
				std::cin >> cipherKey;
				if (cipherKey.size() > manque::Rijndael::c_maxInputCipherKeySize) {
					phrase::Message::rangeExcessive(cipherKey.size(), manque::Rijndael::c_maxInputCipherKeySize);
					continue;
				}

				auto decryptedOutput = rijndael.InverseCipher(cipherKey);
				if (decryptedOutput.empty() || !validateInveseCipher(decryptedOutput)) {
					std::cout << "\n（ ×ω×）" << "復号化に失敗しました\n";
					continue;
				}
				std::cout << phrase::congrats;
			}

			// [START] Encrypt
			std::cout << "暗号化する文章を入力してください\n";
			std::cin >> plainText;
			if (plainText.size() > manque::Rijndael::c_maxPlainTextSize) {
				phrase::Message::rangeExcessive(plainText.size(), manque::Rijndael::c_maxPlainTextSize);
				continue;
			}
			auto encryptedOutput = rijndael.cipher(plainText);
			if (encryptedOutput.empty()) {
				std::cout << "\n（ ×ω×）" << "暗号化に失敗しました\n";
				continue;
			}

			std::cout << "暗号化された文章\n";
			std::stringstream ss;
			for (int column = 0; column < 4; column++) {
				for (int row = 0; row < 4; row++) {
					std::cout
						<< std::setfill('0')
						<< std::setw(2)
						<< std::hex
						<< (unsigned int)encryptedOutput.at(row).at(column);
				}
			}
			std::cout << "\n\n";

			std::cout << "復号化に挑戦しますか？[y/n]";
			std::string ans{ "n" };
			std::cin >> ans;
			if (ans.size() == 1u) {
				switch (ans[0])
				{
				case 0x59:
				case 0x79:
					inverseCipherFlg = true;
					break;
				case 0x4e:
				case 0x6e:
					inverseCipherFlg = false;
					break;
				default:
					break;
				}
			}
		}
		catch (...)
		{
			std::cout << " \n（ ・ω・）エラー起きた...";
			break;
		}
	}
	std::cout << phrase::endApp;
#ifdef _WIN32
	system("pause");
#else
	system("read");
#endif
	}