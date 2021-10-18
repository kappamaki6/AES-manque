#pragma once
#include <iostream>
#include <vector>
#include <unordered_map>
#include <boost/math/tools/polynomial.hpp>

namespace manque {
	struct Subst {
	private:
		static std::vector<unsigned char> calculateMultiplicativeInverse();
		static std::unordered_map<std::byte, std::byte> createSbox();
		static std::unordered_map<std::byte, std::byte> invCreateSbox();
	public:
		inline static std::unordered_map<std::byte, std::byte> sBox = createSbox();
		inline static std::unordered_map<std::byte, std::byte> invSbox = invCreateSbox();
	};

	struct Word {
	public:
		std::vector<unsigned char> bytes;
		Word(std::byte first, std::byte second, std::byte third, std::byte forth) :bytes(4, 0) {
			bytes[0] = std::to_integer<unsigned char>(first);
			bytes[1] = std::to_integer<unsigned char>(second);
			bytes[2] = std::to_integer<unsigned char>(third);
			bytes[3] = std::to_integer<unsigned char>(forth);
		};

		Word& operator^(const Word& rWord) {
			auto&& r = rWord.bytes.begin();
			for (auto& b : bytes) {
				b ^= *r;
				r++;
			}
			return *this;
		}

		Word& operator=(const Word& rWord) {
			bytes = rWord.bytes;
			return *this;
		}

	};

	class Rijndael {
	private:
		const int c_stateClmNum = 4;
		const int c_round = 10;
		std::vector<std::vector<unsigned char>> m_outputBlock, m_state;
		unsigned char m_cipherKey[16];
	public:
		Rijndael(int blockSize) :
			m_outputBlock(blockSize, std::vector<unsigned char>(blockSize, 0)),
			m_state(blockSize, std::vector<unsigned char>(blockSize, 0)),
			m_cipherKey{ 0 }
		{
		};
		~Rijndael() {
		};
		const static unsigned int c_maxPlainTextSize = 16u;
		const static unsigned int c_maxInputCipherKeySize = 32u;
		std::vector<std::vector<unsigned char>> cipher(std::string plainText);
		std::vector<std::vector<unsigned char>> InverseCipher(std::string inputCipherKey);
	private:
		Rijndael() { assert(true); };
		void* operator new(size_t size) { assert(true); };
		void generateCipherKey();
		std::vector<Word> keyExpansion();
		inline std::vector<Word> createRcon();
		void rotWord(Word& word);
		void subWord(Word& word);
		bool convertPlainText2InputBlock(std::string& plainText);
		bool convertCipherKey(std::string inputCipherKey);
		unsigned char mlpInMixColumns(unsigned char coeff, unsigned char stateBit);
		unsigned char mlpInInvMixColumns(unsigned char coeff, unsigned char stateBit);
		void addRoundKey(std::vector<Word>::const_iterator wordItr);
		void subBytes();
		void shiftRows();
		void mixColumns();
		void invAddRoundKey(std::vector<std::vector<unsigned char>>& state, std::vector<Word>::const_iterator wordItr);
		void invSubBytes(std::vector<std::vector<unsigned char>>& state);
		void invShiftRows(std::vector<std::vector<unsigned char>>& state);
		void invMixColumns(std::vector<std::vector<unsigned char>>& state);
	};
}