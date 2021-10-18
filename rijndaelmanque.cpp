#include <random>
#include "fixedphrases.h"
#include "rijndaelmanque.h"

std::vector<unsigned char> manque::Subst::calculateMultiplicativeInverse()
{
	std::vector<unsigned char> multiplicativeInvserse(256, 0);
	boost::math::tools::polynomial<double>  irreduciblePolynomial = { {1,1,0,1,1,0,0,0,1} };
	for (unsigned char i = 0x01;; ) {
		boost::math::tools::polynomial<double>  inverseTarget = {
			{(double)((i >> 0) & 1),(double)((i >> 1) & 1),(double)((i >> 2) & 1),(double)((i >> 3) & 1),
			(double)((i >> 4) & 1),(double)((i >> 5) & 1),(double)((i >> 6) & 1),(double)((i >> 7) & 1)}
		};
		boost::math::tools::polynomial<double> bezoutT = { {0} }, newBezoutT = { {1} },
			remainder = irreduciblePolynomial, newRemainder = inverseTarget,
			zeroRemainder = { {0} }, inverseRemainder = { {1} };
		while (newRemainder != zeroRemainder) {

			auto quotient = remainder / newRemainder;

			// Addition applied for XOR operationg
			for (auto& q : quotient.data()) {
				q = std::abs(q);
				if ((int)q % 2 != 1) {
					q = 0;
				}
				else {
					q = 1;
				}
			}
			auto tempBezouT = bezoutT;
			bezoutT = newBezoutT;
			newBezoutT = tempBezouT - (quotient * newBezoutT);
			for (auto& nb : newBezoutT.data()) {
				nb = std::abs(nb);
				if ((int)nb % 2 != 1) {
					nb = 0;
				}
				else {
					nb = 1;
				}

			}
			auto tempRemainder = remainder;
			remainder = newRemainder;
			newRemainder = tempRemainder - (quotient * newRemainder);
			for (auto& nr : newRemainder.data()) {
				nr = std::abs(nr);
				if ((int)nr % 2 != 1) {
					nr = 0;
				}
				else {
					nr = 1;
				}
			}
			bool isRemainderZero = true;
			for (auto& nr : newRemainder.data()) {
				if (nr != 0) {
					isRemainderZero = false;
					break;
				}
			}
			if (isRemainderZero) {
				newRemainder = zeroRemainder;
			}
			else {
				// Remove zero coefficients from the top recursively
				remainder.normalize();
				newRemainder.normalize();
			}
		}

		if (remainder.degree() != 0 || remainder.data().at(0) != 1.0) {
			assert(false);
		}

		int shiftbit = 0;
		for (const auto& t : bezoutT.data()) {
			if (t == 1.0) {
				unsigned char bitToAdd = 0b1 << shiftbit;
				multiplicativeInvserse.at(i) |= bitToAdd;
			}
			shiftbit++;
		}

		if (i == 0xff) {
			break;
		}
		i++;
	}

	return multiplicativeInvserse;
}

std::unordered_map<std::byte, std::byte> manque::Subst::createSbox()
{
	auto multiplicativeInverse = calculateMultiplicativeInverse();
	std::unordered_map<std::byte, std::byte> substTable;
	const std::byte constByteForAffineTrans{ 0b01100011 };
	unsigned char key = 0x0;
	for (const auto& ml : multiplicativeInverse) {
		std::byte byteAfterAffineTrans{ 0b0000'0000 };
		std::byte mlByte{ ml };
		for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
			std::byte baseBit{ 0b0001 };
			std::byte eachBit{ (mlByte >> bitIndex) & baseBit };
			eachBit ^= std::byte{ (mlByte >> ((bitIndex + 4) % 8)) & baseBit };
			eachBit ^= std::byte{ (mlByte >> ((bitIndex + 5) % 8)) & baseBit };
			eachBit ^= std::byte{ (mlByte >> ((bitIndex + 6) % 8)) & baseBit };
			eachBit ^= std::byte{ (mlByte >> ((bitIndex + 7) % 8)) & baseBit };
			eachBit ^= std::byte{ (constByteForAffineTrans >> bitIndex) & baseBit };
			byteAfterAffineTrans |= (eachBit << bitIndex);
		}
		substTable.insert(std::pair<std::byte, std::byte>{std::byte{ key }, byteAfterAffineTrans });
		key++;
	}

	return substTable;
}

std::unordered_map<std::byte, std::byte> manque::Subst::invCreateSbox()
{
	auto invSbox = std::unordered_map<std::byte, std::byte>{};
	invSbox.reserve(sBox.size());

	for (auto sb : sBox) {
		invSbox[sb.second] = sb.first;
	}

	return invSbox;
}

void manque::Rijndael::generateCipherKey()
{
	for (int i = 0; i < 16; i++) {
		unsigned char key = (unsigned char)((std::rand() % 256 + 1) & 0xff);
		m_cipherKey[i] = key;
	}
}

void manque::Rijndael::subBytes()
{
	// table lookup of SBox
	for (auto& eachRow : m_state) {
		for (auto& state : eachRow) {
			state = std::to_integer<unsigned char>(Subst::sBox[std::byte{ state }]);
		}
	}
}

void manque::Rijndael::addRoundKey(std::vector<Word>::const_iterator wordItr)
{
	// A state vector is composed of ROW data.
	// Meanwhile
	// A word vector is composed of COLUMN data.
	for (int indexOfState = 0; indexOfState < m_state.size(); indexOfState++) {
		int indexOfWord = 0;
		for (auto& eachRow : m_state) {
			eachRow.at(indexOfState) = eachRow.at(indexOfState) ^ wordItr->bytes.at(indexOfWord);
			indexOfWord++;
		}
		wordItr++;
	}
}

void manque::Rijndael::shiftRows()
{
	// Cyclic permutation
	int shift = 0;
	for (auto& eachRow : m_state) {
		std::rotate(eachRow.begin(), eachRow.begin() + shift, eachRow.end());
		shift++;
	}
}

unsigned char manque::Rijndael::mlpInMixColumns(unsigned char coeff, unsigned char stateBit) {
	// Multiplication by x for MixColumns function
	assert(0x01 <= coeff && coeff <= 0x03);

	const unsigned char irreduciblePolynomial{ 0x1b };
	std::vector<unsigned char> addList{ stateBit };
	for (int i = 1; i < coeff; i++) {
		if (stateBit & 0x80) {
			stateBit = (stateBit << 1) ^ irreduciblePolynomial;
		}
		else {
			stateBit = stateBit << 1;
		}
		addList.push_back(stateBit);
	}

	unsigned char result = 0;
	if (addList.size() == 0x03) {
		result = addList.at(0) ^ addList.at(1);
	}
	else {
		result = addList.back();
	}

	return result;

}

void manque::Rijndael::mixColumns()
{
	std::unordered_map<int, std::array<unsigned char, 4>> ax = {
		{0,{0x02, 0x03,0x01,0x01}},
		{1,{0x01,0x02,0x03,0x01,}},
		{2,{0x01,0x01,0x02,0x03}},
		{3,{0x03,0x01,0x01,0x02}}
	};

	auto originalState = m_state;
	for (int column = 0; column < c_stateClmNum; column++) {
		for (int row = 0; row < 4; row++) {
			m_state.at(row).at(column) =
				(mlpInMixColumns(ax[row].at(0), originalState.at(0).at(column))) ^
				(mlpInMixColumns(ax[row].at(1), originalState.at(1).at(column))) ^
				(mlpInMixColumns(ax[row].at(2), originalState.at(2).at(column))) ^
				(mlpInMixColumns(ax[row].at(3), originalState.at(3).at(column)));
		}
	}
}

std::vector<manque::Word> manque::Rijndael::createRcon()
{
	// Multiplication by x
	int length = (c_stateClmNum * c_round) / 4;
	std::vector<manque::Word> rcon;
	rcon.reserve((length));
	std::byte eachByte{ 0x01 };
	rcon.push_back(manque::Word(eachByte, std::byte{ 0x00 }, std::byte{ 0x00 }, std::byte{ 0x00 }));

	std::byte irreduciblePolynomial{ 0x1b };
	for (int i = 1; i < length; i++) {
		if (std::to_integer<bool>(eachByte & std::byte{ 0x80 })) {
			eachByte = (eachByte << 1) ^ irreduciblePolynomial;
		}
		else {
			eachByte = eachByte << 1;
		}
		rcon.push_back(manque::Word(eachByte, std::byte{ 0x00 }, std::byte{ 0x00 }, std::byte{ 0x00 }));
	}

	return rcon;
}

void manque::Rijndael::rotWord(manque::Word& word) {
	// cyclic permutation
	std::rotate(word.bytes.begin(), word.bytes.begin() + 1, word.bytes.end());
}

void manque::Rijndael::subWord(manque::Word& word) {
	// table lookup of SBox
	for (auto& byte : word.bytes) {
		byte = std::to_integer<unsigned char>(Subst::sBox[std::byte{ byte }]);
	}
}

std::vector<manque::Word> manque::Rijndael::keyExpansion()
{
	std::vector<manque::Word> rcon = createRcon();

	int i = 0;
	std::vector<manque::Word> w;
	w.reserve(c_stateClmNum * (c_round + 1));
	while (i < c_stateClmNum) {
		w.push_back(manque::Word(std::byte{ m_cipherKey[4 * i] }, std::byte{ m_cipherKey[4 * i + 1] },
			std::byte{ m_cipherKey[4 * i + 2] }, std::byte{ m_cipherKey[4 * i + 3] }));
		i++;
	}
	i = c_stateClmNum;

	while (i < c_stateClmNum * (c_round + 1)) {
		auto temp = w.at(i - 1);
		if (i % c_stateClmNum == 0) {
			rotWord(temp);
			subWord(temp);
			const auto rn = rcon[(i / c_stateClmNum) - 1].bytes;
			int index = 0;
			for (auto& tByte : temp.bytes) {
				tByte = std::to_integer<unsigned char>(std::byte{ tByte } ^ std::byte{ rn[index] });
				index++;
			}
		}
		else {
			// NOT developed Cipher Key-256
			assert(true);
		}
		auto wi = w[i - c_stateClmNum];
		w.push_back(wi ^ temp);
		i++;
	}
	return w;
}

bool manque::Rijndael::convertPlainText2InputBlock(std::string& plainText)
{
	try {
		int index = 0;
		for (auto& letter : plainText) {
			int i = index / c_stateClmNum;
			int j = index % c_stateClmNum;
			m_state[j][i] = letter;
			index++;
		}
	}
	catch (...) {
		return false;
	}
	return true;
}

std::vector<std::vector<unsigned char>> manque::Rijndael::cipher(std::string plainText)
{
	try
	{
		if (!convertPlainText2InputBlock(plainText)) {
			m_state.clear();
			return m_state;
		}

		generateCipherKey();
		std::vector<Word> roundKey = keyExpansion();

		addRoundKey(roundKey.begin()++);
		for (int currentRound = 1; currentRound < c_round; currentRound++) {
			subBytes();
			shiftRows();
			mixColumns();
			addRoundKey(roundKey.begin() + (currentRound * c_stateClmNum));
		}

		subBytes();
		shiftRows();
		addRoundKey(roundKey.begin() + (c_round * c_stateClmNum));
	}
	catch (...)
	{
		m_state.clear();
		return m_state;
	}
	return m_state;
}

bool manque::Rijndael::convertCipherKey(std::string inputCipherKey)
{
	try {
		unsigned char key[16] = { 0 };
		std::vector<unsigned char> combinedLetter;

		int count = 0;
		for (auto& letter : inputCipherKey) {
			if (count % 2 == 0) {
				combinedLetter.push_back(std::stoi(std::string(1, letter).c_str(), 0, 16));
			}
			else {
				combinedLetter.at(combinedLetter.size() - 1) = (combinedLetter.at(combinedLetter.size() - 1) << 4)
					| std::stoi(std::string(1, letter).c_str(), 0, 16);
			}
			count++;
		}

		int index = 0;
		for (const auto cl : combinedLetter) {
			key[index] = cl;
			index++;
		}
		std::copy(std::begin(key), std::end(key), std::begin(m_cipherKey));

	}
	catch (...) {
		return false;
	}
	return true;
}

void manque::Rijndael::invShiftRows(std::vector<std::vector<unsigned char>>& state)
{
	// Cyclic permutation
	int shift = 0;
	for (auto& eachRow : state) {
		std::rotate(eachRow.begin(), eachRow.begin() + shift, eachRow.end());
		shift = shift == 0 ? 3 : --shift;
	}
}

void manque::Rijndael::invSubBytes(std::vector<std::vector<unsigned char>>& state)
{
	// table lookup of Inverse - SBox
	for (auto& eachRow : state) {
		for (auto& state : eachRow) {
			state = std::to_integer<unsigned char>(Subst::invSbox[std::byte{ state }]);
		}
	}
}

unsigned char manque::Rijndael::mlpInInvMixColumns(unsigned char coeff, unsigned char stateBit) {
	// Multiplication by x for Inverse - MixColumns function
	assert(0x09 <= coeff && coeff <= 0x0e);

	const unsigned char irreduciblePolynomial{ 0x1b };
	std::vector<unsigned char> addList{ stateBit };
	for (int i = 1; i < coeff; i++) {
		if (stateBit & 0x80) {
			stateBit = (stateBit << 1) ^ irreduciblePolynomial;
		}
		else {
			stateBit = stateBit << 1;
		}
		addList.push_back(stateBit);
	}

	unsigned char result = 0;
	if (addList.size() == 0x09) {
		result = addList.at(0) ^ addList.at(3);
	}
	else if (addList.size() == 0x0b) {
		result = addList.at(0) ^ addList.at(1) ^ addList.at(3);
	}
	else if (addList.size() == 0x0d) {
		result = addList.at(0) ^ addList.at(2) ^ addList.at(3);
	}
	else if (addList.size() == 0x0e) {
		result = addList.at(1) ^ addList.at(2) ^ addList.at(3);
	}
	else {
		result = addList.back();
	}

	return result;

}

void manque::Rijndael::invMixColumns(std::vector<std::vector<unsigned char>>& state)
{
	std::unordered_map<int, std::array<unsigned char, 4>> ax = {
		{0,{0x0e, 0x0b,0x0d,0x09}},
		{1,{0x09,0x0e,0x0b,0x0d,}},
		{2,{0x0d,0x09,0x0e,0x0b}},
		{3,{0x0b,0x0d,0x09,0x0e}}
	};

	auto originalState = state;
	for (int column = 0; column < c_stateClmNum; column++) {
		for (int row = 0; row < 4; row++) {
			state.at(row).at(column) =
				(mlpInInvMixColumns(ax[row].at(0), originalState.at(0).at(column))) ^
				(mlpInInvMixColumns(ax[row].at(1), originalState.at(1).at(column))) ^
				(mlpInInvMixColumns(ax[row].at(2), originalState.at(2).at(column))) ^
				(mlpInInvMixColumns(ax[row].at(3), originalState.at(3).at(column)));
		}
	}
}

void manque::Rijndael::invAddRoundKey(std::vector<std::vector<unsigned char>>& state, std::vector<Word>::const_iterator wordItr)
{
	for (int indexOfState = 0; indexOfState < state.size(); indexOfState++) {
		int indexOfWord = 0;
		for (auto& eachRow : state) {
			eachRow.at(indexOfState) = eachRow.at(indexOfState) ^ wordItr->bytes.at(indexOfWord);
			indexOfWord++;
		}
		wordItr++;
	}
}

std::vector<std::vector<unsigned char>> manque::Rijndael::InverseCipher(std::string inputCipherKey)
{
	// To Accept challenging inverse cipher multiple times, m_state (the output of cipher) should NOT be modified.
	auto state = m_state;

	try
	{
		if (!convertCipherKey(inputCipherKey)) {
			state.clear();
			return state;
		}

		std::vector<Word> roundKey = keyExpansion();

		invAddRoundKey(state, roundKey.begin() + (c_round * c_stateClmNum));
		for (int currentRound = 9; 1 <= currentRound; currentRound--) {
			invShiftRows(state);
			invSubBytes(state);
			invAddRoundKey(state, roundKey.begin() + (currentRound * c_stateClmNum));
			invMixColumns(state);
		}

		invShiftRows(state);
		invSubBytes(state);
		invAddRoundKey(state, roundKey.begin()++);
	}
	catch (...)
	{
		state.clear();
		return state;
	}
	return state;
}