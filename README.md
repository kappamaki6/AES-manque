# AES-manque
Console application for Cipher and Inverse Cipher with AES-128 algorithm implemented by C++.

AES-128が実装されたコンソールアプリです<br>
遊び方
1. 暗号化したい文章を入力
2. 暗号化された文章を出力
3. 秘密鍵(パスワード)を入力して復号化に挑戦！
4. 当たるまで遊べます(^^)/


HOW to use:
1. Type what you want to cipher
<br>-> Displays the encrypted data as HEX
2. Challenge inverse cipher by 32 letters as HEX
<br>-> Displays the result of decrypting

---
This application<br><br>
:Requires
- C++17 or later
- Boost 1.77.0 Library or later

:Developed on
- Windows 10 ver.2004
- Visual Studio 2019
- msvc14.1
- Code Page 932 (Shift-jis)

:Based on
- [NIST AES Algorithm](https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf)

:Refers to
- [Wiki-Extended Euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm)
- [Wiki-Rijndael S-box](https://en.wikipedia.org/wiki/Rijndael_S-box#Inverse_S-box)
