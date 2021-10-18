#pragma once
#include <iostream>

namespace phrase {

	const std::string endApp{ "\n(*´ω｀)ﾉｼ bye\n\n" };

	const std::string congrats =
		"\n　　　　　　　　*'``・* 。\n"
		"　　　　　　　　|　　　　 `*。　　　CONGRATULATIONS!!!\n"
		"　　　　 　　,｡∩　　　　 　* 　　　大当たり\n"
		"　　　　　　+　(´･ω･`)　*｡+ﾟ\n"
		"　　　　　　`*｡ ヽ、　 つ *ﾟ*\n"
		"　　　　　　　`・+｡*・' ﾟ⊃ +ﾟ\n"
		"　　　　　　　☆　　 ∪~ ｡*ﾟ\n"
		"　 　　　　　　`・+｡*・ ﾟ\n\n";

	const std::string startApp =
		"\n　   ∧  ∧.\n"
		"⊂（ ´･ω･`） 　< Let's Encrypt !!\n\n\n";

	class Message {
	public:
		static void rangeExcessive(const unsigned int& inputSize, const int& maxSize) {
			std::cout << "最大入力値から" << inputSize - maxSize<< "文字分超過しています\n";
		}
	};
}