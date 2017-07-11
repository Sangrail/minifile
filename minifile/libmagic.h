#pragma once

#include "magic.h"

#pragma comment(lib, "magic1.lib")

namespace classifier {
	class libmagic
	{
	public:
		libmagic() :
			_flags(0),
			_magic(nullptr),
			_magicfile(nullptr)
		{
			_magic = magic_open(_flags);
			magic_load(_magic, _magicfile);
		}

		~libmagic()
		{
			if (_magic)
				magic_close(_magic);
		}

		int getVersion()
		{
			return magic_version();
		}

		const char* getId(const char* filename)
		{
			return magic_file(_magic, filename);
		}

	private:
		int _flags;

		magic_set *_magic;
		const char *_magicfile;
	};
}

