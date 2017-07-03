// minifile.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "magic.h"

#pragma comment(lib, "magic1.lib")

using namespace std;

class libmagic
{
public:
	libmagic():
		_flags(0), 
		_magic(nullptr),
		_magicfile(nullptr)
	{
		_magic = magic_open(_flags);
		magic_load(_magic, _magicfile);
	}

	~magic()
	{
		if(_magic)
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

int main()
{
	const char* filename = R"(C:\Users\jayco\Downloads\libmagic-alpha.tar.gz)";

	libmagic m;

	printf("Version: %d\n", m.getVersion());
	printf("%s: %s",filename, m.getId(filename));
    return 0;
}



