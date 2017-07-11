// minifile.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "libmagic.h"
#include "yara_wrapper.h"

using namespace std;
using namespace yara_wrapper;

int main()
{
	const char* filename = R"(C:\Users\jayco\Downloads\libmagic-alpha.tar.gz)";
	const char* rules_compiled = R"(magic.yarac)";
	const char* rules_text = R"(magic.yara)";

	classifier::libmagic m;

	printf("Version: %d\n", m.getVersion());
	printf("%s: %s\n",filename, m.getId(filename));

	Yara yara;

	auto ld = yara.Initialise(rules_compiled);

	if (ld)
	{
		ld = yara.ScanFile(filename);
	}


	

	//analyse global characteristics of the file

	//map file type to plugin and analyse using file-specific plugins



    return 0;
}



