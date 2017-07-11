// minifile.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "libmagic.h"
#include "yara_wrapper.h"
#include <fstream> 
#include "main.h"

using namespace std;
using namespace yara_wrapper;

bool is_file_exist(const char *fileName)
{
	std::ifstream infile(fileName);
	return infile.good();
}

int main()
{
	const char* filename = R"(C:\Users\jayco\Downloads\libmagic-alpha.tar.gz)";

	MagicFileClassifier(filename);

	YaraFileClassifier(filename);
	
	//analyse global characteristics of the file

	//map file type to plugin and analyse using file-specific plugins



    return 0;
}

void MagicFileClassifier(const char * filename)
{
	classifier::libmagic m;

	printf("Version: %d\n", m.getVersion());
	printf("%s: %s\n", filename, m.getId(filename));
}

void YaraFileClassifier(const char * filename)
{
	Yara fileClassifier;

	bool loadedSigs = false;

	const char* rules_compiled = R"(magic.yarac)";
	const char* rules_text = R"(magic.yara)";

	if (is_file_exist(rules_compiled))
		loadedSigs = fileClassifier.Initialise(rules_compiled);
	else if (is_file_exist(rules_text))
		loadedSigs = fileClassifier.Initialise(rules_text);
	else
		exit(5);

	if (loadedSigs)
	{
		auto scanComplete = fileClassifier.ScanFile(filename);
	}
}



