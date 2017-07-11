#pragma once

#include <string>
#include <iostream>
#include <yara.h>

namespace yara_wrapper
{
	static char cescapes[] =
	{
		0  , 0  , 0  , 0  , 0  , 0  , 0  , 'a',
		'b', 't', 'n', 'v', 'f', 'r', 0  , 0  ,
		0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  ,
		0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  ,
	};


	void print_escaped(	uint8_t* data,size_t length)
	{
		size_t i;

		for (i = 0; i < length; i++)
		{
			switch (data[i])
			{
			case '\"':
			case '\'':
			case '\\':
				printf("\\%c", data[i]);
				break;

			default:
				if (data[i] >= 127)
					printf("\\%03o", data[i]);
				else if (data[i] >= 32)
					putchar(data[i]);
				else if (cescapes[data[i]] != 0)
					printf("\\%c", cescapes[data[i]]);
				else
					printf("\\%03o", data[i]);
			}
		}
	}


	void print_hex_string(uint8_t* data,int length)
	{
		for (int i = 0; i < min(32, length); i++)
			printf("%s%02X", (i == 0 ? "" : " "), (uint8_t)data[i]);

		puts(length > 32 ? " ..." : "");
	}

	bool hasEnding(std::string const &fullString, std::string const &ending) {
		if (fullString.length() >= ending.length()) {
			return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
		}
		else {
			return false;
		}
	}

	#define MAX_ARGS_EXT_VAR 32
	static int stack_size = DEFAULT_STACK_SIZE;
	static int max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;
	static char* ext_vars[MAX_ARGS_EXT_VAR + 1];
	static int timeout = 1000000;
	#define MAX_ARGS_TAG            32
	static char* tags[MAX_ARGS_TAG + 1];
	#define MAX_ARGS_IDENTIFIER     32
	static char* identifiers[MAX_ARGS_IDENTIFIER + 1];

#define PRIx64 "I64x"
#define PRId64 "I64d"

	typedef struct COMPILER_RESULTS
	{
		int errors;
		int warnings;

	} COMPILER_RESULTS;

	typedef struct _MODULE_DATA
	{
		const char* module_name;
		YR_MAPPED_FILE mapped_file;
		struct _MODULE_DATA* next;

	} MODULE_DATA;

	MODULE_DATA* modules_data_list = NULL;

	class Yara
	{
	public:
		Yara():_compiler(nullptr), _rules(nullptr)
		{
			auto result = yr_initialize();
			
			yr_set_configuration(YR_CONFIG_STACK_SIZE, &stack_size);
			yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, &max_strings_per_rule);
			
		}

		bool Initialise(std::string sigs)
		{
			if (hasEnding(sigs,"c"))//compiled
			{
				return LoadCompiled(sigs);
			}
			else
			{
				return CompileTextFile(sigs);
			}
		}
	
		bool ScanFile(std::string filename, bool fast_scan = false)
		{
			int flags = 0;

			if (fast_scan)
				flags |= SCAN_FLAGS_FAST_MODE;

			auto result = yr_rules_scan_file(
				_rules,
				filename.c_str(),
				flags,
				callback,
				nullptr,
				timeout);

			if (result != ERROR_SUCCESS)
			{
				return false;
			}

			return true;
		}

		~Yara()
		{
			if (_compiler != nullptr)
				yr_compiler_destroy(_compiler);

			if (_rules != nullptr)
				yr_rules_destroy(_rules);

			yr_finalize();
		}

	private:

		COMPILER_RESULTS _cr;

		YR_COMPILER* _compiler;
		YR_RULES* _rules;

		static bool _ignore_warnings;
		bool LoadCompiled(std::string filename)
		{
			auto result = yr_rules_load(filename.c_str(), &_rules);

			if (result != ERROR_SUCCESS && result != ERROR_INVALID_FILE)
			{
				return false;
			}

			if (result == ERROR_SUCCESS)
			{
				result = define_external_variables(_rules, nullptr);

				if (result != ERROR_SUCCESS)
				{
					return false;
				}
			}
		}

		bool CompileTextFile(std::string filename)
		{
			if (yr_compiler_create(&_compiler) != ERROR_SUCCESS)
				return false;

			auto result = define_external_variables(nullptr, _compiler);

			if (result != ERROR_SUCCESS)
			{
				return false;
			}

			_cr.errors = 0;
			_cr.warnings = 0;

			yr_compiler_set_callback(_compiler, print_compiler_error, &_cr);

			FILE* rule_file = fopen(filename.c_str(), "r");

			if (rule_file == NULL)
			{
				return false;
			}

			_cr.errors = yr_compiler_add_file(_compiler, rule_file, nullptr, filename.c_str());

			fclose(rule_file);

			if (_cr.errors > 0)
			{
				printf("Errors: %d\n", _cr.errors);
				return false;
			}

			if (_cr.warnings > 0)
			{
				printf("Warnings: %d\n", _cr.warnings);
			}

			result = yr_compiler_get_rules(_compiler, &_rules);
			std::string compiledRules = filename + "c";
			result = yr_rules_save(_rules, compiledRules.c_str());

			if (result != ERROR_SUCCESS)
			{
				return false;
			}


			yr_compiler_destroy(_compiler);

			_compiler = nullptr;

			if (result != ERROR_SUCCESS)
				return false;

			return true;
		}
		int define_external_variables(YR_RULES* rules,	YR_COMPILER* compiler)
		{
			int result = ERROR_SUCCESS;

			for (int i = 0; ext_vars[i] != NULL; i++)
			{
				char* equal_sign = strchr(ext_vars[i], '=');

				if (!equal_sign)
				{
					fprintf(stderr, "error: wrong syntax for `-d` option.\n");
					return ERROR_SUCCESS;
				}

				// Replace the equal sign with null character to split the external
				// variable definition (i.e: myvar=somevalue) in two strings: identifier
				// and value.

				*equal_sign = '\0';

				char* identifier = ext_vars[i];
				char* value = equal_sign + 1;

				if (is_float(value))
				{
					if (rules != NULL)
						result = yr_rules_define_float_variable(
							rules,
							identifier,
							atof(value));

					if (compiler != NULL)
						result = yr_compiler_define_float_variable(
							compiler,
							identifier,
							atof(value));
				}
				else if (is_integer(value))
				{
					if (rules != NULL)
						result = yr_rules_define_integer_variable(
							rules,
							identifier,
							atoi(value));

					if (compiler != NULL)
						result = yr_compiler_define_integer_variable(
							compiler,
							identifier,
							atoi(value));
				}
				else if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0)
				{
					if (rules != NULL)
						result = yr_rules_define_boolean_variable(
							rules,
							identifier,
							strcmp(value, "true") == 0);

					if (compiler != NULL)
						result = yr_compiler_define_boolean_variable(
							compiler,
							identifier,
							strcmp(value, "true") == 0);
				}
				else
				{
					if (rules != NULL)
						result = yr_rules_define_string_variable(
							rules,
							identifier,
							value);

					if (compiler != NULL)
						result = yr_compiler_define_string_variable(
							compiler,
							identifier,
							value);
				}
			}

			return result;
		}

		static int callback(
			int message,
			void* message_data,
			void* user_data)
		{
			YR_MODULE_IMPORT* mi;
			YR_OBJECT* object;
			MODULE_DATA* module_data;

			switch (message)
			{
			case CALLBACK_MSG_RULE_MATCHING:
			case CALLBACK_MSG_RULE_NOT_MATCHING:
				return handle_message(message, (YR_RULE*)message_data, user_data);

			case CALLBACK_MSG_IMPORT_MODULE:

				mi = (YR_MODULE_IMPORT*)message_data;
				module_data = modules_data_list;

				while (module_data != NULL)
				{
					if (strcmp(module_data->module_name, mi->module_name) == 0)
					{
						mi->module_data = module_data->mapped_file.data;
						mi->module_data_size = module_data->mapped_file.size;
						break;
					}

					module_data = module_data->next;
				}

				return CALLBACK_CONTINUE;

			case CALLBACK_MSG_MODULE_IMPORTED:

				/*if (show_module_data)
				{
					object = (YR_OBJECT*)message_data;

					mutex_lock(&output_mutex);

					yr_object_print_data(object, 0, 1);
					printf("\n");

					mutex_unlock(&output_mutex);
				}*/

				return CALLBACK_CONTINUE;
			}

			return CALLBACK_ERROR;
		}

		static void print_compiler_error(
			int error_level,
			const char* file_name,
			int line_number,
			const char* message,
			void* user_data)
		{
			if (error_level == YARA_ERROR_LEVEL_ERROR)
			{
				fprintf(stderr, "%s(%d): error: %s\n", file_name, line_number, message);
			}
			//else if (!_ignore_warnings)
			{
				COMPILER_RESULTS* compiler_results = (COMPILER_RESULTS*)user_data;
				compiler_results->warnings++;

				fprintf(stderr, "%s(%d): warning: %s\n", file_name, line_number, message);
			}
		}

		int is_float(
			const char *str)
		{
			int has_dot = FALSE;

			if (*str == '-')      // skip the minus sign if present
				str++;

			if (*str == '.')      // float can't start with a dot
				return FALSE;

			while (*str)
			{
				if (*str == '.')
				{
					if (has_dot)      // two dots, not a float
						return FALSE;

					has_dot = TRUE;
				}
				else if (!isdigit(*str))
				{
					return FALSE;
				}

				str++;
			}

			return has_dot; // to be float must contain a dot
		}

		int is_integer(
			const char *str)
		{
			if (*str == '-')
				str++;

			while (*str)
			{
				if (!isdigit(*str))
					return FALSE;
				str++;
			}

			return TRUE;
		}

		static int handle_message(
			int message,
			YR_RULE* rule,
			void* data)
		{
			const char* tag;
			int show = TRUE;

			if (tags[0] != NULL)
			{
				// The user specified one or more -t <tag> arguments, let's show this rule
				// only if it's tagged with some of the specified tags.

				show = FALSE;

				for (int i = 0; !show && tags[i] != NULL; i++)
				{
					yr_rule_tags_foreach(rule, tag)
					{
						if (strcmp(tag, tags[i]) == 0)
						{
							show = TRUE;
							break;
						}
					}
				}
			}

			if (identifiers[0] != NULL)
			{
				// The user specified one or more -i <identifier> arguments, let's show
				// this rule only if it's identifier is among of the provided ones.

				show = FALSE;

				for (int i = 0; !show && identifiers[i] != NULL; i++)
				{
					if (strcmp(identifiers[i], rule->identifier) == 0)
					{
						show = TRUE;
						break;
					}
				}
			}

			int is_matching = (message == CALLBACK_MSG_RULE_MATCHING);

			if (is_matching)
			{
				printf("%s:", rule->ns->name);
				printf("%s ", rule->identifier);

				printf("[");

				yr_rule_tags_foreach(rule, tag)
				{
					// print a comma except for the first tag
					if (tag != rule->tags)
						printf(",");

					printf("%s", tag);
				}

				printf("] ");

				YR_META* meta;

				printf("[");

				yr_rule_metas_foreach(rule, meta)
				{
					if (meta != rule->metas)
						printf(",");

					if (meta->type == META_TYPE_INTEGER)
					{
						printf("%s=%" PRId64, meta->identifier, meta->integer);
					}
					else if (meta->type == META_TYPE_BOOLEAN)
					{
						printf("%s=%s", meta->identifier, meta->integer ? "true" : "false");
					}
					else
					{
						printf("%s=\"", meta->identifier);
						print_escaped((uint8_t*)(meta->string), strlen(meta->string));
						putchar('"');
					}
				}

				printf("] ");
			}

			

			return CALLBACK_CONTINUE;
		}
	};
}