#include "KeyEvent.hpp"

static IMAGE_SECTION_HEADER *get_image_section_headers(HANDLE module, WORD &count)
{
	auto header = (IMAGE_DOS_HEADER *)module;

	if(header->e_magic != IMAGE_DOS_SIGNATURE)
		throw "Invalid DOS signature";

	auto nt_header = (IMAGE_NT_HEADERS *)((LONG)module + header->e_lfanew);

	if(nt_header->Signature != IMAGE_NT_SIGNATURE)
		throw "Invalid NT signature";

	count = nt_header->FileHeader.NumberOfSections;

	return (IMAGE_SECTION_HEADER *)(nt_header + 1);
}

static IMAGE_SECTION_HEADER *get_image_section_header(HANDLE module, std::string name)
{
	WORD count;
	auto section_header = get_image_section_headers(module, count);

	for(WORD i = 0; i < count; ++i, ++section_header)
	{
		if(!strncmp((const char *)section_header->Name, name.c_str(), sizeof(section_header->Name)))
			return section_header;
	}
	
	throw "Unable to find named section";
}

static bool compare(const char *address, const char *pattern, const char *mask, size_t size)
{
	for(size_t i = 0; i < size; ++i)
		if((address[i] & mask[i]) != (pattern[i] & mask[i]))
				return false;

	return true;
}

static const void *pattern_search(const char *start, const char *stop, const char *pattern, const char *mask, size_t size)
{
	stop -= size;

	for(auto c = start; c != stop; ++c)
	{
			if(compare(c, pattern, mask, size))
				return c;
	}

	throw "Unable to find pattern";
}

const void *find_pattern(HANDLE module, std::string name, const char *pattern, const char *mask, size_t size)
{
	auto section = get_image_section_header(module, name);

	auto start = (const char *)module + section->VirtualAddress;
	auto stop = start + section->Misc.VirtualSize;

	return pattern_search(start, stop, pattern, mask, size);
}
