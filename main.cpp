/*
The MIT License (MIT)

Copyright (c) 2013-2014 Christopher Rosell
Copyright (c) 2015 Timofey Lagutin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

//
#if !(defined(linux) || defined(__linux) || defined(__linux__) \
		|| defined(__gnu_linux__))
	#error "Unsupported OS. This is a Linux driver, what are trying to do?"
#endif

//
#define elif else if
#define null nullptr

//
#include <cstdint>
#include <cstddef>
typedef std::uint8_t   b1;
typedef std::uint8_t   byte;
typedef std::uint8_t   octet;
typedef std::int8_t    s1;
typedef std::uint8_t   u1;
typedef std::int16_t   s2;
typedef std::uint16_t  u2;
typedef std::int32_t   s4;
typedef std::uint32_t  u4;
typedef std::int64_t   s8;
typedef std::uint64_t  u8;
typedef std::intptr_t  sw;
typedef std::uintptr_t uw;
typedef std::ptrdiff_t ptrd;
static const uw wsz = sizeof(uw);
typedef float          f4;
typedef double         f8;
//static_assert(sizeof(byte) == 1, "szofbyte");
//static_assert(sizeof(octet) == 1, "szofoctet");
//static_assert(sizeof(s1) == 1, "szofs1");
//static_assert(sizeof(u1) == 1, "szofu1");
//static_assert(sizeof(s2) == 2, "szofs2");
//static_assert(sizeof(u2) == 2, "szofu2");
//static_assert(sizeof(s4) == 4, "szofs4");
//static_assert(sizeof(u4) == 4, "szofu4");
//static_assert(sizeof(s8) == 8, "szofs8");
//static_assert(sizeof(u8) == 8, "szofu8");
static_assert(sizeof(f4) == 4, "szoff4");
static_assert(sizeof(f8) == 8, "szoff8");
static_assert(sizeof(uw) == sizeof(void*), "szofword");

//
#include <cstring>
#include <iostream>
#include <tuple>
#include <unordered_map>

//
bool streq(const char *s1, const char *s2)
{
	return std::strcmp(s1, s2) == 0;
}

//
#include "ext/json.h/json.h"
bool json_value_valid(const json_value_s *jsv)
{
	return jsv
		&& jsv->type != json_type_true
		&& jsv->type != json_type_false
		&& jsv->type != json_type_null;
}

struct jstring
{
	char *string;
	uw length;

	jstring(char *string, uw length)
		: string(string), length(length)
	{}
};

struct jsono
{
	enum t
	{
		t_string,
		t_number,
		t_object,
		t_object_elem,
		t_array,
		t_array_elem,
		t_true,
		t_false,
		t_null,
		t_value,
	};

	void *o;
	t type;

	jsono(json_value_s *jsv)
		: o((void*)jsv), type(t_value)
	{}

	jsono(void *o, t type = t_value)
		: o(o), type(type)
	{}

	bool is_string() {return !is_null() && type == t_string;}
	bool is_number() {return !is_null() && type == t_number;}
	bool is_object() {return !is_null() && type == t_object;}
	bool is_object_elem() {return !is_null() && type == t_object_elem;}
	bool is_array() {return !is_null() && type == t_array;}
	bool is_array_elem() {return !is_null() && type == t_array_elem;}
	bool is_true() {return is_value() && ((json_value_s*)o)->type == json_type_true;}
	bool is_false() {return is_value() && ((json_value_s*)o)->type == json_type_false;}
	bool is_null() {return !o || type == t_null;}
	bool is_value() {return !is_null() && type == t_value;}

	uw length()
	{
		if(is_string() || is_number() || is_object() || is_array())
			return ((json_string_s*)o)->string_size;
		else
			return 0;
	}

	jstring string()
	{
		if(is_string())
			return jstring((char*)((json_string_s*)o)->string, length());
		elif(is_number())
			return jstring((char*)((json_number_s*)o)->number, length());
		elif(is_object_elem())
			return jsono((void*)((json_object_element_s*)o)->name, t_string).string();
		else
			return jstring(null, 0);
	}

	f8 number()
	{
		extern f8 atof(const char* str);

		if(is_string() || is_number())
			return atof(string().string);
		else
			return 0.0 / 0.0;
	}

	jsono value()
	{
		if(is_object_elem())
			return jsono((json_value_s*)((json_object_element_s*)o)->value);
		elif(is_array_elem())
			return jsono((json_value_s*)((json_array_element_s*)o)->value);
		elif(is_value())
		{
			json_value_s *jsv = (json_value_s*)o;
			t type;

			if(jsv->type == json_type_string)
				type = t_string;
			elif(jsv->type == json_type_number)
				type = t_number;
			elif(jsv->type == json_type_object)
				type = t_object;
			elif(jsv->type == json_type_array)
				type = t_array;
			elif(jsv->type == json_type_true)
				type = t_true;
			elif(jsv->type == json_type_false)
				type = t_false;
			else
				type = t_null;

			return jsono((void*)jsv->payload, type);
		}
		else
			return jsono((json_value_s*)null);
	}

	jsono payload()
	{
		return value().value();
	}

	bool has_next()
	{
		if(is_object_elem())
			return ((json_object_element_s*)o)->next != null;
		elif(is_array_elem())
			return ((json_array_element_s*)o)->next != null;
		elif(is_object())
			return ((json_object_s*)o)->start != null;
		elif(is_array())
			return ((json_array_s*)o)->start != null;
		else
			return false;
	}

	jsono next()
	{
		if(is_object_elem())
			return jsono((void*)((json_object_element_s*)o)->next, t_object_elem);
		elif(is_array_elem())
			return jsono((void*)((json_array_element_s*)o)->next, t_array_elem);
		elif(is_object())
			return jsono((void*)((json_object_s*)o)->start, t_object_elem);
		elif(is_array())
			return jsono((void*)((json_array_s*)o)->start, t_array_elem);
		else
			return jsono((json_value_s*)null);
	}

	void p(bool comma = false, bool space = false)
	{
		if(comma)
			std::cout << ",";

		if(space)
			std::cout << " ";

		if(is_string())
			std::cout << "\"" << string().string << "\"";
		elif(is_number())
			std::cout << number();
		elif(is_object())
		{
			std::cout << "{";
			if(has_next())
				next().p();
			std::cout << "}";
		}
		elif(is_object_elem())
		{
			std::cout << "\"" << string().string << "\":";
			value().p();
			if(has_next())
				next().p(true, true);
			else
				std::cout << "";
		}
		elif(is_array())
		{
			std::cout << "[";
			if(has_next())
				next().p();
			std::cout << "]";
		}
		elif(is_array_elem())
		{
			value().p();
			if(has_next())
				next().p(true, true);
			else
				std::cout << "";
		}
		elif(is_true())
			std::cout << "true";
		elif(is_false())
			std::cout << "false";
		elif(is_null())
			std::cout << "null";
		elif(is_value())
			value().p();
	}
};

//
void process_args(int argc, const char **argv)
{
	if(argc > 1 && !std::strcmp("--help", argv[1]))
	{
		std::cout << "Help me!" << std::endl;

		return;
	}

	uw arglen = 0;
	for(int i = 1; i < argc; i++)
		arglen += std::strlen(argv[i]);

	if(!arglen)
		return;

	++arglen;
	char *args = new char[arglen];
	for(int i = 1, j = 0; i < argc; i++)
	{
		uw l = std::strlen(argv[i]);
		std::memcpy(args + j, argv[i], l);
		j += l;
	}

	json_value_s *jsv = json_parse((void*)args, arglen - 1);
//	if(!json_value_valid(jsv) || jsv->type != json_type_object)
//		std::cout << "Err." << std::endl;

//	std::cout << (json_object_s)

	std::cout << args << std::endl;
	std::cout << "---------------" << std::endl;
	jsono(jsv).p();
	std::cout << std::endl;
	// {"a":[], "b":{}, "c":1.2, "d":[1, 2, 3, {"4":5}, null, 1, null], "a":null}'
	std::cout
		<< jsono(jsv).value().next().next().next().next().string().string
		<< ":"
		<< jsono(jsv).value().next().next().next().next().payload().next().next().next().payload().number()
		<< std::endl;
}

int main(int argc, const char **argv)
{
	process_args(argc, argv);

	return 0;
}
