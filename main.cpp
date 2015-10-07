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

// udev code was adopted from hidapi https://github.com/signal11/hidapi library
// (c) Alan Ott and licensed under GPLv3, 3-clause BSD or custom hidapi license.
// Please refer to the link provided above for the details.

//
const char config_default[] = R"biteme!(

{
	'comment': 'TODO: Daemon, log redirect.',

	'comment': 'Ordered list of configs, first-found-rest-ignored.',
	'config_paths': ['~/.config/ds4tux.json'],

	'comment': 'Check for config modification and automatically reload it.',
	'config_reload': true,

	'comment': 'List of enabled mappings defined below.',
	'mappings': ['default', 'xbp'],

	'comment': 'Ex. variable definition.',
	'comment': 'DualShock 4 over USB.',
	'var': {'ds4_usb_masq':
		{
			'bus': 'BUS_USB', 'comment': "Actually this is ignored. It's always USB.",
			'vendor': 1356,
			'product': 1476,
			'version': 273
		}},

	'comment': 'Xbox 360 controller.',
	'var': {'xbp_usb_masq':
		{
			'bus': 'BUS_USB',
			'vendor': 1118,
			'product': 654,
			'version': 272
		}},

	'mapping':{'name':'default','for':'ds4'},

	'comment': 'Example default DS4 mapping.',
	'mapping':
	{
		'name': 'default',

		'comment': 'DS3 support, anyone?',
		'for': 'ds4',

		'comment': 'Pretend we are a real thing.',
		'masquerade': {'ref': 'ds4_usb_masq'},

		'group':
		{
			'cond': {'when':'l1 != prev_l1', 'do':'print("--- l1\n")'},
			'cond': {'when':'square', 'do':'0', 'greedy':true},
			'cond': {
				'when':'stick_left_x != prev_stick_left_x | stick_left_y != prev_stick_left_y',
				'do':'print("--- x: " + str(stick_left_x) + " y: " + str(stick_left_y) + "\n")'},
			'cond': {'when':'l2_analog != prev_l2_analog', 'do': 'print("--- l2_analog: " + str(l2_analog) + "\n")'}
		},

		'group':
		{
			'cond': {'when':'l1 & l2 & l1=r1 & l2=r2', 'do':'print("--- l1=r1...\n")'}
		},

		'group':
		{
			'cond': {'when':'battery != prev_battery | usb != prev_usb', 'do':'print("--- battery: " + str((battery*100) / (usb ? 11 : 9)) + "\n")'}
		},

		'comment':
		{
			'when_do': ['l1=r1 & l2=r2', 'print("l1=r1...\n")'],
			'when_do': ['l1 != l1', 'print("l1\n")'],
			'when_do': ['battery < 20', 'print("battery < 20\n")'],
			'when_do': ['l1 != l1', ['post', 'EV_KEY', 'BTN_Y', 'l1']],
			'when_do': ['battery < 20', ['flash', 255, 0, 0, 5, 255]],
			'when_do': ['l1=l1 & l2=l2',
				['exec', 'echo "disconnect (%dev_mac%)" | bluetoothctl']]
		}
	},

	'mapping':{'name':'xbp','for':'ds4'}
}

)biteme!";

//
#if !(defined(linux) || defined(__linux) || defined(__linux__) \
			|| defined(__gnu_linux__))
	#error "Unsupported OS. This is a Linux driver, what are you trying to do?"
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
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>
#include <unordered_map>
//#include <tuple>
#include <functional>

//
#ifdef VERBOSE
	#define verbose(x) x
#else
	#define verbose(x)
#endif

//
template<typename R, typename T>
inline
R scast(T t)
{
	return static_cast<R>(t);
}

template<typename R, typename T>
inline
R rcast(T t)
{
	return reinterpret_cast<R>(t);
}

//
template <typename T, uw N>
constexpr uw arrlen(T(&)[N])
{
	return N;
}

//
bool streq(const char *s1, const char *s2)
{
	return std::strcmp(s1, s2) == 0;
}

bool strstarts(const char *src, const char *starts_with)
{
	return std::strncmp(src, starts_with, std::strlen(starts_with)) == 0;
}

//
struct raii
{
	typedef std::function<void ()> fsig;

	fsig f;

	raii(fsig f) : f(f)
	{
		;
	}

	~raii()
	{
		f();
	}
};

//
struct initialized_helper
{
	bool initialized()
	{
		return _initialized;
	}

	void set_initialized()
	{
		_initialized = true;
	}

	bool destroyed()
	{
		return _destroyed;
	}

	void set_destroyed()
	{
		_destroyed = true;
	}

private:
	bool _initialized = false;
	bool _destroyed = false;
};

//
template<bool convert>
struct _endian
{
	static u1 swap(u1 v)
	{
		return v;
	}

	static s1 swap(s1 v)
	{
		return v;
	}

	static u2 swap(u2 v)
	{
		return !convert ? v :
			(((v >> 8) & 0x00FF) |
			 ((v << 8) & 0xFF00));
	}

	static s2 swap(s2 v)
	{
		return (s2)swap((u2)v);
	}

	static u4 swap(u4 v)
	{
		return !convert ? v :
			(((v >> 24) & 0x000000FF) |
			 ((v >>  8) & 0x0000FF00) |
			 ((v <<  8) & 0x00FF0000) |
			 ((v << 24) & 0xFF000000));
	}

	static s4 swap(s4 v)
	{
		return (s4)swap((u4)v);
	}

	static u8 swap(u8 v)
	{
		return !convert ? v :
			(((u8)swap((u4)(v >> 32))) |
			 ((u8)swap((u4)(v & 0xFFFFFFFF)) << 32));
	}

	static s8 swap(s8 v)
	{
		return (s8)swap((u8)v);
	}

	static f4 swap(f4 v)
	{
		if(!t(convert))
			return v;

		f4 r;
		byte *floatToConvert = (byte*)&v;
		byte *returnFloat    = (byte*)&r;

		returnFloat[0] = floatToConvert[3];
		returnFloat[1] = floatToConvert[2];
		returnFloat[2] = floatToConvert[1];
		returnFloat[3] = floatToConvert[0];

		return r;
	}

	static f8 swap(f8 v)
	{
		if(!t(convert))
			return v;

		f8 r;
		byte *floatToConvert = (byte*)&v;
		byte *returnFloat    = (byte*)&r;

		returnFloat[0] = floatToConvert[7];
		returnFloat[1] = floatToConvert[6];
		returnFloat[2] = floatToConvert[5];
		returnFloat[3] = floatToConvert[4];
		returnFloat[4] = floatToConvert[3];
		returnFloat[5] = floatToConvert[2];
		returnFloat[6] = floatToConvert[1];
		returnFloat[7] = floatToConvert[0];

		return r;
	}

private:
	// Workaround on "warning C4127: conditional expression is constant".
	static bool t(bool v)
	{
		return v;
	}
};

struct endian
{
	#define _bo_be 0
	#define _bo_le 0

	#if defined(i386) || defined(__i386) || defined(__i386__) \
			|| defined(__i486__) || defined(__i586__) || defined(__i686__) \
			|| defined(__IA32__) || defined(_M_I386) || defined(__X86__) \
			|| defined(_X86_) || defined(__THW_INTEL__) || defined(__I86__) \
			|| defined(__INTEL__) || defined(__386) || defined(__x86_64) \
			|| defined(__x86_64__) || defined(__amd64) || defined(__amd64__ ) \
			|| defined(_M_X64) || defined(_M_AMD64) || defined(__LITTLE_ENDIAN__) \
			|| defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) \
			|| (defined(TARGET_RT_LITTLE_ENDIAN ) && TARGET_RT_LITTLE_ENDIAN)
		#undef _bo_le
		#define _bo_le 1

	#elif defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__THUMBEB__) \
				|| defined(__AARCH64EB__) \
				|| (defined(TARGET_RT_BIG_ENDIAN ) && TARGET_RT_BIG_ENDIAN)
		#undef _bo_be
		#define _bo_be 1

	#else
		#error "Unknown endianness."
	#endif

	// Always swap.
	typedef _endian<true> forced;

	// From BE to native.
	typedef _endian<(bool)_bo_le> frombe;
	// From LE to native.
	typedef _endian<(bool)_bo_be> fromle;

	// From native to BE.
	typedef _endian<(bool)_bo_le> tobe;
	// From native to LE.
	typedef _endian<(bool)_bo_be> tole;
};

//
#include <time.h>

void sleep_ms(u8 ms)
{
	timespec ts;
	ts.tv_sec = ms >= 1000 ? ms / 1000 : 0;
	ts.tv_nsec = (ms % 1000) * 1000000;
	nanosleep(&ts, null);
}

u8 now()
{
	timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	return (ts.tv_sec * 1000000000) + (ts.tv_nsec);
}

u8 now_ms()
{
	return now() / 1000000;
}

u8 stopwatch(u8 &initial)
{
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	u8 raw = (ts.tv_sec * 1000000000) + (ts.tv_nsec);

	if(!initial)
		initial = raw;

	return raw - initial;
}

u8 stopwatch_us(u8 &initial)
{
	return stopwatch(initial) / 1000;
}

u8 stopwatch_ms(u8 &initial)
{
	return stopwatch(initial) / 1000000;
}

u8 stopwatch_sec(u8 &initial)
{
	return stopwatch(initial) / 1000000000;
}

//
//#include <linux/hidraw.h>
#include <linux/input.h>
#include <libudev.h>

struct myudev : public initialized_helper
{
	udev *udevh;
	udev_monitor *mon;
	int mon_fd;

	struct dev_info
	{
		bool usb, bt;
		u2 vid;
		u2 pid;
		std::string serial;
		std::string name;
		std::string dev_node;
		std::string input_node;
		std::string event_node;

		// USB additional info.
		std::string manufacturer;
		std::string product;
		long int release_number;
		long int interface_number;
	};

	typedef std::function<void (dev_info)> on_dev_change_sig;

	bool init()
	{
		udevh = udev_new();
		if(!udevh)
			return false;

		mon = udev_monitor_new_from_netlink(udevh, "udev");
		if(!mon)
			return false;

		udev_monitor_filter_add_match_subsystem_devtype(mon, "hidraw", null);
		udev_monitor_enable_receiving(mon);
		mon_fd = udev_monitor_get_fd(mon);

		return true;
	}

	dev_info get_dev_info(udev_device *raw_dev)
	{
		//
		int bus_type;
		u2 dev_vid;
		u2 dev_pid;
		const char *dev_path = null;
		char *serial_number_utf8 = null;
		char *product_name_utf8 = null;
		dev_info di;

		udev_device *hid_dev = null;
		const char *hid_path = null;
		const char *uevent = null;

		udev_device *input_dev = null;
		const char *input_path = null;
		udev_device *event_dev = null;
		const char *event_path = null;

		(void)hid_path;

		auto get_siblings =
			[this](udev_device *hidraw, const char *clazz) -> udev_device*
			{
				udev_device *p = udev_device_get_parent_with_subsystem_devtype(
					hidraw, "hid", null);
				auto p_path = udev_device_get_devpath(p);

				udev_enumerate *uenum;
				uenum = udev_enumerate_new(udevh);
				udev_enumerate_add_match_subsystem(uenum, "input");
				udev_enumerate_scan_devices(uenum);
				udev_list_entry *devices = udev_enumerate_get_list_entry(uenum);
				udev_list_entry *dev_list_entry;
				udev_list_entry_foreach(dev_list_entry, devices)
				{
					const char *sysfs_path = null;
					udev_device *raw_dev = null;
					const char *i_path = null;
					const char *i_name;

					udev_device *input_parent = null;

					sysfs_path = udev_list_entry_get_name(dev_list_entry);
					raw_dev = udev_device_new_from_syspath(udevh, sysfs_path);
					if(!raw_dev)
						goto next_;

					i_name = udev_device_get_sysname(raw_dev);
					if(!strstarts(i_name, clazz))
						goto next_;

					input_parent = udev_device_get_parent_with_subsystem_devtype(
								raw_dev, "hid", null);
					if(!input_parent)
						goto next_;

					i_path = udev_device_get_devpath(input_parent);
					if(i_path && streq(i_path, p_path))
						return raw_dev;

				next_:
					if(raw_dev)
						udev_device_unref(raw_dev);
				}

				udev_enumerate_unref(uenum);

				return null;
			};

		//
		dev_path = udev_device_get_devnode(raw_dev);

		hid_dev = udev_device_get_parent_with_subsystem_devtype(
			raw_dev, "hid", null);
		if(!hid_dev)
			goto next;
		hid_path = udev_device_get_devnode(hid_dev);

		input_dev = get_siblings(raw_dev, "js");
		if(!input_dev)
			goto next;
		input_path = udev_device_get_devnode(input_dev);

		event_dev = get_siblings(raw_dev, "event");
		if(!event_dev)
			goto next;
		event_path = udev_device_get_devnode(event_dev);

		uevent = udev_device_get_sysattr_value(hid_dev, "uevent");
		{
			char *tmp = strdup(uevent);
			char *saveptr = null;
			char *line;
			char *key;
			char *value;

			int found_id = 0;
			int found_serial = 0;
			int found_name = 0;

			extern char *strtok_r(char *str, const char *delim, char **saveptr);
			extern char *strdup(const char *s);
			extern char * strchr(char *str, int character);

			line = strtok_r(tmp, "\n", &saveptr);
			while(line)
			{
				/* line: "KEY=value" */
				key = line;
				value = strchr(line, '=');
				if(!value)
					goto next_line;

				*value = '\0';
				value++;

				if(streq(key, "HID_ID"))
				{
					/**
					*        type vendor   product
					* HID_ID=0003:000005AC:00008242
					**/
					int ret = std::sscanf(value, "%x:%hx:%hx",
						&bus_type, &dev_vid, &dev_pid);
					if(ret == 3)
						found_id = 1;
				}
				elif(streq(key, "HID_UNIQ"))
				{
					/* The caller has to free the serial number */
					serial_number_utf8 = strdup(value);
					found_serial = 1;
				}
				elif(streq(key, "HID_NAME"))
				{
					/* The caller has to free the product name */
					product_name_utf8 = strdup(value);
					found_name = 1;
				}

			next_line:
				line = strtok_r(null, "\n", &saveptr);
			}

			std::free(tmp);

			if(!found_id || !found_name || !found_serial
				 || (bus_type != BUS_USB && bus_type != BUS_BLUETOOTH))
				goto next;
		}

		verbose(std::cout << "udev.get_dev_info(): device:"
			<< std::hex << " '0x" << dev_vid << "' '0x" << dev_pid << "'" << std::dec
			<< " '" << serial_number_utf8 << "'"
			<< " '" << product_name_utf8 << "'"
			<< std::endl);

		switch(bus_type)
		{
			case BUS_USB:
			{
				/* The device pointed to by raw_dev contains information about
				the hidraw device. In order to get information about the
				USB device, get the parent device with the
				subsystem/devtype pair of "usb"/"usb_device". This will
				be several levels up the tree, but the function will find
				it. */
				udev_device *usb_dev = udev_device_get_parent_with_subsystem_devtype(
					raw_dev, "usb", "usb_device");

				if(!usb_dev)
					goto next;

				const char *manufacturer = udev_device_get_sysattr_value(usb_dev,
					"manufacturer");
				const char *product = udev_device_get_sysattr_value(usb_dev,
					"product");

				const char *release_number = udev_device_get_sysattr_value(usb_dev,
					"bcdDevice");
				long int release_num = release_number ?
					std::strtol(release_number, null, 16) : 0x0;

				long int interface_number = 0;
				udev_device *intf_dev = udev_device_get_parent_with_subsystem_devtype(
					raw_dev, "usb", "usb_interface");
				if(intf_dev)
				{
					const char *bin = udev_device_get_sysattr_value(
						intf_dev, "bInterfaceNumber");
					interface_number = bin ? std::strtol(bin, null, 16) : -1;
				}

				di = (dev_info)
					{true, false, dev_vid, dev_pid
					, std::string(serial_number_utf8), std::string(product_name_utf8)
					, std::string(dev_path)
//					, std::string(hid_path)
					, std::string(input_path), std::string(event_path)
					, std::string(manufacturer), std::string(product)
					, release_num, interface_number};

				break;
			}

			case BUS_BLUETOOTH:
			{
				di = (dev_info)
					{false, true, dev_vid, dev_pid
					, std::string(serial_number_utf8), std::string(product_name_utf8)
					, std::string(dev_path)
//					, std::string(hid_path)
					, std::string(input_path), std::string(event_path)
					, "", ""
					, 0, 0};

				break;
			}

			default: break;
		}

	next:
		if(serial_number_utf8)
			std::free(serial_number_utf8);

		if(product_name_utf8)
			std::free(product_name_utf8);

//		if(raw_dev)
//			udev_device_unref(raw_dev);
		/* hid_dev, usb_dev and intf_dev don't need to be (and can't be)
		unref()d.  It will cause a double-free() error.  I'm not
		sure why.  */

		return di;
	}

	void poll_initial(on_dev_change_sig on_dev_add)
	{
		verbose(std::cout << "poll_initial()" << std::endl);

		udev_enumerate *uenum;
		uenum = udev_enumerate_new(udevh);
		udev_enumerate_add_match_subsystem(uenum, "hidraw");
		udev_enumerate_scan_devices(uenum);
		udev_list_entry *devices = udev_enumerate_get_list_entry(uenum);
		udev_list_entry *dev_list_entry;
		udev_list_entry_foreach(dev_list_entry, devices)
		{
			const char *sysfs_path = null;
			udev_device *raw_dev = null;

			sysfs_path = udev_list_entry_get_name(dev_list_entry);
			raw_dev = udev_device_new_from_syspath(udevh, sysfs_path);
			if(!raw_dev)
				goto next;
			else
			{
				dev_info di = get_dev_info(raw_dev);

				on_dev_add(di);
			}

		next:
			if(raw_dev)
				udev_device_unref(raw_dev);
		}

		udev_enumerate_unref(uenum);

		verbose(std::cout << "poll_initial(): done" << std::endl);
	}

	void poll(on_dev_change_sig on_dev_add, on_dev_change_sig on_dev_rem)
	{
		if(!initialized())
			poll_initial(on_dev_add), set_initialized();

		fd_set fds;
		timeval tv;

		FD_ZERO(&fds);
		FD_SET(mon_fd, &fds);
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		int ret = select(mon_fd + 1, &fds, null, null, &tv);

		if(ret > 0 && FD_ISSET(mon_fd, &fds))
		{
			verbose(std::cout << "udev.poll(): got something" << std::endl);

			udev_device *dev = udev_monitor_receive_device(mon);
			if(!dev)
				return;

			dev_info di = get_dev_info(dev);
			const char *act = udev_device_get_action(dev);
			if(streq(act, "add"))
				on_dev_add(di);
			elif(streq(act, "remove"))
				// TODO: ?
				di.dev_node = std::string(udev_device_get_devnode(dev)), on_dev_rem(di);

			udev_device_unref(dev);
		}
	}

	void destroy()
	{
		if(destroyed())
			return;

		verbose(std::cout << "myudev.destroy()" << std::endl);

		if(mon)
			udev_monitor_unref(mon), mon = null;

		if(udevh)
			udev_unref(udevh), udevh = null;

		set_destroyed();
	}

	~myudev()
	{
		destroy();
	}
};

//
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <cerrno>

#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>

struct uinput
{
	;
};

//
struct device_reading
{
	const char *const name;
	const std::function<s8 (byte*)> reader;
	s8 val = 0;
	s8 prev = 0;

	device_reading(const char *name, std::function<s8 (const byte *const)> reader)
		: name(name), reader(reader)
	{
		;
	}

	s8 read(byte *buf)
	{
		prev = val;
		val = reader(buf);

		return val;
	}

private:
	device_reading& operator=(device_reading const&);
};

//
struct device;

struct expr : public initialized_helper
{
	virtual s8 eval(device &d) = 0;

	virtual ~expr()
	{
		set_destroyed();
	}
};

//
struct mapping : public initialized_helper
{
	struct cond : public initialized_helper
	{
		expr *when = null;
		expr *d0 = null;
		const bool greedy = false;

		cond(expr *when, expr *d0, bool greedy)
			: when(when), d0(d0), greedy(greedy)
		{
			set_initialized();
		}

		~cond()
		{
			if(!initialized() || destroyed())
				return;

			set_destroyed();

			delete when, when = null;
			delete d0, d0 = null;
		}
	};

	struct group : public initialized_helper
	{
		std::vector<cond*> conditions;

		group(std::vector<cond*> conditions)
			: conditions(conditions)
		{
			set_initialized();
		}

		~group()
		{
			if(!initialized() || destroyed())
				return;

			set_destroyed();

			for(auto i : conditions)
				delete i;
		}
	};

	std::vector<group*> groups;

	mapping(std::vector<group*> groups)
		: groups(groups)
	{
		set_initialized();
	}

	~mapping()
	{
		if(!initialized() || destroyed())
			return;

		set_destroyed();

		for(auto i : groups)
			delete i;
	}
};

//
struct device : public initialized_helper
{
	myudev::dev_info devinfo;
	std::vector<mapping*> mappings;
	mapping *current_mapping = null;

	device()
	{
		devinfo = {false, false, 0, 0, std::string(""), std::string("")
			, std::string(""), std::string(""), std::string(""), "", "", 0, 0};
	}

	device(myudev::dev_info devinfo, std::vector<mapping*> &mappings)
		: devinfo(devinfo), mappings(mappings)
	{
		if(mappings.size())
			current_mapping = mappings[0];
	}

	virtual bool init() = 0;

	virtual device_reading& get_reading(uw index) = 0;

	virtual void readings_iterate(std::function<bool (device_reading&, uw)> f) = 0;

	sw reading_index(const char *name)
	{
		sw i = -1;

		readings_iterate(
			[&i, name](device_reading &d, uw index)
			{
				if(streq(d.name, name))
				{
					i = (sw)index;

					return true;
				}
				else
					return false;
			});

		return i;
	}

	std::string id()
	{
		return devinfo.dev_node;
	}

	virtual void readings_read() = 0;

	void tick()
	{
		readings_read();

		if(!current_mapping || !current_mapping->groups.size())
			return;

		mapping::group **g = &current_mapping->groups[0];
		for(uw i = 0; i < current_mapping->groups.size(); i++)
		{
			mapping::cond **c = &g[i]->conditions[0];
			for(uw j = 0; j < g[i]->conditions.size(); j++)
				if(c[j]->when->eval(*this))
				{
					c[j]->d0->eval(*this);

					if(c[j]->greedy)
						break;
				}
		}
	}

	virtual ~device()
	{
		;
	}
};

//
struct ds4_device : public device
{
	int devfd = -1;
	int eventfd = -1;
	libevdev *eventdev = null;

	// I honestly did try to do this "more" in compile time,
	// making device a variadic base data type and avoiding using macros.
	// Oh well, good enough.
	device_reading readings[34 /* Fuck you, C++. */] =
	{
		{"stick_left_x", [](const byte *const buf){return buf[1];}},
		{"stick_left_y", [](const byte *const buf){return buf[2];}},
		{"stick_right_x", [](const byte *const buf){return buf[3];}},
		{"stick_right_y", [](const byte *const buf){return buf[4];}},
		{"l2_analog", [](const byte *const buf){return buf[8];}},
		{"r2_analog", [](const byte *const buf){return buf[9];}},
		{"dpad_up", [](const byte *const buf){return buf[5] == 0 || buf[5] == 1 || buf[5] == 7;}},
		{"dpad_down", [](const byte *const buf){return buf[5] == 3 || buf[5] == 4 || buf[5] == 5;}},
		{"dpad_left", [](const byte *const buf){return buf[5] == 5 || buf[5] == 6 || buf[5] == 7;}},
		{"dpad_right", [](const byte *const buf){return buf[5] == 1 || buf[5] == 2 || buf[5] == 3;}},
		{"cross", [](const byte *const buf){return (buf[5] & 32) != 0;}},
		{"circle", [](const byte *const buf){return (buf[5] & 64) != 0;}},
		{"square", [](const byte *const buf){return (buf[5] & 16) != 0;}},
		{"triangle", [](const byte *const buf){return (buf[5] & 128) != 0;}},
		{"l1", [](const byte *const buf){return (buf[6] & 1) != 0;}},
		{"l2", [](const byte *const buf){return (buf[6] & 4) != 0;}},
		{"l3", [](const byte *const buf){return (buf[6] & 64) != 0;}},
		{"r1", [](const byte *const buf){return (buf[6] & 2) != 0;}},
		{"r2", [](const byte *const buf){return (buf[6] & 8) != 0;}},
		{"r3", [](const byte *const buf){return (buf[6] & 128) != 0;}},
		{"share", [](const byte *const buf){return (buf[6] & 16) != 0;}},
		{"options", [](const byte *const buf){return (buf[6] & 32) != 0;}},
		{"trackpad", [](const byte *const buf){return (buf[7] & 2) != 0;}},
		{"ps", [](const byte *const buf){return (buf[7] & 1) != 0;}},
		{"trackpad_touch0_id", [](const byte *const buf){return buf[35] & 0x7F;}},
		{"trackpad_touch0_active", [](const byte *const buf){return (buf[35] >> 7) == 0;}},
		{"trackpad_touch0_x", [](const byte *const buf){return ((buf[37] & 0x0F) << 8) | buf[36];}},
		{"trackpad_touch0_y", [](const byte *const buf){return buf[38] << 4 | ((buf[37] & 0xF0) >> 4);}},
		{"trackpad_touch1_id", [](const byte *const buf){return buf[39] & 0x7F;}},
		{"trackpad_touch1_active", [](const byte *const buf){return (buf[39] >> 7) == 0;}},
		{"trackpad_touch1_x", [](const byte *const buf){return ((buf[41] & 0x0F) << 8) | buf[40];}},
		{"trackpad_touch1_y", [](const byte *const buf){return buf[42] << 4 | ((buf[41] & 0xF0) >> 4);}},
		{"battery", [](const byte *const buf){return buf[30] % 16;}},
		{"usb", [](const byte *const buf){return (buf[30] & 16) != 0;}},
	};

	ds4_device() : device()
	{
		;
	}

	ds4_device(myudev::dev_info devinfo, std::vector<mapping*> &mappings)
		: device(devinfo, mappings)
	{
		;
	}

	int report_size()
	{
		if(devinfo.usb)
			return 64;
		elif(devinfo.bt)
			return 78;
		else
			return 0;
	}

	byte valid_report_id()
	{
		if(devinfo.usb)
			return 0x01;
		elif(devinfo.bt)
			return 0x11;
		else
			return 0;
	}

	int read_feature_report(byte report_id, unsigned long size)
	{
		if(!initialized() || destroyed())
			return EBADF;

		const unsigned long IOC_RW = 3221243904;
		auto HIDIOCSFEATURE = [](unsigned long size) {return IOC_RW|(0x06 << 0)|(size << 16);};
		auto HIDIOCGFEATURE = [](unsigned long size) {return IOC_RW|(0x07 << 0)|(size << 16);};
		(void)HIDIOCSFEATURE;

		auto op = HIDIOCGFEATURE(size + 1);
		byte buf[size + 1];
		buf[0] = report_id;

		return ioctl(devfd, op, buf);
	}

	void set_operational()
	{
		if(!initialized() || destroyed())
			return;

		if(devinfo.usb)
			read_feature_report(0x02, 37);
		else
			read_feature_report(0x81, 6);
	}

	bool init() override
	{
		if(initialized() || destroyed())
			return true;

		verbose(std::cout << "ds4_device init" << std::endl);

		raii res(
			[this]()
			{
				if(initialized() || destroyed())
					return;

				destroy();
			}); (void)res;

		devfd = open(devinfo.dev_node.c_str(), O_RDWR | O_NONBLOCK);
		if(devfd == -1)
		{
			std::cout << "Open devfd: " << errno << " " << strerror(errno)
				<< ". Please check your udev rules." << std::endl;

			return false;
		}

		eventfd = open(devinfo.event_node.c_str(), O_RDONLY | O_NONBLOCK);
		if(eventfd == -1)
		{
			std::cout << "Open eventfd: " << errno << " " << strerror(errno)
				<< std::endl;

			return false;
		}

		if(libevdev_new_from_fd(eventfd, &eventdev) < 0)
			return false;

		if(libevdev_grab(eventdev, LIBEVDEV_GRAB))
			return false;

		set_initialized();

		set_operational();

		return true;
	}

	device_reading& get_reading(uw index) override
	{
		return readings[index];
	}

	void readings_iterate(std::function<bool (device_reading&, uw)> f) override
	{
		for(uw i = 0; i < arrlen(readings); i++)
			if(f(readings[i], i))
				break;
	}

	void write_report(byte report_id, byte *data, int size)
	{
		if(!initialized() || destroyed())
			return;

		byte buf[size + 1];
		buf[0] = report_id;
		std::memcpy(buf + 1, data, size);
		write(devfd, buf, size + 1);
	}

	void control()
	{
		byte pkt[77];

		int offset;
		byte report_id;
		if(devinfo.usb)
		{
			offset = 0;
			report_id = 0x05;
			pkt[0] = 0xFF;
		}
		else
		{
			offset = 2;
			report_id = 0x11;
			pkt[0] = 128;
			pkt[2] = 0xFF;
		}

		// Small and big rumble, max 255.
		pkt[offset + 3] = 0;
		pkt[offset + 4] = 0;

		// LED RGB.
		pkt[offset + 5] = 50;
		pkt[offset + 6] = 0;
		pkt[offset + 7] = 0;

		// Flash on and off duration, where 255 = 2.5s.
		pkt[offset + 8] = 5;
		pkt[offset + 9] = 255;

		if(devinfo.usb)
			write_report(report_id, pkt, 31);
		else
			write_report(report_id, pkt, 77);
	}

	void readings_read() override
	{
		if(!initialized() || destroyed())
			return;

		byte buf[report_size()];
		int r = read(devfd, buf, report_size());

		if(r < report_size() || buf[0] != valid_report_id())
			return;

		for(uw i = 0; i < arrlen(readings); i++)
			readings[i].read(devinfo.usb ? buf : buf + 2);
	}

	void destroy()
	{
		if(!initialized() || destroyed())
			return;

		verbose(std::cout << "ds4_device.destroy() of " << devinfo.dev_node
			<< std::endl);

		if(devfd != -1)
			close(devfd), devfd = -1;

		if(eventdev)
		{
			libevdev_grab(eventdev, LIBEVDEV_UNGRAB);

			libevdev_free(eventdev);

			eventdev = null;
		}

		if(eventfd != -1)
			close(eventfd), eventfd = -1;

		set_destroyed();
	}

	virtual ~ds4_device()
	{
		destroy();
	}

	static bool is_ds4(int vid, int pid, const char *name)
	{
		(void)name;

		return vid == 0x054C && pid == 0x05C4;
	}
};

//
#include <cctype>

struct expr_parser
{
	struct expr_anon : public expr
	{
		std::function<s8 (device&)> f;

		expr_anon(std::function<s8 (device&)> f) : f(f)
		{
			;
		}

		s8 eval(device &d) override
		{
			return f(d);
		}

		virtual ~expr_anon()
		{
			set_destroyed();
		}
	};

	struct expr_unary : public expr
	{
		expr &right;

		std::function<s8 (expr &right, device&)> f;

		expr_unary(expr &right, std::function<s8 (expr &right, device&)> f)
			: right(right), f(f)
		{
			;
		}

		s8 eval(device &d) override
		{
			return f(right, d);
		}

		virtual ~expr_unary()
		{
			if(destroyed())
				return;

			set_destroyed();

			delete &right;
		}
	};

	struct expr_binary : public expr
	{
		expr &left;
		expr &right;

		std::function<s8 (expr &left, expr &right, device&)> f;

		expr_binary(expr &left, expr &right, std::function<s8 (expr &left, expr &right, device&)> f)
			: left(left), right(right), f(f)
		{
			;
		}

		s8 eval(device &d) override
		{
			return f(left, right, d);
		}

		virtual ~expr_binary()
		{
			if(destroyed())
				return;

			set_destroyed();

			delete &left;
			delete &right;
		}
	};

	struct expr_ternary : public expr
	{
		expr &left;
		expr &right;
		expr &ternary;

		std::function<s8 (expr &left, expr &right, expr &ternary, device&)> f;

		expr_ternary(expr &left, expr &right, expr &ternary, std::function<s8 (expr &left, expr &right, expr &ternary, device&)> f)
			: left(left), right(right), ternary(ternary), f(f)
		{
			;
		}

		s8 eval(device &d) override
		{
			return f(left, right, ternary, d);
		}

		virtual ~expr_ternary()
		{
			if(destroyed())
				return;

			set_destroyed();

			delete &left;
			delete &right;
			delete &ternary;
		}
	};

	// Ugh... Learn proper move semantics or something?
	template<uw N>
	struct expr_func : public expr
	{
		expr *arr[N] = {0};

		std::function<s8 (expr *arr[N], device&)> f;

		s8 eval(device &d) override
		{
			return f(arr, d);
		}

		virtual ~expr_func()
		{
			if(destroyed())
				return;

			set_destroyed();

			for(uw i = 0; i < N; i++)
				delete arr[i], arr[i] = 0;
		}
	};

	struct tok
	{
		char sepa;
		std::string symbol;
		s8 num;

		tok(char sepa, std::string symbol, s8 num)
			: sepa(sepa), symbol(symbol), num(num)
		{
			;
		}

		bool is_sepa()
		{
			return sepa && sepa != 0x1A;
		}

		bool is_symbol()
		{
			return symbol.length();
		}

		bool is_num()
		{
			return sepa == 0x1A;
		}
	};

	enum class precedence : int
	{
		semicolon = 1,
		condition,
		logic_or,
		logic_and,
		relational_eq_ne,
		relational_gt_lt,
		add_sub,
		mul_div,
		prefix,
	};

	static expr* parse(const char *input, device &dev)
	{
		return expr_parser(input, dev).parse();
	}

	const char *input;
	const uw input_len;

	device &dev;

	uw lex_idx = 0;

	expr_parser(const char *input, device &dev)
		: input(input), input_len(std::strlen(input)), dev(dev)
	{
		;
	}

	tok lex_next()
	{
		while(lex_idx < input_len)
		{
			char c = input[lex_idx++];

			if(c == '(' || c == ')' || c == '=' || c == '+' || c == '-'
					|| c == '*' || c == '/' || c == '%' || c == '!'
					|| c == '?' || c == ':' || c == '>' || c == '<' || c == '&'
					|| c == '|' || c == '\'' || c == '\"' || c == ';')
				return {c, std::string(), 0};
			elif(std::isalpha(c))
			{
				uw start = lex_idx - 1;
				while(lex_idx < input_len)
					if(!std::isalnum(input[lex_idx]) && input[lex_idx] != '_')
						break;
					else
						++lex_idx;

				return tok('\0', std::string(input + start, lex_idx - start), 0);
			}
			elif(std::isdigit(c))
			{
				uw start = lex_idx - 1;
				while(lex_idx < input_len)
					if(!std::isdigit(input[lex_idx]))
						break;
					else
						++lex_idx;

				return tok(0x1A, std::string()
					, std::stoll(std::string(input + start, lex_idx - start)));
			}
		}

		return tok(0, std::string(), 0);
	}

	tok consume()
	{
		return lex_next();
	}

	tok lookahead(uw level = 1)
	{
		uw lex_idx = this->lex_idx;
		tok t(0, "", 0);
		while(level--)
			t = lex_next();
		this->lex_idx = lex_idx;

		return t;
	}

	int get_precedence_infix()
	{
		char c = lookahead().sepa;

		if(false)
			;

		elif(c == ';')
			return scast<int>(precedence::semicolon);

		elif(c == '?')
			return scast<int>(precedence::condition);

		elif(c == '|')
			return scast<int>(precedence::logic_or);

		elif(c == '&')
			return scast<int>(precedence::logic_and);

		elif(c == '=' || (c == '!' && lookahead(2).sepa == '='))
			return scast<int>(precedence::relational_eq_ne);

		elif((c == '>' && lookahead(2).sepa == '=')
				|| (c == '<' && lookahead(2).sepa == '=')
				|| c == '>' || c == '<')
			return scast<int>(precedence::relational_gt_lt);

		elif(c == '+' || c == '-')
			return scast<int>(precedence::add_sub);

		elif(c == '*' || c == '/' || c == '%')
			return scast<int>(precedence::mul_div);

		return -1;
	}

	expr* parse(int precedence, bool nothrow = false)
	{
		tok t = consume();

		expr *left = null;
		expr *right = null;
		expr *ternary = null;

		bool left_string = false;

		bool failure = true;
		raii res(
			[&]()
			{
				if(!failure)
					return;

				if(left) {delete left; left = null; return;}
				if(ternary) delete ternary, ternary = null;
				if(right) delete right, right = null;
			}); (void)res;

		char c = t.sepa;

		//
		if(false)
			;

		elif(t.is_sepa() && c == '(')
		{
			left = parse();

			if((t = consume()).sepa != ')')
				throw std::string("expr_parser: can't parse parens: expected ')'.");
		}
		elif(t.is_sepa() && c == '+')
		{
			right = parse(scast<int>(expr_parser::precedence::prefix));
			left = new expr_unary(*right,
				[](expr &right, device &d){return std::abs(right.eval(d));});
		}
		elif(t.is_sepa() && c == '-')
		{
			right = parse(scast<int>(expr_parser::precedence::prefix));
			left = new expr_unary(*right,
				[](expr &right, device &d){return -right.eval(d);});
		}
		elif(t.is_sepa() && c == '!')
		{
			right = parse(scast<int>(expr_parser::precedence::prefix));
			left = new expr_unary(*right,
				[](expr &right, device &d){return !right.eval(d);});
		}

		elif(t.is_symbol())
		{
			//
			std::string name = t.symbol;

			if(lookahead().sepa == '(')
			{
				t = consume();

				if(false)
					;

				elif(!name.compare("str"))
				{
					right = parse();
					left = new expr_unary(*right,
						[](expr &right, device &d)
						{
							s8 e = right.eval(d);
							std::string &s = *(new std::string(std::to_string(e)));

							return (s8)&s;
						});
				}

				elif(!name.compare("print"))
				{
					right = parse();
					left = new expr_unary(*right,
						[](expr &right, device &d)
						{
							std::string &s = *(std::string*)right.eval(d);
							std::cout << s;
							delete &s;

							return 1;
						});
				}

				elif(!name.compare("exec"))
				{
					right = parse();
					left = new expr_unary(*right,
						[](expr &right, device &d)
						{
							std::string &s = *(std::string*)right.eval(d);
							int r = std::system(s.c_str());
							delete &s;

							return r;
						});
				}

				elif(!name.compare("now"))
				{
					left = new expr_anon(
						[](device&)
						{
							return (s8)now_ms();
						});
				}

				elif(!name.compare("led_rgb"))
				{
					auto *f = new expr_func<3>();
					left = f;
					f->arr[0] = parse(0, true);
					f->arr[1] = parse(0, true);
					f->arr[2] = parse(0, true);

					if(!f->arr[0] || !f->arr[1] || !f->arr[2])
						throw
							std::string("expr_parser: call to led_rgb(r g b): expected 3 arguments.");

					f->f =
						[](expr *arr[], device &d)
						{
							std::cout << "led_rgb("
								<< arr[0]->eval(d) << " "
								<< arr[1]->eval(d) << " "
								<< arr[2]->eval(d) << ")\n";

							return 1;
						};
				}

				elif(!name.compare("led_flash"))
				{
					auto *f = new expr_func<2>();
					left = f;
					f->arr[0] = parse(0, true);
					f->arr[1] = parse(0, true);

					if(!f->arr[0] || !f->arr[1])
						throw
							std::string("expr_parser: call to led_flash(on off): expected 2 arguments.");

					f->f =
						[](expr *arr[], device &d)
						{
							std::cout << "led_flash("
								<< arr[0]->eval(d) << " "
								<< arr[1]->eval(d) << ")\n";

							return 1;
						};
				}

				else
					throw "expr_parser: call to undefined function '" + name + "'.";

				if((t = consume()).sepa != ')')
					throw "expr_parser: can't parse function call: expected ')' after '"
						+ name + "(...'.";
			}

			//
			else
			{
				bool prev_val = strstarts(t.symbol.c_str(), "prev_");

				sw reading_idx =
					dev.reading_index(prev_val ? t.symbol.c_str() + 5 : t.symbol.c_str());

				if(reading_idx == -1)
					throw "expr_parser: unknown device reading: '" + t.symbol + "'.";

				if(!prev_val)
					left = new expr_anon([reading_idx](device &d)
						{return d.get_reading(reading_idx).val;});
				else
					left = new expr_anon([reading_idx](device &d)
						{return d.get_reading(reading_idx).prev;});
			}
		}

		elif(t.is_num())
		{
			s8 num = t.num;

			left = new expr_anon([num](device&){return num;});
		}

		elif(t.is_sepa() && (c == '\'' || c == '\"'))
		{
			char buf[input_len - lex_idx /* Stfu. */];
			char *tmp = buf;

			while(lex_idx < input_len)
			{
				char h = input[lex_idx++];
				if(h == c)
					break;

				if(h == '\\' && lex_idx < input_len)
					if(input[lex_idx] == '\\')
						h = '\\', ++lex_idx;
					elif(input[lex_idx] == '\'')
						h = '\'', ++lex_idx;
					elif(input[lex_idx] == '\"')
						h = '\"', ++lex_idx;
					elif(input[lex_idx] == 't')
						h = '\t', ++lex_idx;
					elif(input[lex_idx] == 'r')
						h = '\r', ++lex_idx;
					elif(input[lex_idx] == 'n')
						h = '\n', ++lex_idx;

				*tmp = h;
				++tmp;
			}

			*tmp = '\0';

			std::string res(buf);
			left = new expr_anon([res](device&){return (s8)new std::string(res);});
			left_string = true;
		}

		elif(!nothrow)
			throw std::string("expr_parser: can't parse lhs.");
		else
			return null;

		//
		while(precedence < get_precedence_infix())
		{
			t = consume();
			char c = t.sepa;

			if(false)
				;

			elif(c == ';')
			{
				right = parse(0, true);

				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d)
					{
						s8 r = left.eval(d);

						return &right ? right.eval(d) : r;
					});
			}

			elif(c == '?')
			{
				// Then.
				right = parse();

				if((t = consume()).sepa != ':')
					throw
						std::string("expr_parser: can't parse ternary conditional: expected ':'"
							" after 'then'.");

				// Else.
				// Right associative.
				ternary = parse(scast<int>(expr_parser::precedence::condition) - 1);

				left = new expr_ternary(*left, *right, *ternary,
					[](expr &left, expr &right, expr &ternary, device &d){return (left.eval(d) ? right.eval(d) : ternary.eval(d));});
			}

			elif(c == '|')
			{
				right = parse(scast<int>(expr_parser::precedence::logic_or));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) || right.eval(d);});
			}
			elif(c == '&')
			{
				right = parse(scast<int>(expr_parser::precedence::logic_and));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) && right.eval(d);});
			}

			elif(c == '=')
			{
				right = parse(scast<int>(expr_parser::precedence::relational_eq_ne));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) == right.eval(d);});
			}
			elif(c == '!' && lookahead().sepa == '=')
			{
				consume();

				right = parse(scast<int>(expr_parser::precedence::relational_eq_ne));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) != right.eval(d);});
			}

			elif(c == '>' && lookahead().sepa == '=')
			{
				consume();

				right = parse(scast<int>(expr_parser::precedence::relational_gt_lt));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) >= right.eval(d);});
			}
			elif(c == '<' && lookahead().sepa == '=')
			{
				consume();

				right = parse(scast<int>(expr_parser::precedence::relational_gt_lt));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) <= right.eval(d);});
			}
			elif(c == '>')
			{
				right = parse(scast<int>(expr_parser::precedence::relational_gt_lt));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) > right.eval(d);});
			}
			elif(c == '<')
			{
				right = parse(scast<int>(expr_parser::precedence::relational_gt_lt));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) < right.eval(d);});
			}

			elif(c == '+')
			{
				right = parse(scast<int>(expr_parser::precedence::add_sub));
				if(!left_string)
					left = new expr_binary(*left, *right,
						[](expr &left, expr &right, device &d){return left.eval(d) + right.eval(d);});
				else
					left = new expr_binary(*left, *right,
						[](expr &left, expr &right, device &d)
						{
							std::string *l = (std::string*)left.eval(d);
							std::string *r = (std::string*)right.eval(d);

							std::string *res = &(new std::string(*l))->append(*r);

							delete l;
							delete r;

							return (s8)res;
						});
			}
			elif(c == '-')
			{
				right = parse(scast<int>(expr_parser::precedence::add_sub));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) - right.eval(d);});
			}

			elif(c == '*')
			{
				right = parse(scast<int>(expr_parser::precedence::mul_div));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) * right.eval(d);});
			}
			elif(c == '/')
			{
				right = parse(scast<int>(expr_parser::precedence::mul_div));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) / right.eval(d);});
			}
			elif(c == '%')
			{
				right = parse(scast<int>(expr_parser::precedence::mul_div));
				left = new expr_binary(*left, *right,
					[](expr &left, expr &right, device &d){return left.eval(d) % right.eval(d);});
			}

			else
				throw std::string("expr_parser: can't parse rhs.");
		}

		failure = false;

		return left;
	}

	expr* parse()
	{
		return parse(0);
	}
};

//
#include "ext/json.h/json.h"
#ifndef DEV
	#pragma GCC diagnostic push
	#pragma GCC diagnostic warning "-fpermissive"
	#include "ext/json.h/json.c"
	#pragma GCC diagnostic pop
#endif

struct jstring
{
	char *string;
	uw length;

	jstring(char *string, uw length) : string(string), length(length) {}

	operator char*() {return string;}
};

struct json
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

		t_bool,
	};

	void *o;
	t type;

	json(json_value_s *jsv = null) : o((void*)jsv), type(t_value)
	{
		if(!o)
			type = t_null;
	}

	json(void *o, t type = t_value) : o(o), type(type)
	{
		if(!o)
			type = t_null;
	}

	bool is_string() {return !is_null() && type == t_string;}
	bool is_number() {return !is_null() && type == t_number;}
	bool is_object() {return !is_null() && type == t_object;}
	bool is_object_elem() {return !is_null() && type == t_object_elem;}
	bool is_array() {return !is_null() && type == t_array;}
	bool is_array_elem() {return !is_null() && type == t_array_elem;}
	bool is_true() {return type == t_true;}
	bool is_false() {return type == t_false;}
	bool is_bool() {return is_true() || is_false();}
	bool is_null() {return !is_bool() && (!o || type == t_null);}
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
			return json((void*)((json_object_element_s*)o)->name, t_string).string();
		else
			return jstring(null, 0);
	}

	f8 number()
	{
		extern f8 atof(const char* str);

		if(is_string() || is_number())
			return atof(string());
		else
			return 0.0 / 0.0;
	}

	json value()
	{
		if(is_object_elem())
			return json((json_value_s*)((json_object_element_s*)o)->value);
		elif(is_array_elem())
			return json((json_value_s*)((json_array_element_s*)o)->value);
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

			return json((void*)jsv->payload, type);
		}
		else
			return json((json_value_s*)null);
	}

	// Actual value of object and array elems.
	json payload()
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

	json next()
	{
		if(is_object_elem())
			return json((void*)((json_object_element_s*)o)->next, t_object_elem);
		elif(is_array_elem())
			return json((void*)((json_array_element_s*)o)->next, t_array_elem);
		elif(is_object())
			return json((void*)((json_object_s*)o)->start, t_object_elem);
		elif(is_array())
			return json((void*)((json_array_s*)o)->start, t_array_elem);
		else
			return json((json_value_s*)null);
	}

	bool obj_is(const char *name)
	{
		return is_object_elem() && string() && streq(string(), name);
	}

	bool obj_is(t value_type)
	{
		if(!is_object_elem())
			return false;

		json p = payload();
		return p.type == value_type || (value_type == t_bool && p.is_bool());
	}

	bool obj_is(const char *name, t value_type)
	{
		return obj_is(name) && obj_is(value_type);
	}

	bool is_comment()
	{
		return obj_is("comment");
	}

	bool is_var_def()
	{
		return is_object_elem() && string() && streq(string(), "var")
			&& payload().is_object() && payload().next().string();
	}

	bool is_var_ref()
	{
		return is_object() && next().string() && streq(next().string(), "ref")
			&& next().payload().is_string() && next().payload().string();
	}

	void p(bool comma = false, bool space = false)
	{
		if(comma)
			std::cout << ",";

		if(space)
			std::cout << " ";

		if(is_string())
			std::cout << "\"" << string() << "\"";
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
			std::cout << "\"" << string() << "\":";
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
struct config : public initialized_helper
{
	//
	json defson;
	json cmdson;
	json fileson;

	std::unordered_map<std::string, json> vars;

	//
	std::vector<std::string> configs;
	bool config_reload = false;

	//
	std::unordered_map<std::string, mapping*> mappings_ds4;
	std::vector<mapping*> mappings_enabled_ds4;

	bool parse(json cfg)
	{
		if(!cfg.has_next())
			return false;

		std::unordered_map<std::string, json> vars;

		auto def_vars =
			[&](json o)
			{
				while(o.has_next())
				{
					o = o.next();

					if(!o.is_var_def())
						continue;

					if(vars.count(std::string(o.payload().next().string())))
						vars.erase(std::string(o.payload().next().string()));

					vars.insert({
						{std::string(o.payload().next().string()), o.payload().next().payload()}});
				}
			};

		auto get_var =
			[&vars](json o) -> json
			{
				if(o.is_var_ref())
					if(vars.count(std::string(o.next().payload().string())))
						return vars.at(std::string(o.next().payload().string()));
					else
					{
						std::cerr << "Can't find referenced var '"
							<< o.next().payload().string() << "'." << std::endl;

						return json();
					}
				else
					return o;
			};

		auto obj_is =
			[&get_var](json o, const char *name, json::t type) -> bool
			{
				if(!o.obj_is(name))
					return false;

				json var = get_var(o.payload());

				return var.type == type || (type == json::t::t_bool && var.is_bool());
			};

		auto get =
			[&](json o, const char *name, json::t type, json *node = null) -> json
			{
				while(o.has_next())
				{
					o = o.next();

					if(node)
						*node = o;

					if(obj_is(o, name, type))
					{
						return get_var(o.payload());
					}
				}

				return json();
			};

		def_vars(cfg);

		json j = cfg;

		if(!(j = get(cfg, "config_paths", json::t_array)).is_null())
		{
			configs.clear();

			while(j.has_next())
			{
				j = j.next();
				if(j.payload().is_string())
					configs.push_back(std::string(j.payload().string()));
			}
		}

		if(!(j = get(cfg, "config_reload", json::t_bool)).is_null())
			config_reload = j.is_true();

		j = cfg;
		while(j.has_next())
		{
			json m;
			if((m = get(j, "mapping", json::t_object, &j)).is_null())
				continue;

			json jname = get(m, "name", json::t_string);
			json jfordev = get(m, "for", json::t_string);
			if(jname.is_null() || jfordev.is_null())
				continue;

			bool for_ds4 = streq(jfordev.string(), "ds4");
			if(!for_ds4)
				continue;

			verbose(std::cout << "mapping: " << jname.string() << " "
				<< jfordev.string() << std::endl);

			device *dev;
			if(for_ds4)
				dev = new ds4_device();
			dev->set_destroyed();

			std::vector<mapping::group*> groups;

			bool failure = true;
			raii res([&]()
				{
					if(!failure)
						return;

					// TODO: Do the same for all the mappings defined in this iteration.
					// It's not a big deal though, since they depend on to be enabled in
					// config in 'mappings' array and will be overwritten next time.
					for(auto i : groups)
						delete i;
				});

			json g;
			while(!(g = get(m, "group", json::t_object, &m)).is_null())
			{
				std::vector<mapping::cond*> conds;
				json c;
				while(!(c = get(g, "cond", json::t_object, &g)).is_null())
				{
					json jwhen = get(c, "when", json::t_string);
					json jd0 = get(c, "do", json::t_string);
					json jgreedy = get(c, "greedy", json::t_bool);

					if(jwhen.is_null() || jd0.is_null()
						|| !jwhen.string() || !jd0.string())
					{
						std::cerr << "config: empty 'when' or 'do' in '" << jname.string()
							<< "' mapping." << std::endl;

						continue;
					}

					verbose(std::cout << "cond: " << jwhen.string() << " ... "
						<< jd0.string() << std::endl);

					expr *when = null;
					expr *d0 = null;
					try
					{
						when = expr_parser::parse(jwhen.string(), *dev);
						d0 = expr_parser::parse(jd0.string(), *dev);
					}
					catch(std::string s)
					{
						std::cerr << "config: error while parsing 'when' or 'do' in '"
							<< jname.string() << "' mapping. The error: " << s
							<< " 'when': '" << jwhen.string() << "', 'do': '" << jd0.string()
							<< "'." << std::endl;

						delete when;
						delete d0;

						return false;
					}

					conds.push_back(new mapping::cond(when, d0, jgreedy.is_true()));
				}

				if(conds.empty())
					continue;

				groups.push_back(new mapping::group(conds));
			}

			failure = false;

			std::unordered_map<std::string, mapping*> *maps;
			if(for_ds4)
				maps = &mappings_ds4;

			if(maps->count(std::string(jname.string())))
			{
				verbose(std::cout << "deleting existing " << jname.string()
					<< std::endl);

				delete maps->at(std::string(jname.string()));
				maps->erase(std::string(jname.string()));
			}

			maps->insert({{std::string(jname.string()), new mapping(groups)}});

			delete dev;
		}

		j = cfg;
		if(!(j = get(cfg, "mappings", json::t_array)).is_null())
		{
			mappings_enabled_ds4.clear();

			while(j.has_next())
			{
				j = j.next();
				if(!j.payload().is_string())
					continue;

				if(mappings_ds4.count(std::string(j.payload().string())))
					mappings_enabled_ds4.push_back(
						mappings_ds4.at(std::string(j.payload().string())));
				else
				{
					std::cerr << "config: 'mappings': mapping definition not found: '"
						<< j.payload().string() << "'." << std::endl;

					return false;
				}
			}
		}

		return true;
	}

	bool parse(const char *config, uw length, json &src)
	{
		json cfg(json_parse((void*)config, length));

		if(parse(cfg.value()))
			return &(src = cfg);

		std::free(cfg.o);

		return false;
	}

	bool def(const char *config, uw length)
	{
		return parse(config, length, defson);
	}

	bool cmd(const char *config, uw length)
	{
		return parse(config, length, cmdson);
	}

	bool file(const char *config, uw length)
	{
		return parse(config, length, fileson);
	}

	~config()
	{
		if(destroyed())
			return;

		set_destroyed();

		std::free(defson.o);
		defson.o = null;
		defson.type = json::t_null;

		std::free(cmdson.o);
		cmdson.o = null;
		cmdson.type = json::t_null;

		std::free(fileson.o);
		fileson.o = null;
		fileson.type = json::t_null;

		for(auto const &i : mappings_ds4)
			delete i.second;
	}
};

struct ds4tux : public initialized_helper
{
	//
	struct first_time_init
	{
		static bool initialized()
		{
			return _initialized;
		}

		static void set_initialized()
		{
			_initialized = true;
		}

	private:
		static bool _initialized;
	};

	//
	config cfg;

	myudev md;

	std::unordered_map<std::string, device*> devices;

	bool init(const char *args = null)
	{
		//
		if(initialized())
			return false;

		//
		if(!cfg.def(config_default, sizeof(config_default)))
		{
			std::cerr << "Can't parse default config." << std::endl;

			return false;
		}

		if(args && !cfg.cmd(args, std::strlen(args)))
		{
			std::cerr << "Can't parse command line arguments." << std::endl;

			return false;
		}

		//
		if(!md.init())
		{
			std::cerr << "Failed to initialize udev." << std::endl;

			return false;
		}

		//
		set_initialized();

		return true;
	}

	void tick()
	{
		verbose(
			auto verbosedev = [](myudev::dev_info di, const char *act)
			{
				std::cout << act
					<< " " << di.vid << ";"
					<< " " << di.pid << ";"
					<< " " << di.serial << ";"
					<< " " << di.name << ";"
					<< " node: " << di.dev_node << ";"
					<< " input: " << di.input_node << ";"
					<< " event: " << di.event_node << ";"
					<< " " << di.manufacturer << ";"
					<< " " << di.product << ";"
					<< " " << di.release_number << ";"
					<< " " << di.interface_number << ";"
					;
				if(ds4_device::is_ds4(di.vid, di.pid, di.name.c_str()))
					std::cout << ". Got ds4! " << di.pid;
				std::cout << std::endl;
				std::cout << "-------------------------" << std::endl;
			};

			myudev::on_dev_change_sig verbosedadd =
			[&verbosedev](myudev::dev_info di)
			{
				verbosedev(di, "add");
			};

			myudev::on_dev_change_sig verbosedrem =
			[&verbosedev](myudev::dev_info di)
			{
				verbosedev(di, "rem");
			};);

		myudev::on_dev_change_sig dadd =
			[&, this](myudev::dev_info di)
			{
				verbose(verbosedadd(di));

				if(!ds4_device::is_ds4(di.vid, di.pid, di.name.c_str()))
					return;

				ds4_device *d = new ds4_device(di, cfg.mappings_enabled_ds4);

				if(devices.count(d->id()))
				{
					std::cerr << "Already in list: " << d->devinfo.dev_node << ". Wtf?"
						<< std::endl;

					d->set_destroyed();
					delete d;

					return;
				}

				devices.insert({{d->id(), d}});

				d->init();
				sleep_ms(500);
				d->control();
			};

		myudev::on_dev_change_sig drem =
			[&, this](myudev::dev_info di)
			{
				verbose(verbosedrem(di));

//				if(!ds4_device::is_ds4(di.vid, di.pid, di.name.c_str()))
//					return;

				ds4_device d(di, cfg.mappings_enabled_ds4);
				d.set_destroyed();

				if(!devices.count(d.id()))
					return;

				device *orig = devices.at(d.id());
				if(orig)
				{
					devices.erase(orig->id());

					delete orig;
				}
			};

		md.poll(dadd, drem);

		for(auto i = devices.begin(); i != devices.end();)
			if(!i->second->init() || i->second->destroyed())
				delete i->second, i = devices.erase(i);
			else
			{
				i->second->tick();

				++i;
			}
	}

	void start()
	{
		;
	}

	void destroy()
	{
		if(destroyed())
			return;

		verbose(std::cout << "d4t.destroy()" << std::endl);

		for(auto i = devices.begin(); i != devices.end();)
			delete i->second, i = devices.erase(i);

		md.destroy();

		set_destroyed();
	}

	~ds4tux()
	{
		destroy();
	}
};

// This shit still?!
bool ds4tux::first_time_init::_initialized = false;

//
#include <csignal>

bool quit = false;
bool reload = false;

void sigint(int sig)
{
	(void)sig;

	quit = true;
}

void sighup(int sig)
{
	(void)sig;

	reload = true;
	std::cout << "reload" << std::endl;
}

char* process_args(int argc, const char **argv)
{
	if(argc > 1
		 && (streq("h", argv[1]) || streq("help", argv[1])
				 || streq("-h", argv[1]) || streq("--h", argv[1])
				 || streq("-help", argv[1]) || streq("--help", argv[1])))
	{
		std::cout << "Help me!" << std::endl;

		std::exit(0);
	}

	uw arglen = 0;
	for(int i = 1; i < argc; i++)
		arglen += std::strlen(argv[i]);

	if(!arglen)
		return null;

	++arglen;
	auto args = new char[arglen];
	for(int i = 1, j = 0; i < argc; i++)
	{
		uw l = std::strlen(argv[i]);
		std::memcpy(args + j, argv[i], l);
		j += l;
	}

	return args;
}

int main(int argc, const char **argv)
{
	signal(SIGINT, sigint);
	signal(SIGHUP, sighup);
	signal(SIGQUIT, sighup);

//	ds4_device d;
//	d.set_destroyed();
//	d.readings[33].val = 1;
//	d.readings[32].val = -2;

//	while(true)
//	{
//		std::cout << "> ";
//		std::string in;
//		std::getline(std::cin, in);
//		if(!in.size())
//			break;
//		try
//		{
//			expr *ex = expr_parser::parse(in.c_str(), d);
//			s8 r = ex->eval(d);
//			std::cout << r << std::endl;
//			delete ex;
//		}
//		catch(std::string s) {std::cout << s << std::endl;}
//		catch(const char *s) {std::cout << s << std::endl;}
//	}

//	exit(0);

	ds4tux d4t;
	if(!d4t.init(process_args(argc, argv)))
		exit(0);
	ds4tux::first_time_init::set_initialized();
	d4t.start();
	while(!quit)
	{
		d4t.tick();
		if(d4t.devices.size())
			sleep_ms(2);
		else
			sleep_ms(500);
	}

	d4t.destroy();

	return 0;
}
