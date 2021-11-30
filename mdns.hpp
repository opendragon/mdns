/* mdns.h  -  mDNS/DNS-SD library  -  Public Domain  -  2017 Mattias Jansson
 *
 * This library provides a cross-platform mDNS and DNS-SD library in C.
 * The implementation is based on RFC 6762 and RFC 6763.
 *
 * The latest source code is always available at
 *
 * https://github.com/mjansson/mdns
 *
 * This library is put in the public domain; you can redistribute it and/or modify it without any
 * restrictions.
 *
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#if defined(_WIN32)
 #include <Winsock2.h>
 #include <Ws2tcpip.h>
 #define strncasecmp _strnicmp
#else /* not defined(_WIN32) */
 #include <unistd.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
#endif /* not defined(_WIN32) */

#define MDNS_INVALID_POS static_cast<size_t>(-1)

#define MDNS_STRING_CONST(ss) (ss), (sizeof((ss)) - 1)
#define MDNS_STRING_ARGS(ss) s.str, ss.length
#define MDNS_STRING_FORMAT(ss) static_cast<int>((ss).length), ss.str

#define MDNS_POINTER_OFFSET(pp, ofs) reinterpret_cast<void *>(reinterpret_cast<char *>(pp) + static_cast<ptrdiff_t>(ofs))
#define MDNS_POINTER_OFFSET_CONST(pp, ofs) reinterpret_cast<const void *>(reinterpret_cast<const char *>(pp) + static_cast<ptrdiff_t>(ofs))
#define MDNS_POINTER_DIFF(aa, bb) static_cast<size_t>(reinterpret_cast<const char *>(aa) - reinterpret_cast<const char *>(bb))

#define MDNS_PORT 5353
#define MDNS_UNICAST_RESPONSE 0x8000U
#define MDNS_CACHE_FLUSH 0x8000U
#define MDNS_MAX_SUBSTRINGS 64

namespace mDNS
{
	// Suppresses 'unused variable' warnings.
	namespace internal_
	{
		template <typename Type>
		void ignore_unused_variable_
			(const Type &)
		{
		} /* ignore_unused_variable_ */
	}; /* internal_ */

#define UNUSED_ARG_(var_)	DLMData::internal_::ignore_unused_variable_(var_)
#define UNUSED_PARAM_(xx_)	/* xx_ */
#define UNUSED_VAR_(var_)	UNUSED_ARG_(var_)

	enum record_type_t
	{
		kRecordTypeIgnore = 0,
		// Address
		kRecordTypeA = 1,
		// Domain Name pointer
		kRecordTypePTR = 12,
		// Arbitrary text string
		kRecordTypeTXT = 16,
		// IP6 Address [Thomson]
		kRecordTypeAAAA = 28,
		// Server Selection [RFC2782]
		kRecordTypeSRV = 33,
		// Any available records
		kRecordTypeANY = 255
	};

	enum entry_type_t
	{
		kEntryTypeQuestion = 0,
		kEntryTypeAnswer = 1,
		kEntryTypeAuthority = 2,
		kEntryTypeAdditional = 3
	};

	enum class_t
	{
		kClassTypeIn = 1,
		kClassTypeAny = 255
	};

	typedef int (*record_callback_fn)
		(const int sock,
		const struct sockaddr * from,
		const size_t addrlen,
		const entry_type_t entry,
		const uint16_t query_id,
		const uint16_t rtype,
		const uint16_t rclass,
		const uint32_t ttl,
		const void * data,
		const size_t size,
		const size_t name_offset,
		const size_t name_length,
		const size_t record_offset,
		const size_t record_length,
		void * user_data);

	#if defined(_WIN32)
	typedef int size_t_;
	typedef int ssize_t_;
	#else /* not defined(_WIN32) */
	typedef size_t size_t_;
	typedef ssize_t ssize_t_;
	#endif /* not defined(_WIN32) */

	struct string_t
	{
		const char * str;
		size_t length;
	};

	struct string_pair_t
	{
		size_t offset;
		size_t length;
		int ref;
	};

	struct string_table_t
	{
		size_t offset[16];
		size_t count;
		size_t next;
	};

	struct record_srv_t
	{
		uint16_t priority;
		uint16_t weight;
		uint16_t port;
		string_t name;
	};

	struct record_ptr_t
	{
		string_t name;
	};

	struct record_a_t
	{
		struct sockaddr_in addr;
	};

	struct record_aaaa_t
	{
		struct sockaddr_in6 addr;
	};

	struct record_txt_t
	{
		string_t key;
		string_t value;
	};

	struct record_t
	{
		string_t name;
		record_type_t type;
		union mdns_record_data
		{
			record_ptr_t ptr;
			record_srv_t srv;
			record_a_t a;
			record_aaaa_t aaaa;
			record_txt_t txt;
		} data;
	};

	struct header_t
	{
		uint16_t query_id;
		uint16_t flags;
		uint16_t questions;
		uint16_t answer_rrs;
		uint16_t authority_rrs;
		uint16_t additional_rrs;
	};

	// mDNS/DNS-SD public API

	//! Open and setup a IPv4 socket for mDNS/DNS-SD. To bind the socket to a specific interface, pass
	//! in the appropriate socket address in saddr, otherwise pass a null pointer for INADDR_ANY. To
	//! send one-shot discovery requests and queries pass a null pointer or set 0 as port to assign a
	//! random user level ephemeral port. To run discovery service listening for incoming discoveries
	//! and queries, you must set MDNS_PORT as port.
	static int
	socket_open_ipv4
		(const struct sockaddr_in * saddr);

	//! Setup an already opened IPv4 socket for mDNS/DNS-SD. To bind the socket to a specific interface,
	//! pass in the appropriate socket address in saddr, otherwise pass a null pointer for INADDR_ANY.
	//! To send one-shot discovery requests and queries pass a null pointer or set 0 as port to assign a
	//! random user level ephemeral port. To run discovery service listening for incoming discoveries
	//! and queries, you must set MDNS_PORT as port.
	static int
	socket_setup_ipv4
		(const int sock,
		const struct sockaddr_in * saddr);

	//! Open and setup a IPv6 socket for mDNS/DNS-SD. To bind the socket to a specific interface, pass
	//! in the appropriate socket address in saddr, otherwise pass a null pointer for in6addr_any. To
	//! send one-shot discovery requests and queries pass a null pointer or set 0 as port to assign a
	//! random user level ephemeral port. To run discovery service listening for incoming discoveries
	//! and queries, you must set MDNS_PORT as port.
	static int
	socket_open_ipv6
		(const struct sockaddr_in6 * saddr);

	//! Setup an already opened IPv6 socket for mDNS/DNS-SD. To bind the socket to a specific interface,
	//! pass in the appropriate socket address in saddr, otherwise pass a null pointer for in6addr_any.
	//! To send one-shot discovery requests and queries pass a null pointer or set 0 as port to assign a
	//! random user level ephemeral port. To run discovery service listening for incoming discoveries
	//! and queries, you must set MDNS_PORT as port.
	static int
	socket_setup_ipv6
		(const int sock,
		const struct sockaddr_in6 * saddr);

	//! Close a socket opened with mDNS::socket_open_ipv4 and mDNS::socket_open_ipv6.
	static void
	socket_close
		(const int sock);

	//! Listen for incoming multicast DNS-SD and mDNS query requests. The socket should have been opened
	//! on port MDNS_PORT using one of the mdns open or setup socket functions. Buffer must be 32 bit
	//! aligned. Parsing is stopped when callback function returns non-zero. Returns the number of
	//! queries parsed.
	static size_t
	socket_listen
		(const int sock,
		void * buffer,
		const size_t capacity,
		record_callback_fn callback,
		void * user_data);

	//! Send a multicast DNS-SD reqeuest on the given socket to discover available services. Returns 0
	//! on success, or <0 if error.
	static int
	discovery_send
		(const int sock);

	//! Recieve unicast responses to a DNS-SD sent with mDNS::discovery_send. Any data will be piped to
	//! the given callback for parsing. Buffer must be 32 bit aligned. Parsing is stopped when callback
	//! function returns non-zero. Returns the number of responses parsed.
	static size_t
	discovery_recv
		(const int sock,
		void * buffer,
		const size_t capacity,
		record_callback_fn callback,
		void * user_data);

	//! Send a multicast mDNS query on the given socket for the given service name. The supplied buffer
	//! will be used to build the query packet and must be 32 bit aligned. The query ID can be set to
	//! non-zero to filter responses, however the RFC states that the query ID SHOULD be set to 0 for
	//! multicast queries. The query will request a unicast response if the socket is bound to an
	//! ephemeral port, or a multicast response if the socket is bound to mDNS port 5353. Returns the
	//! used query ID, or <0 if error.
	static int
	query_send
		(const int sock,
		const record_type_t type,
		const char * name,
		const size_t length,
		void * buffer,
		const size_t capacity,
		const uint16_t query_id);

	//! Receive unicast responses to a mDNS query sent with mDNS::discovery_recv, optionally filtering
	//! out any responses not matching the given query ID. Set the query ID to 0 to parse all responses,
	//! even if it is not matching the query ID set in a specific query. Any data will be piped to the
	//! given callback for parsing. Buffer must be 32 bit aligned. Parsing is stopped when callback
	//! function returns non-zero. Returns the number of responses parsed.
	static size_t
	query_recv
		(const int sock,
		void * buffer,
		const size_t capacity,
		record_callback_fn callback,
		void * user_data,
		const int query_id);

	//! Send a variable unicast mDNS query answer to any question with variable number of records to the
	//! given address. Use the top bit of the query class field (MDNS_UNICAST_RESPONSE) in the query
	//! recieved to determine if the answer should be sent unicast (bit set) or multicast (bit not set).
	//! Buffer must be 32 bit aligned. The record type and name should match the data from the query
	//! recieved. Returns 0 if success, or <0 if error.
	static int
	query_answer_unicast
		(const int sock,
		const void * address,
		const size_t address_size,
		void * buffer,
		const size_t capacity,
		const uint16_t query_id,
		const record_type_t record_type,
		const char * name,
		const size_t name_length,
		const record_t & answer,
		record_t * authority,
		const size_t authority_count,
		record_t * additional,
		const size_t additional_count);

	//! Send a variable multicast mDNS query answer to any question with variable number of records. Use
	//! the top bit of the query class field (MDNS_UNICAST_RESPONSE) in the query recieved to determine
	//! if the answer should be sent unicast (bit set) or multicast (bit not set). Buffer must be 32 bit
	//! aligned. Returns 0 if success, or <0 if error.
	static int
	query_answer_multicast
		(const int sock,
		void * buffer,
		const size_t capacity,
		const record_t & answer,
		record_t * authority,
		const size_t authority_count,
		record_t * additional,
		const size_t additional_count);

	//! Send a variable multicast mDNS announcement (as an unsolicited answer) with variable number of
	//! records. Buffer must be 32 bit aligned. Returns 0 if success, or <0 if error. Use this on service
	//! startup to announce your instance to the local network.
	static int
	announce_multicast
		(const int sock,
		void * buffer,
		const size_t capacity,
		const record_t & answer,
		record_t * authority,
		const size_t authority_count,
		record_t * additional,
		const size_t additional_count);

	//! Send a variable multicast mDNS announcement. Use this on service end for removing the resource
	//! from the local network. The records must be identical to the according announcement.
	static int
	goodbye_multicast
		(const int sock,
		void * buffer,
		const size_t capacity,
		const record_t & answer,
		record_t * authority,
		const size_t authority_count,
		record_t * additional,
		const size_t additional_count);

	// Parse records functions

	//! Parse a PTR record, returns the name in the record
	static string_t
	record_parse_ptr
		(const void * buffer,
		const size_t size,
		const size_t offset,
		const size_t length,
		char * strbuffer,
		const size_t capacity);

	//! Parse a SRV record, returns the priority, weight, port and name in the record
	static record_srv_t
	record_parse_srv
		(const void * buffer,
		const size_t size,
		const size_t offset,
		const size_t length,
		char * strbuffer,
		const size_t capacity);

	//! Parse an A record, returns the IPv4 address in the record
	static struct sockaddr_in *
	record_parse_a
		(const void * buffer,
		const size_t size,
		const size_t offset,
		const size_t length,
		struct sockaddr_in * addr);

	//! Parse an AAAA record, returns the IPv6 address in the record
	static struct sockaddr_in6 *
	record_parse_aaaa
		(const void * buffer,
		const size_t size,
		const size_t offset,
		const size_t length,
		struct sockaddr_in6 * addr);

	//! Parse a TXT record, returns the number of key=value records parsed and stores the key-value
	//! pairs in the supplied buffer
	static size_t
	record_parse_txt
		(const void * buffer,
		const size_t size,
		const size_t offset,
		const size_t length,
		record_txt_t * records,
		const size_t capacity);

	// Internal functions

	namespace mDNSPrivate
	{
	
		static string_t
		string_extract
			(const void * buffer,
			const size_t size,
			size_t & offset,
			char * str,
			const size_t capacity);

		static bool
		string_skip
			(const void * buffer,
			const size_t size,
			size_t & offset);

		static size_t
		string_find
			(const char * str,
			const size_t length,
			const char cc,
			const size_t offset);

		static bool
		string_equal
			(const void * buffer_lhs,
			const size_t size_lhs,
			size_t & ofs_lhs,
			const void * buffer_rhs,
			const size_t size_rhs,
			size_t & ofs_rhs);

		static void *
		string_make
			(void * buffer,
			const size_t capacity,
			void * data,
			const char * name,
			const size_t length,
			string_table_t & string_table);

		static void *
		string_make
			(void * buffer,
			const size_t capacity,
			void * data,
			const char * name,
			const size_t length);

		static size_t
		string_table_find
			(const string_table_t & string_table,
			const void * buffer,
			const size_t capacity,
			const char * str,
			const size_t first_length,
			const size_t total_length);

	}; /* mDNSPrivate */
	

}; /* mDNS */

static mDNS::string_t
make_mdns_string
	(const char * inString,
	const size_t inLength)
{
	mDNS::string_t	result;

	result.str = strdup(inString);
	result.length = inLength;
	return result;
}

static mDNS::string_t
make_mdns_string
	(const char * inString)
{
	mDNS::string_t	result;

	result.str = strdup(inString);
	result.length = strlen(inString);
	return result;
}

static mDNS::string_t
make_mdns_string
	(const mDNS::string_t &	inString)
{
	mDNS::string_t	result;

	result.str = strdup(inString.str);
	result.length = inString.length;
	return result;
}

static void
release_mdns_string
	(mDNS::string_t &	inString)
{
	delete inString.str;
	inString.str = nullptr;
	inString.length = 0;
}

// Implementations

static uint16_t
mdns_ntohs
	(const void * data)
{
	uint16_t aligned;

	memcpy(&aligned, data, sizeof(uint16_t));
	return ntohs(aligned);
}

static uint32_t
mdns_ntohl
	(const void * data)
{
	uint32_t aligned;

	memcpy(&aligned, data, sizeof(uint32_t));
	return ntohl(aligned);
}

static void *
mdns_htons
	(void * data,
	const uint16_t val)
{
	uint16_t work_val = htons(val);

	memcpy(data, &work_val, sizeof(work_val));
	return MDNS_POINTER_OFFSET(data, sizeof(work_val));
}

static void *
mdns_htonl
	(void * data,
	const uint32_t val)
{
	uint32_t work_val = htonl(val);

	memcpy(data, &work_val, sizeof(work_val));
	return MDNS_POINTER_OFFSET(data, sizeof(work_val));
}

static int
mDNS::socket_open_ipv4
	(const struct sockaddr_in * saddr)
{
	int sock = static_cast<int>(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));

	if (sock < 0)
	{
		return -1;
	
	}
	if (mDNS::socket_setup_ipv4(sock, saddr))
	{
		mDNS::socket_close(sock);
		return -1;

	}
	return sock;
}

static int
mDNS::socket_setup_ipv4
	(const int sock,
	const struct sockaddr_in * saddr)
{
	unsigned char ttl = 1;
	unsigned char loopback = 1;
	unsigned int reuseaddr = 1;
	struct ip_mreq req;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&reuseaddr), sizeof(reuseaddr));
#if defined(SO_REUSEPORT)
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char *>(&reuseaddr), sizeof(reuseaddr));
#endif /* defined(SO_REUSEPORT) */
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, reinterpret_cast<const char *>(&ttl), sizeof(ttl));
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, reinterpret_cast<const char *>(&loopback), sizeof(loopback));
	memset(&req, 0, sizeof(req));
	req.imr_multiaddr.s_addr = htonl((static_cast<uint32_t>(224U) << 24U) | static_cast<uint32_t>(251U));
	if (saddr)
	{
		req.imr_interface = saddr->sin_addr;
	}
	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, reinterpret_cast<char *>(&req), sizeof(req)))
	{
		return -1;

	}
	struct sockaddr_in sock_addr;

	if (nullptr == saddr)
	{
		memset(&sock_addr, 0, sizeof(sock_addr));
		sock_addr.sin_family = AF_INET;
		sock_addr.sin_addr.s_addr = INADDR_ANY;
#if defined(__APPLE__)
		sock_addr.sin_len = sizeof(sock_addr);
#endif /* defined(__APPLE__) */
	}
	else
	{
		memcpy(&sock_addr, saddr, sizeof(sockaddr));
		setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, reinterpret_cast<const char *>(&sock_addr.sin_addr), sizeof(sock_addr.sin_addr));
#if (! defined(_WIN32))
		sock_addr.sin_addr.s_addr = INADDR_ANY;
#endif /* not defined(_WIN32) */
	}
	if (bind(sock, reinterpret_cast<struct sockaddr *>(&sock_addr), sizeof(sock_addr)))
	{
		return -1;
	
	}
#if defined(_WIN32)
	unsigned long param = 1;

	ioctlsocket(sock, FIONBIO, &param);
#else /* not defined(_WIN32) */
	const int flags = fcntl(sock, F_GETFL, 0);

	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif /* not defined(_WIN32) */
	return 0;
}

static int
mDNS::socket_open_ipv6
	(const struct sockaddr_in6 * saddr)
{
	int sock = static_cast<int>(socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP));

	if (sock < 0)
	{
		return -1;
	
	}
	if (mDNS::socket_setup_ipv6(sock, saddr))
	{
		mDNS::socket_close(sock);
		return -1;
	
	}
	return sock;
}

static int
mDNS::socket_setup_ipv6
	(const int sock,
	const struct sockaddr_in6 * saddr)
{
	int hops = 1;
	unsigned int loopback = 1;
	unsigned int reuseaddr = 1;
	struct ipv6_mreq req;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&reuseaddr), sizeof(reuseaddr));
#if defined(SO_REUSEPORT)
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char *>(&reuseaddr), sizeof(reuseaddr));
#endif /* defined(SO_REUSEPORT) */
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, reinterpret_cast<const char *>(&hops), sizeof(hops));
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, reinterpret_cast<const char *>(&loopback), sizeof(loopback));
	memset(&req, 0, sizeof(req));
	req.ipv6mr_multiaddr.s6_addr[0] = 0xFF;
	req.ipv6mr_multiaddr.s6_addr[1] = 0x02;
	req.ipv6mr_multiaddr.s6_addr[15] = 0xFB;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, reinterpret_cast<char *>(&req), sizeof(req)))
	{
		return -1;
	
	}
	struct sockaddr_in6 sock_addr;

	if (nullptr == saddr)
	{
		memset(&sock_addr, 0, sizeof(sock_addr));
		sock_addr.sin6_family = AF_INET6;
		sock_addr.sin6_addr = in6addr_any;
#if defined(__APPLE__)
		sock_addr.sin6_len = sizeof(sock_addr);
#endif /* defined(__APPLE__) */
	}
	else
	{
		memcpy(&sock_addr, saddr, sizeof(sock_addr));
		unsigned int ifindex = 0;

		setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, reinterpret_cast<const char *>(&ifindex), sizeof(ifindex));
#if (! defined(_WIN32))
		sock_addr.sin6_addr = in6addr_any;
#endif /* not defined(_WIN32) */
	}
	if (bind(sock, reinterpret_cast<struct sockaddr *>(&sock_addr), sizeof(sock_addr)))
	{
		return -1;
	
	}
#if defined(_WIN32)
	unsigned long param = 1;

	ioctlsocket(sock, FIONBIO, &param);
#else /* not defined(_WIN32) */
	const int flags = fcntl(sock, F_GETFL, 0);

	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif /* not defined(_WIN32) */
	return 0;
}

static void
mDNS::socket_close
	(const int sock)
{
#if defined(_WIN32)
	closesocket(sock);
#else /* not defined(_WIN32) */
	close(sock);
#endif /* not defined(_WIN32) */
}

static int
mdns_is_string_ref
	(const uint8_t val)
{
	return (0xC0 == (val & 0xC0));
}

static mDNS::string_pair_t
mdns_get_next_substring
	(const void * rawdata,
	const size_t size,
	const size_t offset)
{
	size_t work_offset = offset;
	const uint8_t * buffer = reinterpret_cast<const uint8_t *>(rawdata);
	mDNS::string_pair_t pair = { MDNS_INVALID_POS, 0, 0 };

	if (work_offset >= size)
	{
		return pair;
	
	}
	if (0 == buffer[work_offset])
	{
		pair.offset = work_offset;
		return pair;

	}
	int recursion = 0;

	while (mdns_is_string_ref(buffer[work_offset]))
	{
		if (size < (work_offset + 2))
		{
			return pair;
		
		}
		work_offset = (mdns_ntohs(MDNS_POINTER_OFFSET_CONST(buffer, work_offset)) & 0x3fff);
		if (work_offset >= size)
		{
			return pair;
		
		}
		pair.ref = 1;
		if (++recursion > 16)
		{
			return pair;
		}
	}
	size_t length = static_cast<size_t>(buffer[work_offset++]);

	if (size < (work_offset + length))
	{
		return pair;

	}
	pair.offset = work_offset;
	pair.length = length;
	return pair;
}

static bool
mDNS::mDNSPrivate::string_skip
	(const void * buffer,
	const size_t size,
	size_t & offset)
{
	size_t cur = offset;
	mDNS::string_pair_t substr;
	unsigned int counter = 0;

	do
	{
		substr = mdns_get_next_substring(buffer, size, cur);
		if ((substr.offset == MDNS_INVALID_POS) || (counter++ > MDNS_MAX_SUBSTRINGS))
		{
			return false;

		}
		if (substr.ref)
		{
			offset = cur + 2;
			return true;
		
		}
		cur = substr.offset + substr.length;
	}
	while (substr.length);
	offset = cur + 1;
	return true;
}

static bool
mDNS::mDNSPrivate::string_equal
	(const void * buffer_lhs,
	const size_t size_lhs,
	size_t & ofs_lhs,
	const void * buffer_rhs,
	const size_t size_rhs,
	size_t & ofs_rhs)
{
	size_t lhs_cur = ofs_lhs;
	size_t rhs_cur = ofs_rhs;
	size_t lhs_end = MDNS_INVALID_POS;
	size_t rhs_end = MDNS_INVALID_POS;
	mDNS::string_pair_t lhs_substr;
	mDNS::string_pair_t rhs_substr;
	unsigned int counter = 0;

	do
	{
		lhs_substr = mdns_get_next_substring(buffer_lhs, size_lhs, lhs_cur);
		rhs_substr = mdns_get_next_substring(buffer_rhs, size_rhs, rhs_cur);
		if ((lhs_substr.offset == MDNS_INVALID_POS) || (rhs_substr.offset == MDNS_INVALID_POS) ||
			(counter++ > MDNS_MAX_SUBSTRINGS))
		{
			return false;

		}
		if (lhs_substr.length != rhs_substr.length)
		{
			return false;

		}
		if (strncasecmp(reinterpret_cast<const char *>(MDNS_POINTER_OFFSET_CONST(buffer_rhs, rhs_substr.offset)),
						reinterpret_cast<const char *>(MDNS_POINTER_OFFSET_CONST(buffer_lhs, lhs_substr.offset)),
						rhs_substr.length))
		{
			return false;

		}
		if (lhs_substr.ref && (lhs_end == MDNS_INVALID_POS))
		{
			lhs_end = lhs_cur + 2;
		}
		if (rhs_substr.ref && (rhs_end == MDNS_INVALID_POS))
		{
			rhs_end = rhs_cur + 2;
		}
		lhs_cur = lhs_substr.offset + lhs_substr.length;
		rhs_cur = rhs_substr.offset + rhs_substr.length;
	}
	while (lhs_substr.length);
	if (lhs_end == MDNS_INVALID_POS)
	{
		lhs_end = lhs_cur + 1;
	}
	ofs_lhs = lhs_end;
	if (rhs_end == MDNS_INVALID_POS)
	{
		rhs_end = rhs_cur + 1;
	}
	ofs_rhs = rhs_end;
	return true;
}

static mDNS::string_t
mDNS::mDNSPrivate::string_extract
	(const void * buffer,
	const size_t size,
	size_t & offset,
	char * str,
	const size_t capacity)
{
	size_t cur = offset;
	size_t end = MDNS_INVALID_POS;
	mDNS::string_pair_t substr;
	char * dst = str;
	unsigned int counter = 0;
	size_t remain = capacity;

	do
	{
		substr = mdns_get_next_substring(buffer, size, cur);
		if ((substr.offset == MDNS_INVALID_POS) || (counter++ > MDNS_MAX_SUBSTRINGS))
		{
			return make_mdns_string(str, 0);
		
		}
		if (substr.ref && (end == MDNS_INVALID_POS))
		{
			end = cur + 2;
		}
		if (substr.length)
		{
			size_t to_copy = ((substr.length < remain) ? substr.length : remain);

			memcpy(dst, reinterpret_cast<const char *>(buffer) + substr.offset, to_copy);
			dst += to_copy;
			remain -= to_copy;
			if (remain)
			{
				*dst++ = '.';
				--remain;
			}
		}
		cur = substr.offset + substr.length;
	}
	while (0 < substr.length);
	if (end == MDNS_INVALID_POS)
	{
		end = cur + 1;
	}
	offset = end;
	return make_mdns_string(str, capacity - remain);
}

static size_t
mDNS::mDNSPrivate::string_table_find
	(const mDNS::string_table_t & string_table,
	const void * buffer,
	const size_t capacity,
	const char * str,
	const size_t first_length,
	const size_t total_length)
{
	for (size_t istr = 0; istr < string_table.count; ++istr)
	{
		if (string_table.offset[istr] >= capacity)
		{
			continue;
		
		}
		size_t offset = 0;
		mDNS::string_pair_t sub_string = mdns_get_next_substring(buffer, capacity, string_table.offset[istr]);

		if ((0 == sub_string.length) || (sub_string.length != first_length))
		{
			continue;
		
		}
		if (memcmp(str, MDNS_POINTER_OFFSET_CONST(buffer, sub_string.offset), sub_string.length))
		{
			continue;
		
		}
		// Initial substring matches, now match all remaining substrings
		offset += first_length + 1;
		while (offset < total_length)
		{
			size_t dot_pos = mDNS::mDNSPrivate::string_find(str, total_length, '.', offset);

			if (dot_pos == MDNS_INVALID_POS)
			{
				dot_pos = total_length;
			}
			size_t current_length = dot_pos - offset;

			sub_string = mdns_get_next_substring(buffer, capacity, sub_string.offset + sub_string.length);
			if ((0 == sub_string.length) || (sub_string.length != current_length))
			{
				break;
			
			}
			if (memcmp(str + offset, MDNS_POINTER_OFFSET_CONST(buffer, sub_string.offset), sub_string.length))
			{
				break;
			
			}
			offset = dot_pos + 1;
		}
		// Return reference offset if entire string matches
		if (offset >= total_length)
		{
			return string_table.offset[istr];
		
		}
	}
	return MDNS_INVALID_POS;
}

static void
mdns_string_table_add
	(mDNS::string_table_t & string_table,
	const size_t offset)
{
	string_table.offset[string_table.next] = offset;
	size_t table_capacity = sizeof(string_table.offset) / sizeof(*string_table.offset);

	if (++string_table.count > table_capacity)
	{
		string_table.count = table_capacity;
	}
	if (++string_table.next >= table_capacity)
	{
		string_table.next = 0;
	}
}

static size_t
mDNS::mDNSPrivate::string_find
	(const char * str,
	const size_t length,
	const char cc,
	const size_t offset)
{
	if (offset >= length)
	{
		return MDNS_INVALID_POS;
	
	}
	const void * found = memchr(str + offset, cc, length - offset);

	if (found)
	{
		return static_cast<size_t>(MDNS_POINTER_DIFF(found, str));
	
	}
	return MDNS_INVALID_POS;
}

static void *
mdns_string_make_ref
	(void * data,
	const size_t capacity,
	const size_t ref_offset)
{
	if (capacity < 2)
	{
		return nullptr;
	
	}
	return mdns_htons(data, 0xC000 | static_cast<uint16_t>(ref_offset));
}

static void *
mDNS::mDNSPrivate::string_make
	(void * buffer,
	const size_t capacity,
	void * data,
	const char * name,
	const size_t length,
	mDNS::string_table_t & string_table)
{
	size_t work_length = length;
	size_t last_pos = 0;
	size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);

	if (name[work_length - 1] == '.')
	{
		--work_length;
	}
	while (last_pos < work_length)
	{
		size_t pos = mDNS::mDNSPrivate::string_find(name, work_length, '.', last_pos);
		size_t sub_length = ((pos != MDNS_INVALID_POS) ? pos : work_length) - last_pos;
		size_t total_length = work_length - last_pos;
		size_t ref_offset = mDNS::mDNSPrivate::string_table_find(string_table, buffer, capacity,
													reinterpret_cast<char *>(const_cast<void *>(MDNS_POINTER_OFFSET_CONST(name, last_pos))),
													sub_length, total_length);

		if (ref_offset != MDNS_INVALID_POS)
		{
			return mdns_string_make_ref(data, remain, ref_offset);
		
		}
		if (remain <= (sub_length + 1))
		{
			return nullptr;
		
		}
		*reinterpret_cast<unsigned char *>(data) = static_cast<unsigned char>(sub_length);
		memcpy(MDNS_POINTER_OFFSET(data, 1), name + last_pos, sub_length);
		mdns_string_table_add(string_table, MDNS_POINTER_DIFF(data, buffer));
		data = MDNS_POINTER_OFFSET(data, sub_length + 1);
		last_pos = ((pos != MDNS_INVALID_POS) ? (pos + 1) : work_length);
		remain = capacity - MDNS_POINTER_DIFF(data, buffer);
	}
	if (0 == remain)
	{
		return nullptr;
	
	}
	*reinterpret_cast<unsigned char *>(data) = 0;
	return MDNS_POINTER_OFFSET(data, 1);
}

static void *
mDNS::mDNSPrivate::string_make
	(void * buffer,
	const size_t capacity,
	void * data,
	const char * name,
	const size_t length)
{
	size_t work_length = length;
	size_t last_pos = 0;
	size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);

	if (name[work_length - 1] == '.')
	{
		--work_length;
	}
	while (last_pos < work_length)
	{
		size_t pos = mDNS::mDNSPrivate::string_find(name, work_length, '.', last_pos);
		size_t sub_length = ((pos != MDNS_INVALID_POS) ? pos : work_length) - last_pos;
		size_t total_length = work_length - last_pos;

		if (remain <= (sub_length + 1))
		{
			return nullptr;
		
		}
		*reinterpret_cast<unsigned char *>(data) = static_cast<unsigned char>(sub_length);
		memcpy(MDNS_POINTER_OFFSET(data, 1), name + last_pos, sub_length);
		data = MDNS_POINTER_OFFSET(data, sub_length + 1);
		last_pos = ((pos != MDNS_INVALID_POS) ? (pos + 1) : work_length);
		remain = capacity - MDNS_POINTER_DIFF(data, buffer);
	}
	if (0 == remain)
	{
		return nullptr;
	
	}
	*reinterpret_cast<unsigned char *>(data) = 0;
	return MDNS_POINTER_OFFSET(data, 1);
}

static size_t
mdns_records_parse
	(const int sock,
	const struct sockaddr * from,
	const size_t addrlen,
	const void * buffer,
	const size_t size,
	size_t & offset,
	const mDNS::entry_type_t type,
	const uint16_t query_id,
	const size_t records,
	mDNS::record_callback_fn callback,
	void * user_data)
{
	size_t parsed = 0;

	for (size_t ii = 0; ii < records; ++ii)
	{
		size_t name_offset = offset;

		mDNS::mDNSPrivate::string_skip(buffer, size, offset);
		if ((offset + 10) > size)
		{
			return parsed;
		
		}
		size_t name_length = offset - name_offset;
		const uint16_t * data = reinterpret_cast<const uint16_t *>(MDNS_POINTER_OFFSET_CONST(buffer, offset));
		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);
		uint32_t ttl = mdns_ntohl(data);

		data += 2;
		uint16_t length = mdns_ntohs(data++);

		offset += 10;
		if (length <= (size - offset))
		{
			++parsed;
			if (callback &&
				callback(sock, from, addrlen, type, query_id, rtype, rclass, ttl, buffer, size,
						name_offset, name_length, offset, length, user_data))
			{
				break;
			
			}
		}
		offset += length;
	}
	return parsed;
}

static int
mdns_unicast_send
	(const int sock,
	const void * address,
	const size_t address_size,
	const void * buffer,
	const size_t size)
{
	if (sendto(sock, reinterpret_cast<const char *>(buffer), static_cast<mDNS::size_t_>(size), 0, reinterpret_cast<const struct sockaddr *>(address),
			static_cast<socklen_t>(address_size)) < 0)
	{
		return -1;
	}
	return 0;
}

static int
mdns_multicast_send
	(const int sock,
	const void * buffer,
	const size_t size)
{
	struct sockaddr_storage addr_storage;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	struct sockaddr * saddr = reinterpret_cast<struct sockaddr *>(&addr_storage);
	socklen_t saddrlen = sizeof(addr_storage);

	if (getsockname(sock, saddr, &saddrlen))
	{
		return -1;
	
	}
	if (saddr->sa_family == AF_INET6)
	{
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
#if defined(__APPLE__)
		addr6.sin6_len = sizeof(addr6);
#endif /* defined(__APPLE__) */
		addr6.sin6_addr.s6_addr[0] = 0xFF;
		addr6.sin6_addr.s6_addr[1] = 0x02;
		addr6.sin6_addr.s6_addr[15] = 0xFB;
		addr6.sin6_port = htons(static_cast<unsigned short>(MDNS_PORT));
		saddr = reinterpret_cast<struct sockaddr *>(&addr6);
		saddrlen = sizeof(addr6);
	}
	else
	{
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
#if defined(__APPLE__)
		addr.sin_len = sizeof(addr);
#endif /* defined(__APPLE__) */
		addr.sin_addr.s_addr = htonl((static_cast<uint32_t>(224U) << 24U) | static_cast<uint32_t>(251U));
		addr.sin_port = htons(static_cast<unsigned short>(MDNS_PORT));
		saddr = reinterpret_cast<struct sockaddr *>(&addr);
		saddrlen = sizeof(addr);
	}
	if (sendto(sock, reinterpret_cast<const char *>(buffer), static_cast<mDNS::size_t_>(size), 0, saddr, saddrlen) < 0)
	{
		return -1;
	
	}
	return 0;
}

static const uint8_t mdns_services_query[] =
{
	// Query ID
	0x00, 0x00,
	// Flags
	0x00, 0x00,
	// 1 question
	0x00, 0x01,
	// No answer, authority or additional RRs
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// _services._dns-sd._udp.local.
	0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's', 0x07, '_', 'd', 'n', 's', '-', 's', 'd',
	0x04, '_', 'u', 'd', 'p', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
	// PTR record
	0x00, mDNS::kRecordTypePTR,
	// QU (unicast response) and class IN
	0x80, mDNS::kClassTypeIn
};

static int
mDNS::discovery_send
	(const int sock)
{
	return mdns_multicast_send(sock, mdns_services_query, sizeof(mdns_services_query));
}

static size_t
mDNS::discovery_recv
	(const int sock,
	void * buffer,
	const size_t capacity,
	record_callback_fn callback,
	void * user_data)
{
	struct sockaddr_in6 addr;
	struct sockaddr * saddr = reinterpret_cast<struct sockaddr *>(&addr);
	socklen_t addrlen = sizeof(addr);

	memset(&addr, 0, sizeof(addr));
#if defined(__APPLE__)
	saddr->sa_len = sizeof(addr);
#endif /* defined(__APPLE__) */
	mDNS::ssize_t_ ret = recvfrom(sock, reinterpret_cast<char *>(buffer), static_cast<mDNS::size_t_>(capacity), 0, saddr, &addrlen);

	if (ret <= 0)
	{
		return 0;
	
	}
	size_t data_size = static_cast<size_t>(ret);
	size_t records = 0;
	const uint16_t * data = reinterpret_cast<const uint16_t *>(buffer);
	uint16_t query_id = mdns_ntohs(data++);
	uint16_t flags = mdns_ntohs(data++);
	uint16_t questions = mdns_ntohs(data++);
	uint16_t answer_rrs = mdns_ntohs(data++);
	uint16_t authority_rrs = mdns_ntohs(data++);
	uint16_t additional_rrs = mdns_ntohs(data++);

	// According to RFC 6762 the query ID MUST match the sent query ID (which is 0 in our case)
	if (query_id || (flags != 0x8400))
	{
		return 0;  // Not a reply to our question
	
	}
	// It seems some implementations do not fill the correct questions field,
	// so ignore this check for now and only validate answer string
	/*
	if (questions != 1)
	{
		return 0;
	
	}
	*/
	for (int ii = 0; ii < questions; ++ii)
	{
		size_t ofs = MDNS_POINTER_DIFF(data, buffer);
		size_t verify_ofs = 12;

		// Verify it's our question, _services._dns-sd._udp.local.
		if (! mDNS::mDNSPrivate::string_equal(buffer, data_size, ofs, mdns_services_query,
												sizeof(mdns_services_query), verify_ofs))
		{
			return 0;
		
		}
		data = reinterpret_cast<const uint16_t *>(MDNS_POINTER_OFFSET(buffer, ofs));
		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);

		// Make sure we get a reply based on our PTR question for class IN
		if ((rtype != kRecordTypePTR) || ((rclass & 0x7FFF) != kClassTypeIn))
		{
			return 0;
		
		}
	}
	for (int ii = 0; ii < answer_rrs; ++ii)
	{
		size_t ofs = MDNS_POINTER_DIFF(data, buffer);
		size_t verify_ofs = 12;
		// Verify it's an answer to our question, _services._dns-sd._udp.local.
		size_t name_offset = ofs;
		bool is_answer = mDNS::mDNSPrivate::string_equal(buffer, data_size, ofs, mdns_services_query,
														sizeof(mdns_services_query), verify_ofs);
		size_t name_length = ofs - name_offset;

		if ((ofs + 10) > data_size)
		{
			return records;
		
		}
		data = reinterpret_cast<const uint16_t *>(MDNS_POINTER_OFFSET(buffer, ofs));
		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);
		uint32_t ttl = mdns_ntohl(data);

		data += 2;
		uint16_t length = mdns_ntohs(data++);

		if (length > (data_size - ofs))
		{
			return 0;
		
		}
		if (is_answer)
		{
			++records;
			ofs = MDNS_POINTER_DIFF(data, buffer);
			if (callback &&
				callback(sock, saddr, addrlen, kEntryTypeAnswer, query_id, rtype, rclass, ttl,
						buffer, data_size, name_offset, name_length, ofs, length, user_data))
			{
				return records;
			
			}
		}
		data = reinterpret_cast<const uint16_t *>(MDNS_POINTER_OFFSET_CONST(data, length));
	}
	size_t total_records = records;
	size_t offset = MDNS_POINTER_DIFF(data, buffer);

	records = mdns_records_parse(sock, saddr, addrlen, buffer, data_size, offset,
								kEntryTypeAuthority, query_id, authority_rrs, callback, user_data);
	total_records += records;
	if (records != authority_rrs)
	{
		return total_records;
	
	}
	records = mdns_records_parse(sock, saddr, addrlen, buffer, data_size, offset,
								kEntryTypeAdditional, query_id, additional_rrs, callback,
								user_data);
	total_records += records;
	if (records != additional_rrs)
	{
		return total_records;
	
	}
	return total_records;
}

static size_t
mDNS::socket_listen
	(const int sock,
	void * buffer,
	const size_t capacity,
	record_callback_fn callback,
	void * user_data)
{
	struct sockaddr_in6 addr;
	struct sockaddr * saddr = reinterpret_cast<struct sockaddr *>(&addr);
	socklen_t addrlen = sizeof(addr);

	memset(&addr, 0, sizeof(addr));
#if defined(__APPLE__)
	saddr->sa_len = sizeof(addr);
#endif /* defined(__APPLE__) */
	mDNS::ssize_t_ ret = recvfrom(sock, reinterpret_cast<char *>(buffer), static_cast<mDNS::size_t_>(capacity), 0, saddr, &addrlen);

	if (ret <= 0)
	{
		return 0;
	
	}
	size_t data_size = static_cast<size_t>(ret);
	const uint16_t * data = reinterpret_cast<const uint16_t *>(buffer);
	uint16_t query_id = mdns_ntohs(data++);
	uint16_t flags = mdns_ntohs(data++);
	uint16_t questions = mdns_ntohs(data++);
	
	/*
	This data is unused at the moment, skip
	uint16_t answer_rrs = mdns_ntohs(data++);
	uint16_t authority_rrs = mdns_ntohs(data++);
	uint16_t additional_rrs = mdns_ntohs(data++);
	*/
	data += 3;
	size_t parsed = 0;

	for (int iquestion = 0; iquestion < questions; ++iquestion)
	{
		size_t question_offset = MDNS_POINTER_DIFF(data, buffer);
		size_t offset = question_offset;
		size_t verify_ofs = 12;
		bool dns_sd = false;

		if (mDNS::mDNSPrivate::string_equal(buffer, data_size, offset, mdns_services_query,
											sizeof(mdns_services_query), verify_ofs))
		{
			dns_sd = true;
		}
		else
		{
			offset = question_offset;
			if (! mDNS::mDNSPrivate::string_skip(buffer, data_size, offset))
			{
				break;
			
			}
		}
		size_t length = offset - question_offset;
		data = reinterpret_cast<const uint16_t *>(MDNS_POINTER_OFFSET_CONST(buffer, offset));
		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);
		uint16_t class_without_flushbit = (rclass & ~MDNS_CACHE_FLUSH);

		// Make sure we get a question of class IN
		if (! ((class_without_flushbit == kClassTypeIn) ||
			(class_without_flushbit == kClassTypeAny)))
		{
			break;
		
		}
		if (dns_sd && flags)
		{
			continue;
		
		}
		++parsed;
		if (callback && callback(sock, saddr, addrlen, kEntryTypeQuestion, query_id, rtype,
								rclass, 0, buffer, data_size, question_offset, length,
								question_offset, length, user_data))
		{
			break;
		
		}
	}
	return parsed;
}

static int
mDNS::query_send
	(const int sock,
	const record_type_t type,
	const char * name,
	const size_t length,
	void * buffer,
	const size_t capacity,
	const uint16_t query_id)
{
	if (capacity < (17 + length))
	{
		return -1;
	
	}
	// Ask for a unicast response since it's a one-shot query
	uint16_t rclass = (mDNS::kClassTypeIn | MDNS_UNICAST_RESPONSE);
	struct sockaddr_storage addr_storage;
	struct sockaddr * saddr = reinterpret_cast<struct sockaddr *>(&addr_storage);
	socklen_t saddrlen = sizeof(addr_storage);

	if (getsockname(sock, saddr, &saddrlen) == 0)
	{
		if ((saddr->sa_family == AF_INET) &&
			(ntohs(reinterpret_cast<struct sockaddr_in *>(saddr)->sin_port) == MDNS_PORT))
		{
			rclass &= ~MDNS_UNICAST_RESPONSE;
		}
		else if ((saddr->sa_family == AF_INET6) &&
				(ntohs(reinterpret_cast<struct sockaddr_in6 *>(saddr)->sin6_port) == MDNS_PORT))
		{
			rclass &= ~MDNS_UNICAST_RESPONSE;
		}
	}
	header_t * header = reinterpret_cast<header_t *>(buffer);

	// Query ID
	header->query_id = htons(query_id);
	// Flags
	header->flags = 0;
	// Questions
	header->questions = htons(1);
	// No answer, authority or additional RRs
	header->answer_rrs = 0;
	header->authority_rrs = 0;
	header->additional_rrs = 0;
	// Fill in question
	// Name string
	void * data = MDNS_POINTER_OFFSET(buffer, sizeof(header_t));

	data = mDNS::mDNSPrivate::string_make(buffer, capacity, data, name, length);
	if (nullptr == data)
	{
		return -1;
	
	}
	// Record type
	data = mdns_htons(data, type);
	//! Optional unicast response based on local port, class IN
	data = mdns_htons(data, rclass);
	size_t tosend = MDNS_POINTER_DIFF(data, buffer);

	if (mdns_multicast_send(sock, buffer, static_cast<size_t>(tosend)))
	{
		return -1;
	
	}
	return query_id;
}

static size_t
mDNS::query_recv
	(const int sock,
	void * buffer,
	const size_t capacity,
	record_callback_fn callback,
	void * user_data,
	const int only_query_id)
{
	struct sockaddr_in6 addr;
	struct sockaddr * saddr = reinterpret_cast<struct sockaddr *>(&addr);
	socklen_t addrlen = sizeof(addr);

	memset(&addr, 0, sizeof(addr));
#if defined(__APPLE__)
	saddr->sa_len = sizeof(addr);
#endif /* defined(__APPLE__) */
	mDNS::ssize_t_ ret = recvfrom(sock, reinterpret_cast<char *>(buffer), static_cast<mDNS::size_t_>(capacity), 0, saddr, &addrlen);
	
	if (ret <= 0)
	{
		return 0;
	
	}
	size_t data_size = static_cast<size_t>(ret);
	const uint16_t * data = reinterpret_cast<const uint16_t *>(buffer);
	uint16_t query_id = mdns_ntohs(data++);
	// uint16_t flags = mdns_ntohs(data++);
	++data; // skip flags
	uint16_t questions = mdns_ntohs(data++);
	uint16_t answer_rrs = mdns_ntohs(data++);
	uint16_t authority_rrs = mdns_ntohs(data++);
	uint16_t additional_rrs = mdns_ntohs(data++);

	// (void)sizeof(flags);

	if ((only_query_id > 0) && (query_id != only_query_id))
	{
		return 0;  // Not a reply to the wanted one-shot query
	
	}
	if (questions > 1)
	{
		return 0;
	
	}
	// Skip questions part
	for (int ii = 0; ii < questions; ++ii)
	{
		size_t ofs = MDNS_POINTER_DIFF(data, buffer);

		if (! mDNS::mDNSPrivate::string_skip(buffer, data_size, ofs))
		{
			return 0;
		
		}
		data = reinterpret_cast<const uint16_t *>(MDNS_POINTER_OFFSET_CONST(buffer, ofs));
		/* Record type and class not used, skip
		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);*/
		data += 2;
	}
	size_t total_records = 0;
	size_t offset = MDNS_POINTER_DIFF(data, buffer);
	size_t records = mdns_records_parse(sock, saddr, addrlen, buffer, data_size, offset,
										kEntryTypeAnswer, query_id, answer_rrs, callback, user_data);

	total_records += records;
	if (records != answer_rrs)
	{
		return total_records;
	
	}
	records = mdns_records_parse(sock, saddr, addrlen, buffer, data_size, offset,
								kEntryTypeAuthority, query_id, authority_rrs, callback, user_data);
	total_records += records;
	if (records != authority_rrs)
	{
		return total_records;
	
	}
	records = mdns_records_parse(sock, saddr, addrlen, buffer, data_size, offset,
								kEntryTypeAdditional, query_id, additional_rrs, callback,
								user_data);
	total_records += records;
	if (records != additional_rrs)
	{
		return total_records;
	
	}
	return total_records;
}

static void *
mdns_answer_add_question_unicast
	(void * buffer,
	const size_t capacity,
	void * data,
	const mDNS::record_type_t record_type,
	const char * name,
	const size_t name_length,
	mDNS::string_table_t & string_table)
{
	data = mDNS::mDNSPrivate::string_make(buffer, capacity, data, name, name_length, string_table);
	if (nullptr == data)
	{
		return nullptr;
	
	}
	size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);

	if (remain < 4)
	{
		return nullptr;
	
	}
	data = mdns_htons(data, record_type);
	data = mdns_htons(data, MDNS_UNICAST_RESPONSE | mDNS::kClassTypeIn);
	return data;
}

static void *
mdns_answer_add_record_header
	(void * buffer,
	const size_t capacity,
	void * data,
	const mDNS::record_t record,
	const uint16_t rclass,
	const uint32_t ttl,
	mDNS::string_table_t & string_table)
{
	data = mDNS::mDNSPrivate::string_make(buffer, capacity, data, record.name.str, record.name.length, string_table);
	if (nullptr == data)
	{
		return nullptr;
	
	}
	size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);

	if (remain < 10)
	{
		return nullptr;
	
	}
	data = mdns_htons(data, record.type);
	data = mdns_htons(data, rclass);
	data = mdns_htonl(data, ttl);
	data = mdns_htons(data, 0);  // Length, to be filled later
	return data;
}

static void *
mdns_answer_add_record
	(void * buffer,
	const size_t capacity,
	void * data,
	const mDNS::record_t & record,
	const uint16_t rclass,
	const uint32_t ttl,
	mDNS::string_table_t & string_table)
{
	// TXT records will be coalesced into one record later
	if ((nullptr == data) || (record.type == mDNS::kRecordTypeTXT))
	{
		return data;
	
	}
	data = mdns_answer_add_record_header(buffer, capacity, data, record, rclass, ttl, string_table);
	if (nullptr == data)
	{
		return nullptr;
	
	}
	// Pointer to length of record to be filled at end
	void * record_length = MDNS_POINTER_OFFSET(data, -2);
	void * record_data = data;
	size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);

	switch (record.type)
	{
		case mDNS::kRecordTypePTR:
			data = mDNS::mDNSPrivate::string_make(buffer, capacity, data, record.data.ptr.name.str, record.data.ptr.name.length, string_table);
			break;

		case mDNS::kRecordTypeSRV:
			if (remain <= 6)
			{
				return nullptr;
			
			}
			data = mdns_htons(data, record.data.srv.priority);
			data = mdns_htons(data, record.data.srv.weight);
			data = mdns_htons(data, record.data.srv.port);
			data = mDNS::mDNSPrivate::string_make(buffer, capacity, data, record.data.srv.name.str,
									record.data.srv.name.length, string_table);
			break;

		case mDNS::kRecordTypeA:
			if (remain < 4)
			{
				return nullptr;
			
			}
			memcpy(data, &record.data.a.addr.sin_addr.s_addr, 4);
			data = MDNS_POINTER_OFFSET(data, 4);
			break;

		case mDNS::kRecordTypeAAAA:
			if (remain < 16)
			{
				return nullptr;
			
			}
			memcpy(data, &record.data.aaaa.addr.sin6_addr, 16);  // ipv6 address
			data = MDNS_POINTER_OFFSET(data, 16);
			break;

		default:
			break;
	}
	if (nullptr == data)
	{
		return nullptr;
	
	}
	// Fill record length
	mdns_htons(record_length, (uint16_t)MDNS_POINTER_DIFF(data, record_data));
	return data;
}

static void *
mdns_answer_add_txt_record
	(void * buffer,
	const size_t capacity,
	void * data,
	mDNS::record_t * records,
	const size_t record_count,
	const uint16_t rclass,
	const uint32_t ttl,
	mDNS::string_table_t & string_table)
{
	// Pointer to length of record to be filled at end
	void * record_length = nullptr;
	void * record_data = nullptr;
	size_t remain = 0;

	for (size_t irec = 0; data && (irec < record_count); ++irec)
	{
		if (records[irec].type != mDNS::kRecordTypeTXT)
		{
			continue;
		
		}
		if (nullptr == record_data)
		{
			data = mdns_answer_add_record_header(buffer, capacity, data, records[irec], rclass, ttl, string_table);
			record_length = MDNS_POINTER_OFFSET(data, -2);
			record_data = data;
		}
		// TXT strings are unlikely to be shared, just make then raw. Also need one byte for
		// termination, thus the <= check
		size_t string_length = records[irec].data.txt.key.length + records[irec].data.txt.value.length + 1;

		if (nullptr == data)
		{
			return nullptr;

		}
		remain = capacity - MDNS_POINTER_DIFF(data, buffer);
		if ((remain <= string_length) || (string_length > 0x3FFF))
		{
			return nullptr;
		
		}
		unsigned char * strdata = reinterpret_cast<unsigned char *>(data);

		*strdata++ = static_cast<unsigned char>(string_length);
		memcpy(strdata, records[irec].data.txt.key.str, records[irec].data.txt.key.length);
		strdata += records[irec].data.txt.key.length;
		*strdata++ = '=';
		memcpy(strdata, records[irec].data.txt.value.str, records[irec].data.txt.value.length);
		strdata += records[irec].data.txt.value.length;
		data = strdata;
	}
	// Fill record length
	if (record_data)
	{
		mdns_htons(record_length, static_cast<uint16_t>(MDNS_POINTER_DIFF(data, record_data)));
	}
	return data;
}

static uint16_t
mdns_answer_get_record_count
	(mDNS::record_t * records,
	const size_t record_count)
{
	// TXT records will be coalesced into one record
	uint16_t total_count = 0;
	uint16_t txt_record = 0;

	for (size_t irec = 0; irec < record_count; ++irec)
	{
		if (records[irec].type == mDNS::kRecordTypeTXT)
		{
			txt_record = 1;
		}
		else
		{
			++total_count;
		}
	}
	return total_count + txt_record;
}

static int
mDNS::query_answer_unicast
	(const int sock,
	const void * address,
	const size_t address_size,
	void * buffer,
	const size_t capacity,
	const uint16_t query_id,
	const record_type_t record_type,
	const char * name,
	const size_t name_length,
	const record_t & answer,
	record_t * authority,
	const size_t authority_count,
	record_t * additional,
	const size_t additional_count)
{
	if (capacity < (sizeof(header_t) + 32 + 4))
	{
		return -1;
	
	}
	uint16_t rclass = (MDNS_CACHE_FLUSH | mDNS::kClassTypeIn);
	uint32_t ttl = 10;
	// Basic answer structure
	header_t * header = reinterpret_cast<header_t *>(buffer);

	header->query_id = htons(query_id);
	header->flags = htons(0x8400);
	header->questions = htons(1);
	header->answer_rrs = htons(1);
	header->authority_rrs = htons(mdns_answer_get_record_count(authority, authority_count));
	header->additional_rrs = htons(mdns_answer_get_record_count(additional, additional_count));
	string_table_t string_table = { { 0 }, 0, 0};
	void * data = MDNS_POINTER_OFFSET(buffer, sizeof(header_t));

	// Fill in question
	data = mdns_answer_add_question_unicast(buffer, capacity, data, record_type, name, name_length, string_table);
	// Fill in answer
	data = mdns_answer_add_record(buffer, capacity, data, answer, rclass, ttl, string_table);
	// Fill in authority records
	for (size_t irec = 0; data && (irec < authority_count); ++irec)
	{
		data = mdns_answer_add_record(buffer, capacity, data, authority[irec], rclass, ttl, string_table);
	}
	data = mdns_answer_add_txt_record(buffer, capacity, data, authority, authority_count, rclass, ttl, string_table);
	// Fill in additional records
	for (size_t irec = 0; data && (irec < additional_count); ++irec)
	{
		data = mdns_answer_add_record(buffer, capacity, data, additional[irec], rclass, ttl, string_table);
	}
	data = mdns_answer_add_txt_record(buffer, capacity, data, additional, additional_count, rclass, ttl, string_table);
	if (nullptr == data)
	{
		return -1;
	
	}
	size_t tosend = MDNS_POINTER_DIFF(data, buffer);

	return mdns_unicast_send(sock, address, address_size, buffer, tosend);
}

static int
mdns_answer_multicast_rclass_ttl
	(const int sock,
	void * buffer,
	const size_t capacity,
	const uint16_t rclass,
	const mDNS::record_t & answer,
	mDNS::record_t * authority,
	const size_t authority_count,
	mDNS::record_t * additional,
	const size_t additional_count,
	const uint32_t ttl)
{
	if (capacity < (sizeof(mDNS::header_t) + 32 + 4))
	{
		return -1;
	
	}
	// Basic answer structure
	mDNS::header_t * header = reinterpret_cast<mDNS::header_t *>(buffer);

	header->query_id = 0;
	header->flags = htons(0x8400);
	header->questions = 0;
	header->answer_rrs = htons(1);
	header->authority_rrs = htons(mdns_answer_get_record_count(authority, authority_count));
	header->additional_rrs = htons(mdns_answer_get_record_count(additional, additional_count));
	mDNS::string_table_t string_table = { { 0 }, 0, 0};
	void * data = MDNS_POINTER_OFFSET(buffer, sizeof(mDNS::header_t));

	// Fill in answer
	data = mdns_answer_add_record(buffer, capacity, data, answer, rclass, ttl, string_table);
	// Fill in authority records
	for (size_t irec = 0; data && (irec < authority_count); ++irec)
	{
		data = mdns_answer_add_record(buffer, capacity, data, authority[irec], rclass, ttl, string_table);
	}
	data = mdns_answer_add_txt_record(buffer, capacity, data, authority, authority_count, rclass, ttl, string_table);
	// Fill in additional records
	for (size_t irec = 0; data && (irec < additional_count); ++irec)
	{
		data = mdns_answer_add_record(buffer, capacity, data, additional[irec], rclass, ttl, string_table);
	}
	data = mdns_answer_add_txt_record(buffer, capacity, data, additional, additional_count, rclass, ttl, string_table);
	if (nullptr == data)
	{
		return -1;
	
	}
	size_t tosend = MDNS_POINTER_DIFF(data, buffer);
	
	return mdns_multicast_send(sock, buffer, tosend);
}

static int
mdns_answer_multicast_rclass
	(const int sock,
	void * buffer,
	const size_t capacity,
	const uint16_t rclass,
	const mDNS::record_t & answer,
	mDNS::record_t * authority,
	const size_t authority_count,
	mDNS::record_t * additional,
	const size_t additional_count)
{
	return mdns_answer_multicast_rclass_ttl(sock, buffer, capacity, rclass, answer, authority,
											authority_count, additional, additional_count, 60);
}

static int
mDNS::query_answer_multicast
	(const int sock,
	void * buffer,
	const size_t capacity,
	const record_t & answer,
	record_t * authority,
	const size_t authority_count,
	record_t * additional,
	const size_t additional_count)
{
	uint16_t rclass = mDNS::kClassTypeIn;

	return mdns_answer_multicast_rclass(sock, buffer, capacity, rclass, answer, authority,
										authority_count, additional, additional_count);
}

static int
mDNS::announce_multicast
	(const int sock,
	void * buffer,
	const size_t capacity,
	const record_t & answer,
	record_t * authority,
	const size_t authority_count,
	record_t * additional,
	const size_t additional_count)
{
	uint16_t rclass = (mDNS::kClassTypeIn | MDNS_CACHE_FLUSH);

	return mdns_answer_multicast_rclass(sock, buffer, capacity, rclass, answer, authority,
										authority_count, additional, additional_count);
}

static int
mDNS::goodbye_multicast
	(const int sock,
	void * buffer,
	const size_t capacity,
	const record_t & answer,
	record_t * authority,
	const size_t authority_count,
	record_t * additional,
	const size_t additional_count)
{
	uint16_t rclass = (mDNS::kClassTypeIn | MDNS_CACHE_FLUSH);

	return mdns_answer_multicast_rclass_ttl(sock, buffer, capacity, rclass, answer, authority,
											authority_count, additional, additional_count, 0);
}

static mDNS::string_t
mDNS::record_parse_ptr
	(const void * buffer,
	const size_t size,
	const size_t offset,
	const size_t length,
	char * strbuffer,
	const size_t capacity)
{
	// PTR record is just a string
	if ((size >= (offset + length)) && (length >= 2))
	{
		size_t work_offset = offset;

		return mDNS::mDNSPrivate::string_extract(buffer, size, work_offset, strbuffer, capacity);
	
	}
	return make_mdns_string(nullptr, 0);
}

static mDNS::record_srv_t
mDNS::record_parse_srv
	(const void * buffer,
	const size_t size,
	const size_t offset,
	const size_t length,
	char * strbuffer,
	const size_t capacity)
{
	size_t work_offset = offset;
	record_srv_t srv;
	
	memset(&srv, 0, sizeof(srv));
	// Read the service priority, weight, port number and the discovery name
	// SRV record format (http://www.ietf.org/rfc/rfc2782.txt):
	// 2 bytes network-order unsigned priority
	// 2 bytes network-order unsigned weight
	// 2 bytes network-order unsigned port
	// string: discovery (domain) name, minimum 2 bytes when compressed
	if ((size >= (offset + length)) && (length >= 8))
	{
		const uint16_t * recorddata = reinterpret_cast<const uint16_t *>(MDNS_POINTER_OFFSET_CONST(buffer, offset));

		srv.priority = mdns_ntohs(recorddata++);
		srv.weight = mdns_ntohs(recorddata++);
		srv.port = mdns_ntohs(recorddata++);
		work_offset += 6;
		srv.name = mDNS::mDNSPrivate::string_extract(buffer, size, work_offset, strbuffer, capacity);
	}
	return srv;
}

static struct sockaddr_in *
mDNS::record_parse_a
	(const void * buffer,
	const size_t size,
	const size_t offset,
	const size_t length,
	struct sockaddr_in * addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
#if defined(__APPLE__)
	addr->sin_len = sizeof(*addr);
#endif /* defined(__APPLE__) */
	if ((size >= offset + length) && (length == 4))
	{
		memcpy(&addr->sin_addr.s_addr, MDNS_POINTER_OFFSET_CONST(buffer, offset), 4);
	}
	return addr;
}

static struct sockaddr_in6 *
mDNS::record_parse_aaaa
	(const void * buffer,
	const size_t size,
	const size_t offset,
	const size_t length,
	struct sockaddr_in6 * addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
#if defined(__APPLE__)
	addr->sin6_len = sizeof(*addr);
#endif /* defined(__APPLE__) */
	if ((size >= offset + length) && (length == 16))
	{
		memcpy(&addr->sin6_addr, MDNS_POINTER_OFFSET_CONST(buffer, offset), 16);
	}
	return addr;
}

static size_t
mDNS::record_parse_txt
	(const void * buffer,
	const size_t size,
	const size_t offset,
	const size_t length,
	record_txt_t * records,
	const size_t capacity)
{
	size_t work_offset = offset;
	size_t parsed = 0;
	const char * strdata;
	size_t end = work_offset + length;

	if (size < end)
	{
		end = size;
	}
	while ((work_offset < end) && (parsed < capacity))
	{
		strdata = reinterpret_cast<const char *>(MDNS_POINTER_OFFSET_CONST(buffer, work_offset));
		size_t sublength = *reinterpret_cast<const unsigned char *>(strdata);

		++strdata;
		work_offset += sublength + 1;
		size_t separator = 0;

		for (size_t cc = 0; cc < sublength; ++cc)
		{
			// DNS-SD TXT record keys MUST be printable US-ASCII, [0x20, 0x7E]
			if ((strdata[cc] < 0x20) || (strdata[cc] > 0x7E))
			{
				break;
			
			}
			if (strdata[cc] == '=')
			{
				separator = cc;
				break;

			}
		}
		if (0 == separator)
		{
			continue;
		
		}
		if (separator < sublength)
		{
			records[parsed].key.str = strdata;
			records[parsed].key.length = separator;
			records[parsed].value.str = strdata + separator + 1;
			records[parsed].value.length = sublength - (separator + 1);
		}
		else
		{
			records[parsed].key.str = strdata;
			records[parsed].key.length = sublength;
		}
		++parsed;
	}
	return parsed;
}

#if defined(_WIN32)
 #undef strncasecmp
#endif /* defined(_WIN32) */
