#if defined(_WIN32)
 #define _CRT_SECURE_NO_WARNINGS 1
#endif /* defined(_WIN32) */

#include <stdio.h>
#include <errno.h>
#include <memory>

#if defined(_WIN32)
 #include <winsock2.h>
 #include <iphlpapi.h>
 #define sleep(x) Sleep(x * 1000)
#else /* not defined(_WIN32) */
 #include <netdb.h>
 #include <ifaddrs.h>
#endif /* not defined(_WIN32) */

// Alias some things to simulate receiving data to fuzz library
#if defined(MDNS_FUZZING)
 #define recvfrom(sock, buffer, capacity, flags, src_addr, addrlen) static_cast<mDNS::ssize_t_>(capacity)
#endif /* defined(MDNS_FUZZING) */

#include "mdns.hpp"

#if defined(MDNS_FUZZING)
 #undef recvfrom
#endif /* defined(MDNS_FUZZING) */

static const size_t	kNumTxtRecords = 2;

static char               addrbuffer[64];
static char               entrybuffer[256];
static char               namebuffer[256];
static char               sendbuffer[1024];
static mDNS::record_txt_t txtbuffer[128];

static struct sockaddr_in  service_address_ipv4;
static struct sockaddr_in6 service_address_ipv6;

static bool has_ipv4 = false;
static bool has_ipv6 = false;

// Data for our service including the mDNS records
struct service_t
{
	mDNS::string_t      service;
	mDNS::string_t      hostname;
	mDNS::string_t      service_instance;
	mDNS::string_t      hostname_qualified;
	struct sockaddr_in  address_ipv4;
	struct sockaddr_in6 address_ipv6;
	int                 port;
	mDNS::record_t      record_ptr;
	mDNS::record_t      record_srv;
	mDNS::record_t      record_a;
	mDNS::record_t      record_aaaa;
	mDNS::record_t      txt_record[kNumTxtRecords];
};

#define MAKE_MDNS_STRING_C(ss)	make_mdns_string(ss, sizeof(ss) - 1)

//============================ Local functions ==============================
  
static mDNS::string_t
ipv4_address_to_string
	(char *       buffer,
	 const size_t capacity,
	 const struct sockaddr_in & addr,
	 const size_t addrlen)
{
	char host[NI_MAXHOST] = { 0 };
	char service[NI_MAXSERV] = { 0 };
	int	 ret = getnameinfo(reinterpret_cast<const struct sockaddr *>(&addr), static_cast<socklen_t>(addrlen), host, NI_MAXHOST,
	                      service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	int  len = 0;

	if (ret == 0)
	{
		if (addr.sin_port != 0)
		{
			len = snprintf(buffer, capacity, "%s:%s", host, service);
		}
		else
		{
			len = snprintf(buffer, capacity, "%s", host);
		}
	}
	if (len >= static_cast<int>(capacity))
	{
		len = static_cast<int>(capacity) - 1;
	}
	return make_mdns_string(buffer, len);
}

static mDNS::string_t
ipv6_address_to_string
	(char *                      buffer,
	 const size_t                capacity,
	 const struct sockaddr_in6 & addr,
	 const size_t                addrlen)
{
	char host[NI_MAXHOST] = { 0 };
	char service[NI_MAXSERV] = { 0 };
	int  ret = getnameinfo(reinterpret_cast<const struct sockaddr *>(&addr), static_cast<socklen_t>(addrlen), host, NI_MAXHOST,
								 service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	int  len = 0;

	if (ret == 0)
	{
		if (addr.sin6_port != 0)
		{
			len = snprintf(buffer, capacity, "[%s]:%s", host, service);
		}
		else
		{
			len = snprintf(buffer, capacity, "%s", host);
		}
	}
	if (len >= static_cast<int>(capacity))
	{
		len = static_cast<int>(capacity) - 1;
	}
	return make_mdns_string(buffer, len);
}

static mDNS::string_t
ip_address_to_string
	(char *                  buffer,
	 const size_t            capacity,
	 const struct sockaddr & addr,
	 const size_t            addrlen)
{
	if (addr.sa_family == AF_INET6)
	{
		return ipv6_address_to_string(buffer, capacity, reinterpret_cast<const struct sockaddr_in6 &>(addr), addrlen);

	}
	return ipv4_address_to_string(buffer, capacity, reinterpret_cast<const struct sockaddr_in &>(addr), addrlen);
}

// Callback handling parsing answers to queries sent
static int
query_callback
	(const int                UNUSED_PARAM_(sock),
	 const struct sockaddr &  from,
	 const size_t             addrlen,
	 const mDNS::entry_type_t entry,
	 const uint16_t           UNUSED_PARAM_(query_id),
	 const uint16_t           rtype,
	 const uint16_t           rclass,
	 const uint32_t           ttl,
	 const void *             data,
	 const size_t             size,
	 const size_t             name_offset,
	 const size_t             UNUSED_PARAM_(name_length),
	 const size_t             record_offset,
	 const size_t             record_length,
	 void *                   UNUSED_PARAM_(user_data))
{
	size_t	       work_offset = name_offset;
	mDNS::string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
	const char *   entrytype = ((entry == mDNS::kEntryTypeAnswer) ? "answer" :
                                ((entry == mDNS::kEntryTypeAuthority) ? "authority" : "additional"));
	mDNS::string_t entrystr = mDNS::mDNSPrivate::string_extract(data, size, work_offset, entrybuffer, sizeof(entrybuffer));

	if (rtype == mDNS::kRecordTypePTR)
	{
		mDNS::string_t namestr = mDNS::record_parse_ptr(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));

		std::cout << MDNS_STRING_FORMAT(fromaddrstr) << " : " << entrytype << " " << MDNS_STRING_FORMAT(entrystr) << " PTR " <<
					MDNS_STRING_FORMAT(namestr) << " rclass 0x" << std::hex << rclass << std::dec << " ttl " << ttl << " length " <<
					record_length << std::endl;
		release_mdns_string(namestr);
	}
	else if (rtype == mDNS::kRecordTypeSRV)
	{
		mDNS::record_srv_t srv = mDNS::record_parse_srv(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));

		std::cout << MDNS_STRING_FORMAT(fromaddrstr) << " : " << entrytype << " " << MDNS_STRING_FORMAT(entrystr) << " SRV " <<
					MDNS_STRING_FORMAT(entrystr) << " priority " << srv.priority << " weight " << srv.weight << " port " << srv.weight << std::endl;
		release_mdns_string(srv.name);
	}
	else if (rtype == mDNS::kRecordTypeA)
	{
		struct sockaddr_in addr;

		mDNS::record_parse_a(data, size, record_offset, record_length, addr);
		mDNS::string_t addrstr = ipv4_address_to_string(namebuffer, sizeof(namebuffer), addr, sizeof(addr));

		std::cout << MDNS_STRING_FORMAT(fromaddrstr) << " : " << entrytype << " " << MDNS_STRING_FORMAT(entrystr) << " A " <<
					MDNS_STRING_FORMAT(addrstr) << std::endl;
		release_mdns_string(addrstr);
	}
	else if (rtype == mDNS::kRecordTypeAAAA)
	{
		struct sockaddr_in6 addr;

		mDNS::record_parse_aaaa(data, size, record_offset, record_length, addr);
		mDNS::string_t addrstr = ipv6_address_to_string(namebuffer, sizeof(namebuffer), addr, sizeof(addr));

		std::cout << MDNS_STRING_FORMAT(fromaddrstr) << " : " << entrytype << " " << MDNS_STRING_FORMAT(entrystr) << " AAAA " <<
					MDNS_STRING_FORMAT(addrstr) << std::endl;
		release_mdns_string(addrstr);
	}
	else if (rtype == mDNS::kRecordTypeTXT)
	{
		size_t parsed = mDNS::record_parse_txt(data, size, record_offset, record_length, txtbuffer, sizeof(txtbuffer) / sizeof(*txtbuffer));

		for (size_t itxt = 0; itxt < parsed; ++itxt)
		{
			if (txtbuffer[itxt].value.length)
			{
				std::cout << MDNS_STRING_FORMAT(fromaddrstr) << " : " << entrytype << " " << MDNS_STRING_FORMAT(entrystr) << " TXT " <<
							MDNS_STRING_FORMAT(txtbuffer[itxt].key) << " = " << MDNS_STRING_FORMAT(txtbuffer[itxt].value) << std::endl;
			}
			else
			{
				std::cout << MDNS_STRING_FORMAT(fromaddrstr) << " : " << entrytype << " " << MDNS_STRING_FORMAT(entrystr) << " TXT " <<
							MDNS_STRING_FORMAT(txtbuffer[itxt].key) << std::endl;
			}
			release_mdns_string(txtbuffer[itxt].key);
			release_mdns_string(txtbuffer[itxt].value);
		}
	}
	else
	{
		std::cout << MDNS_STRING_FORMAT(fromaddrstr) << " : " << entrytype << " " << MDNS_STRING_FORMAT(entrystr) << " type " << rtype <<
					" rclass 0x" << std::hex << rclass << std::dec << " ttl " << ttl << " length " << record_length << std::endl;
	}
	release_mdns_string(fromaddrstr);
	release_mdns_string(entrystr);
	return 0;
}

// Callback handling questions incoming on service sockets
static int
service_callback
	(const int                sock,
	 const struct sockaddr &  from,
	 const size_t             addrlen,
	 const mDNS::entry_type_t entry,
	 const uint16_t           query_id,
	 const uint16_t           rtype,
	 const uint16_t           rclass,
	 const uint32_t           UNUSED_PARAM_(ttl),
	 const void *             data,
	 const size_t             size,
	 const size_t             name_offset,
	 const size_t             name_length,
	 const size_t             record_offset,
	 const size_t             record_length,
	 void *                   user_data)
{
	if (entry != mDNS::kEntryTypeQuestion)
	{
		return 0;

	}
	const char        dns_sd[] = "_services._dns-sd._udp.local.";
	const service_t * servicePtr = reinterpret_cast<const service_t *>(user_data);
	const service_t & service = *servicePtr;
	//mDNS::string_t    fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
	size_t            offset = name_offset;
	mDNS::string_t    name = mDNS::mDNSPrivate::string_extract(data, size, offset, namebuffer, sizeof(namebuffer));
	const char *      record_name = nullptr;
	bool              unicast = (0 != (rclass & MDNS_UNICAST_RESPONSE));
	int               res = 0;

	if (rtype == mDNS::kRecordTypePTR)
	{
		record_name = "PTR";
	}
	else if (rtype == mDNS::kRecordTypeSRV)
	{
		record_name = "SRV";
	}
	else if (rtype == mDNS::kRecordTypeA)
	{
		record_name = "A";
	}
	else if (rtype == mDNS::kRecordTypeAAAA)
	{
		record_name = "AAAA";
	}
	else if (rtype == mDNS::kRecordTypeANY)
	{
		record_name = "ANY";
	}
	else
	{
		release_mdns_string(name);
		return 0;

	}
	std::cout << "Query " << record_name << " " << MDNS_STRING_FORMAT(name) << std::endl;
	if ((name.length == (sizeof(dns_sd) - 1)) && (strncmp(name.str, dns_sd, name.length) == 0))
	{
		if ((rtype == mDNS::kRecordTypePTR) || (rtype == mDNS::kRecordTypeANY))
		{
			// The PTR query was for the DNS-SD domain, send answer with a PTR record for the
			// service name we advertise, typically in the "<_service-name>._tcp.local." format

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
			mDNS::record_t answer;

			answer.name = name; // answer is not being retained, so we can just 'borrow' the strings.
			answer.type = mDNS::kRecordTypePTR;
			answer.data.ptr.name = service.service;
			// Send the answer, unicast or multicast depending on flag in query
			std::cout << "  --> answer " << MDNS_STRING_FORMAT(answer.data.ptr.name) << " (" << (unicast ? "unicast" : "multicast") << ")" <<
						std::endl;
			if (unicast)
			{
				res = mDNS::query_answer_unicast(sock, &from, addrlen, sendbuffer, sizeof(sendbuffer),
				                          		query_id, static_cast<mDNS::record_type_t>(rtype), name.str, name.length, answer, 0, 0, 0, 0);
			}
			else
			{
				res = mDNS::query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, 0, 0);
			}
		}
	}
	else if ((name.length == service.service.length) && (strncmp(name.str, service.service.str, name.length) == 0))
	{
		if ((rtype == mDNS::kRecordTypePTR) || (rtype == mDNS::kRecordTypeANY))
		{
			// The PTR query was for our service (usually "<_service-name._tcp.local"), answer a PTR
			// record reverse mapping the queried service name to our service instance name
			// (typically on the "<hostname>.<_service-name>._tcp.local." format), and add
			// additional records containing the SRV record mapping the service instance name to our
			// qualified hostname (typically "<hostname>.local.") and port, as well as any IPv4/IPv6
			// address for the hostname as A/AAAA records, and two test TXT records

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
			mDNS::record_t answer = service.record_ptr;
			mDNS::record_t additional[kNumTxtRecords + 3] = { 0 };
			size_t         additional_count = 0;

			// SRV record mapping "<hostname>.<_service-name>._tcp.local." to
			// "<hostname>.local." with port. Set weight & priority to 0.
			additional[additional_count++] = service.record_srv;
			// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
			if (service.address_ipv4.sin_family == AF_INET)
			{
				additional[additional_count++] = service.record_a;
			}
			if (service.address_ipv6.sin6_family == AF_INET6)
			{
				additional[additional_count++] = service.record_aaaa;
			}
			// Add two test TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			for (size_t ii = 0; ii < kNumTxtRecords; ++ii)
			{
				additional[additional_count++] = service.txt_record[ii];
			} 
			// Send the answer, unicast or multicast depending on flag in query
			std::cout << "  --> answer " << MDNS_STRING_FORMAT(service.record_ptr.data.ptr.name) << " (" << (unicast ? "unicast" : "multicast") <<
						")" << std::endl;
			if (unicast)
			{
				res = mDNS::query_answer_unicast(sock, &from, addrlen, sendbuffer, sizeof(sendbuffer),
												query_id, static_cast<mDNS::record_type_t>(rtype), name.str, name.length, answer, 0, 0,
												additional, additional_count);
			}
			else
			{
				res = mDNS::query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, additional, additional_count);
			}
		}
	}
	else if ((name.length == service.service_instance.length) && (strncmp(name.str, service.service_instance.str, name.length) == 0))
	{
		if ((rtype == mDNS::kRecordTypeSRV) || (rtype == mDNS::kRecordTypeANY))
		{
			// The SRV query was for our service instance (usually
			// "<hostname>.<_service-name._tcp.local"), answer a SRV record mapping the service
			// instance name to our qualified hostname (typically "<hostname>.local.") and port, as
			// well as any IPv4/IPv6 address for the hostname as A/AAAA records, and two test TXT
			// records

			// Answer PTR record reverse mapping "<_service-name>._tcp.local." to
			// "<hostname>.<_service-name>._tcp.local."
			mDNS::record_t answer = service.record_srv;
			mDNS::record_t additional[kNumTxtRecords + 3] = { 0 };
			size_t         additional_count = 0;

			// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
			if (service.address_ipv4.sin_family == AF_INET)
			{
				additional[additional_count++] = service.record_a;
			}
			if (service.address_ipv6.sin6_family == AF_INET6)
			{
				additional[additional_count++] = service.record_aaaa;
			}
			// Add two test TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			for (size_t ii = 0; ii < kNumTxtRecords; ++ii)
			{
				additional[additional_count++] = service.txt_record[ii];
			} 
			// Send the answer, unicast or multicast depending on flag in query
			std::cout << "  --> answer " << MDNS_STRING_FORMAT(service.record_srv.data.srv.name) << " port " << service.port << " (" <<
						(unicast ? "unicast" : "multicast") << ")" << std::endl;
			if (unicast)
			{
				res = mDNS::query_answer_unicast(sock, &from, addrlen, sendbuffer, sizeof(sendbuffer),
												query_id, static_cast<mDNS::record_type_t>(rtype), name.str, name.length, answer, 0, 0,
												additional, additional_count);
			}
			else
			{
				res = mDNS::query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, additional, additional_count);
			}
		}
	}
	else if ((name.length == service.hostname_qualified.length) &&
	           (strncmp(name.str, service.hostname_qualified.str, name.length) == 0))
	{
		if (((rtype == mDNS::kRecordTypeA) || (rtype == mDNS::kRecordTypeANY)) && (service.address_ipv4.sin_family == AF_INET))
		{
			// The A query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv4 address, answer with an A record mappiing the hostname to an IPv4
			// address, as well as any IPv6 address for the hostname, and two test TXT records

			// Answer A records mapping "<hostname>.local." to IPv4 address
			mDNS::record_t answer = service.record_a;
			mDNS::record_t additional[kNumTxtRecords + 3] = { 0 };
			size_t         additional_count = 0;

			// AAAA record mapping "<hostname>.local." to IPv6 addresses
			if (service.address_ipv6.sin6_family == AF_INET6)
			{
				additional[additional_count++] = service.record_aaaa;
			}
			// Add two test TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			for (size_t ii = 0; ii < kNumTxtRecords; ++ii)
			{
				additional[additional_count++] = service.txt_record[ii];
			}
			// Send the answer, unicast or multicast depending on flag in query
			mDNS::string_t addrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer),
															reinterpret_cast<const struct sockaddr &>(service.record_a.data.a.addr),
			    											sizeof(service.record_a.data.a.addr));

			std::cout << "  --> answer " << MDNS_STRING_FORMAT(service.record_a.name) << " IPv4 " << MDNS_STRING_FORMAT(addrstr) << " (" <<
						(unicast ? "unicast" : "multicast") << ")" << std::endl;
			if (unicast)
			{
				res = mDNS::query_answer_unicast(sock, &from, addrlen, sendbuffer, sizeof(sendbuffer),
												query_id, static_cast<mDNS::record_type_t>(rtype), name.str, name.length, answer, 0, 0,
												additional, additional_count);
			}
			else
			{
				res = mDNS::query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, additional, additional_count);
			}
			release_mdns_string(addrstr);
		}
		else if (((rtype == mDNS::kRecordTypeAAAA) || (rtype == mDNS::kRecordTypeANY)) && (service.address_ipv6.sin6_family == AF_INET6))
		{
			// The AAAA query was for our qualified hostname (typically "<hostname>.local.") and we
			// have an IPv6 address, answer with an AAAA record mappiing the hostname to an IPv6
			// address, as well as any IPv4 address for the hostname, and two test TXT records

			// Answer AAAA records mapping "<hostname>.local." to IPv6 address
			mDNS::record_t answer = service.record_aaaa;
			mDNS::record_t additional[kNumTxtRecords + 3] = { 0 };
			size_t         additional_count = 0;

			// A record mapping "<hostname>.local." to IPv4 addresses
			if (service.address_ipv4.sin_family == AF_INET)
			{
				additional[additional_count++] = service.record_a;
			}
			// Add two test TXT records for our service instance name, will be coalesced into
			// one record with both key-value pair strings by the library
			for (size_t ii = 0; ii < kNumTxtRecords; ++ii)
			{
				additional[additional_count++] = service.txt_record[ii];
			}
			// Send the answer, unicast or multicast depending on flag in query
			mDNS::string_t addrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer),
																reinterpret_cast<const struct sockaddr &>(service.record_aaaa.data.aaaa.addr),
			                         					sizeof(service.record_aaaa.data.aaaa.addr));

			std::cout << "  --> answer " << MDNS_STRING_FORMAT(service.record_aaaa.name) << " IPv6 " << MDNS_STRING_FORMAT(addrstr) << " (" <<
						(unicast ? "unicast" : "multicast") << ")" << std::endl;
			if (unicast)
			{
				res = mDNS::query_answer_unicast(sock, &from, addrlen, sendbuffer, sizeof(sendbuffer),
												query_id, static_cast<mDNS::record_type_t>(rtype), name.str, name.length, answer, 0, 0,
												additional, additional_count);
			}
			else
			{
				res = mDNS::query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, additional, additional_count);
			}
			release_mdns_string(addrstr);
		}
		if (0 != res)
		{
			std::cout << "fault during " << (unicast ? "unicast" : "multicast") << " send" << std::endl;
		}
	}
	release_mdns_string(name);
	return 0;
}

// Open sockets for sending one-shot multicast queries from an ephemeral port
static int
open_client_sockets
	(int *     sockets,
	 const int max_sockets,
	 const int port)
{
	// When sending, each socket can only send to one network interface
	// Thus we need to open one socket for each interface and address family
	int num_sockets = 0;
#if defined(_WIN32)
	IP_ADAPTER_ADDRESSES * adapter_address = nullptr;
	ULONG                  address_size = 8000;
	unsigned int           ret;
	unsigned int           num_retries = 4;

	do
	{
		adapter_address = static_cast<IP_ADAPTER_ADDRESSES *>(malloc(address_size));
		ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0,
		                           adapter_address, &address_size);
		if (ret == ERROR_BUFFER_OVERFLOW)
		{
			free(adapter_address);
			adapter_address = 0;
			address_size *= 2;
		}
		else
		{
			break;

		}
	}
	while (num_retries-- > 0);
	if ((nullptr == adapter_address) || (ret != NO_ERROR))
	{
		free(adapter_address);
		std::cout << "Failed to get network adapter addresses" << std::endl;
		return num_sockets;

	}
	bool first_ipv4 = true;
	bool first_ipv6 = true;

	for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next)
	{
		if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
		{
			continue;

		}
		if (adapter->OperStatus != IfOperStatusUp)
		{
			continue;
		
		}
		for (IP_ADAPTER_UNICAST_ADDRESS * unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next)
		{
			if (unicast->Address.lpSockaddr->sa_family == AF_INET)
			{
				struct sockaddr_in & saddr = *reinterpret_cast<struct sockaddr_in *>(unicast->Address.lpSockaddr);

				if ((saddr.sin_addr.S_un.S_un_b.s_b1 != 127) || (saddr.sin_addr.S_un.S_un_b.s_b2 != 0) ||
					 (saddr.sin_addr.S_un.S_un_b.s_b3 != 0) || (saddr.sin_addr.S_un.S_un_b.s_b4 != 1))
				{
					bool log_addr = false;

					if (first_ipv4)
					{
						service_address_ipv4 = saddr;
						first_ipv4 = false;
						log_addr = true;
					}
					has_ipv4 = true;
					if (num_sockets < max_sockets)
					{
						saddr.sin_port = htons(static_cast<unsigned short>(port));
						int sock = mDNS::socket_open_ipv4(saddr);
						if (sock >= 0)
						{
							sockets[num_sockets++] = sock;
							log_addr = true;
						}
						else
						{
							log_addr = false;
						}
					}
					if (log_addr)
					{
						char buffer[128];
						string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr, sizeof(saddr));

						std::cout << "Local IPv4 address: " << MDNS_STRING_FORMAT(addr) << std::endl;
						release_mdns_string(addr);
					}
				}
			}
			else if (unicast->Address.lpSockaddr->sa_family == AF_INET6)
			{
				struct sockaddr_in6 &      saddr = *reinterpret_cast<struct sockaddr_in6 *>(unicast->Address.lpSockaddr);
				static const unsigned char localhost[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
				static const unsigned char localhost_mapped[] = { 0, 0, 0,    0,    0,    0, 0, 0,
				                                                  0, 0, 0xff, 0xff, 0x7f, 0, 0, 1 };

				if ((unicast->DadState == NldsPreferred) &&
					 memcmp(saddr.sin6_addr.s6_addr, localhost, 16) &&
					 memcmp(saddr.sin6_addr.s6_addr, localhost_mapped, 16))
				{
					bool log_addr = false;

					if (first_ipv6)
					{
						service_address_ipv6 = *saddr;
						first_ipv6 = false;
						log_addr = true;
					}
					has_ipv6 = true;
					if (num_sockets < max_sockets)
					{
						saddr.sin6_port = htons(static_cast<unsigned short>(port));
						int sock = mDNS::socket_open_ipv6(saddr);

						if (sock >= 0)
						{
							sockets[num_sockets++] = sock;
							log_addr = true;
						}
						else
						{
							log_addr = false;
						}
					}
					if (log_addr)
					{
						char     buffer[128];
						string_t addr = ipv6_address_to_string(buffer, sizeof(buffer), saddr, sizeof(saddr));

						std::cout << "Local IPv6 address: " << MDNS_STRING_FORMAT(addr) << std::endl;
						release_mdns_string(addr);
					}
				}
			}
		}
	}
	free(adapter_address);
#else /* not defined(_WIN32) */
	struct ifaddrs * ifaddr = nullptr;
	struct ifaddrs * ifa = nullptr;

	if (getifaddrs(&ifaddr) < 0)
	{
		std::cout << "Unable to get interface addresses" << std::endl;
	}
	bool first_ipv4 = true;
	bool first_ipv6 = true;

	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next)
	{
		if (nullptr == ifa->ifa_addr)
		{
			continue;

		}
		if (ifa->ifa_addr->sa_family == AF_INET)
		{
			struct sockaddr_in & saddr = *reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);

			if (saddr.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
			{
				bool log_addr = false;

				if (first_ipv4)
				{
					service_address_ipv4 = saddr;
					first_ipv4 = false;
					log_addr = true;
				}
				has_ipv4 = true;
				if (num_sockets < max_sockets)
				{
					saddr.sin_port = htons(port);
					int sock = mDNS::socket_open_ipv4(saddr);

					if (sock >= 0)
					{
						sockets[num_sockets++] = sock;
						log_addr = true;
					}
					else
					{
						log_addr = false;
					}
				}
				if (log_addr)
				{
					char           buffer[128];
					mDNS::string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr, sizeof(saddr));

					std::cout << "Local IPv4 address: " << MDNS_STRING_FORMAT(addr) << std::endl;
					release_mdns_string(addr);
				}
			}
		}
		else if (ifa->ifa_addr->sa_family == AF_INET6)
		{
			struct sockaddr_in6 &      saddr = *reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr);
			static const unsigned char localhost[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
			static const unsigned char localhost_mapped[] = { 0, 0, 0,    0,    0,    0, 0, 0,
															  0, 0, 0xff, 0xff, 0x7f, 0, 0, 1 };

			if (memcmp(saddr.sin6_addr.s6_addr, localhost, 16) &&
				 memcmp(saddr.sin6_addr.s6_addr, localhost_mapped, 16))
			{
				bool log_addr = false;

				if (first_ipv6)
				{
					service_address_ipv6 = saddr;
					first_ipv6 = false;
					log_addr = true;
				}
				has_ipv6 = true;
				if (num_sockets < max_sockets)
				{
					saddr.sin6_port = htons(port);
					int sock = mDNS::socket_open_ipv6(saddr);

					if (sock >= 0)
					{
						sockets[num_sockets++] = sock;
						log_addr = true;
					}
					else
					{
						log_addr = false;
					}
				}
				if (log_addr)
				{
					char           buffer[128];
					mDNS::string_t addr = ipv6_address_to_string(buffer, sizeof(buffer), saddr, sizeof(saddr));

					std::cout << "Local IPv6 address: " << MDNS_STRING_FORMAT(addr) << std::endl;
					release_mdns_string(addr);
				}
			}
		}
	}
	freeifaddrs(ifaddr);
#endif /* not defined(_WIN32) */
	return num_sockets;
}

// Open sockets to listen to incoming mDNS queries on port 5353
static int
open_service_sockets
	(int *     sockets,
	 const int max_sockets)
{
	// When recieving, each socket can recieve data from all network interfaces
	// Thus we only need to open one socket for each address family
	int num_sockets = 0;

	// Call the client socket function to enumerate and get local addresses,
	// but not open the actual sockets
	open_client_sockets(0, 0, 0);
	if (num_sockets < max_sockets)
	{
		struct sockaddr_in sock_addr;

		memset(&sock_addr, 0, sizeof(sock_addr));
		sock_addr.sin_family = AF_INET;
#if defined(_WIN32)
		sock_addr.sin_addr = in4addr_any;
#else /* not defined(_WIN32) */
		sock_addr.sin_addr.s_addr = INADDR_ANY;
#endif /* not defined(_WIN32) */
		sock_addr.sin_port = htons(MDNS_PORT);
#if defined(__APPLE__)
		sock_addr.sin_len = sizeof(sock_addr);
#endif /* defined(__APPLE__) */
		int sock = mDNS::socket_open_ipv4(sock_addr);

		if (sock >= 0)
		{
			sockets[num_sockets++] = sock;
		}
	}
	if (num_sockets < max_sockets)
	{
		struct sockaddr_in6 sock_addr;

		memset(&sock_addr, 0, sizeof(sock_addr));
		sock_addr.sin6_family = AF_INET6;
		sock_addr.sin6_addr = in6addr_any;
		sock_addr.sin6_port = htons(MDNS_PORT);
#if defined(__APPLE__)
		sock_addr.sin6_len = sizeof(sock_addr);
#endif /* defined(__APPLE__) */
		int sock = mDNS::socket_open_ipv6(sock_addr);

		if (sock >= 0)
		{
			sockets[num_sockets++] = sock;
		}
	}
	return num_sockets;
}

// Add application-specific conditions to stop looping.
static bool interrupted
	(void)
{
	return false;
}

// Send a DNS-SD query
static int
send_dns_sd
	(void)
{
	int sockets[32];
	int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(*sockets), 0);

	if (num_sockets <= 0)
	{
		std::cout << "Failed to open any client sockets" << std::endl;
		return -1;

	}
	std::cout << "Opened " << num_sockets << " socket" << ((num_sockets > 1) ? "s" : "") << " for DNS-SD" << std::endl;
	std::cout << "Sending DNS-SD discovery" << std::endl;
	for (int isock = 0; isock < num_sockets; ++isock)
	{
		if (mDNS::discovery_send(sockets[isock]))
		{
			std::cout << "Failed to send DNS-DS discovery: " << strerror(errno) << std::endl;
		}
	}
	size_t                   capacity = 2048;
	std::unique_ptr<uint8_t> buffer(new uint8_t[capacity]);
	void *                   user_data = nullptr;
	size_t                   records;
	// This is a simple implementation that loops for 5 seconds or as long as we get replies
	int                      res;

	std::cout << "Reading DNS-SD replies" << std::endl;
	do
	{
		struct timeval timeout;

		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		int    nfds = 0;
		fd_set readfs;

		FD_ZERO(&readfs);
		for (int isock = 0; isock < num_sockets; ++isock)
		{
			if (sockets[isock] >= nfds)
			{
				nfds = sockets[isock] + 1;
			}
			FD_SET(sockets[isock], &readfs);
		}
		records = 0;
		res = select(nfds, &readfs, 0, 0, &timeout);
		if (res > 0)
		{
			for (int isock = 0; isock < num_sockets; ++isock)
			{
				if (FD_ISSET(sockets[isock], &readfs))
				{
					records += mDNS::discovery_recv(sockets[isock], buffer.get(), capacity, query_callback, user_data);
				}
			}
		}
	}
	while (res > 0);
	for (int isock = 0; isock < num_sockets; ++isock)
	{
		mDNS::socket_close(sockets[isock]);
	}
	std::cout << "Closed socket" << (num_sockets ? "s" : "") << std::endl;
	return 0;
}

// Send an mDNS query
static int
send_mdns_query
	(const char * service,
	 const int    record)
{
	int work_record = record;
	int sockets[32];
	int query_id[32];
	int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(*sockets), 0);

	if (num_sockets <= 0)
	{
		std::cout << "Failed to open any client sockets" << std::endl;
		return -1;

	}
	std::cout << "Opened " << num_sockets << " socket" << (num_sockets ? "s" : "") << " for mDNS query" << std::endl;
	size_t                   capacity = 2048;
	std::unique_ptr<uint8_t> buffer(new uint8_t[capacity]);
	void *                   user_data = nullptr;
	size_t                   records;
	const char *             record_name;

	if (work_record == mDNS::kRecordTypeSRV)
	{
		record_name = "SRV";
	}
	else if (work_record == mDNS::kRecordTypeA)
	{
		record_name = "A";
	}
	else if (work_record == mDNS::kRecordTypeAAAA)
	{
		record_name = "AAAA";
	}
	else
	{
		record_name = "PTR";
		work_record = mDNS::kRecordTypePTR;
	}
	std::cout << "Sending mDNS query: " << service << " " << record_name << std::endl;
	for (int isock = 0; isock < num_sockets; ++isock)
	{
		query_id[isock] = mDNS::query_send(sockets[isock], static_cast<mDNS::record_type_t>(work_record), service, strlen(service), buffer.get(), capacity, 0);
		if (query_id[isock] < 0)
		{
			std::cout << "Failed to send mDNS query: " << strerror(errno) << std::endl;
		}
	}
	// This is a simple implementation that loops for 10 seconds or as long as we get replies
	struct timeval timeout;

	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
	int res;

	std::cout << "Reading mDNS query replies" << std::endl;
	do
	{
		if (interrupted())
		{
			break;

		}
		int    nfds = 0;
		fd_set readfs;

		FD_ZERO(&readfs);
		for (int isock = 0; isock < num_sockets; ++isock)
		{
			if (interrupted())
			{
				break;

			}
			if (sockets[isock] >= nfds)
			{
				nfds = sockets[isock] + 1;
			}
			FD_SET(sockets[isock], &readfs);
		}
		records = 0;
		res = select(nfds, &readfs, nullptr, nullptr, &timeout);
		if (res > 0)
		{
			for (int isock = 0; isock < num_sockets; ++isock)
			{
				if (interrupted())
				{
					break;

				}
				if (FD_ISSET(sockets[isock], &readfs))
				{
					records += mDNS::query_recv(sockets[isock], buffer.get(), capacity, query_callback, user_data, query_id[isock]);
				}
				FD_SET(sockets[isock], &readfs);
			}
		}
	}
	while (res > 0);
	for (int isock = 0; isock < num_sockets; ++isock)
	{
		mDNS::socket_close(sockets[isock]);
	}
	std::cout << "Closed socket" << (num_sockets ? "s" : "") << std::endl;
	return 0;
}

static int
do_setup
	(const char * service_name,
	 const int    service_port,
	 const char * hostname,
	 service_t &  service,
	 int &        num_sockets,
	 const size_t max_sockets,
	 int *        sockets,
	 void * &     buffer,
	 const size_t capacity,
	 char * &     service_name_buffer)
{
	num_sockets = open_service_sockets(sockets, max_sockets);
	if (num_sockets <= 0)
	{
		std::cout << "Failed to open any client sockets" << std::endl;
		return -1;

	}
	std::cout << "Opened " << num_sockets << " socket" << (num_sockets ? "s" : "") << " for mDNS service" << std::endl;
	size_t service_name_length = strlen(service_name);

	if (0 == service_name_length)
	{
		std::cout << "Invalid service name" << std::endl;
		return -1;

	}
	service_name_buffer = static_cast<char *>(malloc(service_name_length + 2));
	memcpy(service_name_buffer, service_name, service_name_length);
	if (service_name_buffer[service_name_length - 1] != '.')
	{
		service_name_buffer[service_name_length++] = '.';
	}
	service_name_buffer[service_name_length] = 0;
	std::cout << "Service mDNS: " << service_name_buffer << ":" << service_port << std::endl;
	std::cout << "Hostname: " << hostname << std::endl;
	buffer = malloc(capacity);
	mDNS::string_t service_string = make_mdns_string(service_name_buffer);
	mDNS::string_t hostname_string = make_mdns_string(hostname);
	// Build the service instance "<hostname>.<_service-name>._tcp.local." string
	std::string    service_instance_buffer(hostname_string.str);

	service_instance_buffer += ".";
	service_instance_buffer += service_string.str;
	mDNS::string_t service_instance_string = make_mdns_string(service_instance_buffer.c_str());
	// Build the "<hostname>.local." string
	std::string    qualified_hostname_buffer(hostname_string.str);

	qualified_hostname_buffer += ".local.";
	mDNS::string_t hostname_qualified_string = make_mdns_string(qualified_hostname_buffer.c_str());

	service.service = make_mdns_string(service_string);
	service.hostname = make_mdns_string(hostname_string);
	service.service_instance = make_mdns_string(service_instance_string);
	service.hostname_qualified = make_mdns_string(hostname_qualified_string);
	service.address_ipv4 = service_address_ipv4;
	service.address_ipv6 = service_address_ipv6;
	service.port = service_port;
	release_mdns_string(service_string);
	release_mdns_string(hostname_string);
	release_mdns_string(service_instance_string);
	release_mdns_string(hostname_qualified_string);

	// Setup our mDNS records

	// PTR record reverse mapping "<_service-name>._tcp.local." to
	// "<hostname>.<_service-name>._tcp.local."
	service.record_ptr.name = make_mdns_string(service.service);
	service.record_ptr.type = mDNS::kRecordTypePTR;
	service.record_ptr.data.ptr.name = make_mdns_string(service.service_instance);
	// SRV record mapping "<hostname>.<_service-name>._tcp.local." to
	// "<hostname>.local." with port. Set weight & priority to 0.
	service.record_srv.name = make_mdns_string(service.service_instance);
	service.record_srv.type = mDNS::kRecordTypeSRV;
	service.record_srv.data.srv.name = make_mdns_string(service.hostname_qualified);
	service.record_srv.data.srv.port = service.port;
	service.record_srv.data.srv.priority = 0;
	service.record_srv.data.srv.weight = 0;	
	// A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
	service.record_a.name = make_mdns_string(service.hostname_qualified);
	service.record_a.type = mDNS::kRecordTypeA;
	service.record_a.data.a.addr = service.address_ipv4;
	service.record_aaaa.name = make_mdns_string(service.hostname_qualified);
	service.record_aaaa.type = mDNS::kRecordTypeAAAA;
	service.record_aaaa.data.aaaa.addr = service.address_ipv6;
	// Add two test TXT records for our service instance name, will be coalesced into
	// one record with both key-value pair strings by the library
	service.txt_record[0].name = make_mdns_string(service.service_instance);
	service.txt_record[0].type = mDNS::kRecordTypeTXT;
	service.txt_record[0].data.txt.key = MAKE_MDNS_STRING_C("test");
	service.txt_record[0].data.txt.value = MAKE_MDNS_STRING_C("1");
	service.txt_record[1].name = make_mdns_string(service.service_instance);
	service.txt_record[1].type = mDNS::kRecordTypeTXT;
	service.txt_record[1].data.txt.key = MAKE_MDNS_STRING_C("other");
	service.txt_record[1].data.txt.value = MAKE_MDNS_STRING_C("value");
	// Send an announcement on startup of service
	mDNS::record_t additional[kNumTxtRecords + 3] = { 0 };
	size_t         additional_count = 0;

	additional[additional_count++] = service.record_srv;
	if (service.address_ipv4.sin_family == AF_INET)
	{
		additional[additional_count++] = service.record_a;
	}
	if (service.address_ipv6.sin6_family == AF_INET6)
	{
		additional[additional_count++] = service.record_aaaa;
	}
	for (size_t ii = 0; ii < kNumTxtRecords; ++ii)
	{
		additional[additional_count++] = service.txt_record[ii];
	} 
	for (int isock = 0; isock < num_sockets; ++isock)
	{
		mDNS::announce_multicast(sockets[isock], buffer, capacity, service.record_ptr, 0, 0, additional, additional_count);
	}
	return 0;
}

static void
do_cleanup
	(service_t &  service,
	 const int    num_sockets,
	 int *        sockets,
	 void *       buffer,
	 const size_t capacity,
	 char *       service_name_buffer)
{
	// Send a goodbye on end of service
	mDNS::record_t additional[kNumTxtRecords + 3] = { 0 };
	size_t         additional_count = 0;

	additional[additional_count++] = service.record_srv;
	if (service.address_ipv4.sin_family == AF_INET)
	{
		additional[additional_count++] = service.record_a;
	}
	if (service.address_ipv6.sin6_family == AF_INET6)
	{
		additional[additional_count++] = service.record_aaaa;
	}
	for (size_t ii = 0; ii < kNumTxtRecords; ++ii)
	{
		additional[additional_count++] = service.txt_record[ii];
	} 
	for (int isock = 0; isock < num_sockets; ++isock)
	{
		mDNS::goodbye_multicast(sockets[isock], buffer, capacity, service.record_ptr, 0, 0, additional, additional_count);
	}
	free(buffer);
	free(service_name_buffer);
	for (int isock = 0; isock < num_sockets; ++isock)
	{
		mDNS::socket_close(sockets[isock]);
	}
	std::cout << "Closed socket" << (num_sockets ? "s" : "") << std::endl;
	release_mdns_string(service.service);
	release_mdns_string(service.hostname);
	release_mdns_string(service.service_instance);
	release_mdns_string(service.hostname_qualified);
	release_mdns_string(service.record_ptr.name);	
	release_mdns_string(service.record_ptr.data.ptr.name);	
	release_mdns_string(service.record_srv.name);	
	release_mdns_string(service.record_srv.data.srv.name);	
	release_mdns_string(service.record_a.name);	
	release_mdns_string(service.record_aaaa.name);	
	for (size_t ii = 0; ii < kNumTxtRecords; ++ii)
	{
		release_mdns_string(service.txt_record[ii].name);	
		release_mdns_string(service.txt_record[ii].data.txt.key);	
		release_mdns_string(service.txt_record[ii].data.txt.value);	
	}
}

// Provide an mDNS service, answering incoming DNS-SD and mDNS queries
static int
service_mdns
	(const char * hostname,
	 const char * service_name,
	 const int    service_port)
{
	service_t service = { 0 };
	int       sockets[32];
	int       num_sockets = 0;
	size_t    capacity = 2048;
	void *    buffer = malloc(capacity);
	char *    service_name_buffer = nullptr;
	int       res = do_setup(service_name, service_port, hostname, service, num_sockets,
						sizeof(sockets) / sizeof(*sockets), sockets, buffer, capacity, service_name_buffer);

	if (0 == res)
	{
		struct timeval timeout;

		timeout.tv_sec = 2;
		timeout.tv_usec = 0;
		// This is a crude implementation that checks for incoming queries
		while (true)
		{
			if (interrupted())
			{
				break;

			}
			int    nfds = 0;
			fd_set readfs;

			FD_ZERO(&readfs);
			for (int isock = 0; isock < num_sockets; ++isock)
			{
				if (interrupted())
				{
					break;

				}
				if (sockets[isock] >= nfds)
				{
					nfds = sockets[isock] + 1;
				}
				FD_SET(sockets[isock], &readfs);
			}
			if (! interrupted())
			{
				int res = select(nfds, &readfs, nullptr, nullptr, &timeout);
				
				if (res >= 0)
				{
					for (int isock = 0; (0 < res) && (isock < num_sockets); ++isock)
					{
						if (interrupted())
						{
							break;

						}
						if (FD_ISSET(sockets[isock], &readfs))
						{
							mDNS::socket_listen(sockets[isock], buffer, capacity, service_callback, &service);
						}
						FD_SET(sockets[isock], &readfs);
					}
				}
				else
				{
					break;

				}
			}
		}
		do_cleanup(service, num_sockets, sockets, buffer, capacity, service_name_buffer);
	}
	return 0;
}

#if defined(MDNS_FUZZING)
// Fuzzing by piping random data into the receive functions
static void
fuzz_mdns
	(void)
{
 #define MAX_FUZZ_SIZE 4096
 #define MAX_PASSES    (1024 * 1024 * 1024)

	static uint8_t fuzz_mdns_services_query[] =
	{
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, '_',
	    's',  'e',  'r',  'v',  'i',  'c',  'e',  's',  0x07, '_',  'd',  'n',  's',  '-',
	    's',  'd',  0x04, '_',  'u',  'd',  'p',  0x05, 'l',  'o',  'c',  'a',  'l',  0x00
	};
	std::unique_ptr<uint8_t> buffer(new uint8_t[MAX_FUZZ_SIZE]);
	std::unique_ptr<uint8_t> strbuffer(new uint8_t[MAX_FUZZ_SIZE]);

	for (int ipass = 0; ipass < MAX_PASSES; ++ipass)
	{
		size_t size = (rand() % MAX_FUZZ_SIZE);

		for (size_t ii = 0; ii < size; ++ii)
		{
			buffer.get()[ii] = (rand() & 0xFF);
		}
		if (ipass % 4)
		{
			// Crafted fuzzing, make sure header is reasonable
			memcpy(buffer.get(), fuzz_mdns_services_query, sizeof(fuzz_mdns_services_query));
			uint16_t * header = reinterpret_cast<uint16_t *>(buffer.get());

			header[0] = 0;
			header[1] = htons(0x8400);
			for (int ival = 2; ival < 6; ++ival)
			{
				header[ival] = rand() & 0xFF;
			}
		}
		mDNS::discovery_recv(0, reinterpret_cast<void *>(buffer.get()), size, query_callback, 0);
		mDNS::socket_listen(0, reinterpret_cast<void *>(buffer.get()), size, service_callback, 0);
		if (ipass % 4)
		{
			// Crafted fuzzing, make sure header is reasonable (1 question claimed).
			// Earlier passes will have done completely random data
			uint16_t * header = reinterpret_cast<uint16_t *>(buffer.get());

			header[2] = htons(1);
		}
		mDNS::query_recv(0, reinterpret_cast<void *>(buffer.get()), size, query_callback, 0, 0);
		// Fuzzing by piping random data into the parse functions
		size_t offset = (size ? (rand() % size) : 0);
		size_t length = (size ? (rand() % (size - offset)) : 0);

		mDNS::record_parse_ptr(buffer.get(), size, offset, length, strbuffer.get(), MAX_FUZZ_SIZE);
		offset = (size ? (rand() % size) : 0);
		length = (size ? (rand() % (size - offset)) : 0);

		mDNS::record_parse_srv(buffer.get(), size, offset, length, strbuffer.get(), MAX_FUZZ_SIZE);
		struct sockaddr_in addr_ipv4;

		offset = (size ? (rand() % size) : 0);
		length = (size ? (rand() % (size - offset)) : 0);
		mDNS::record_parse_a(buffer.get(), size, offset, length, addr_ipv4);
		struct sockaddr_in6 addr_ipv6;

		offset = (size ? (rand() % size) : 0);
		length = (size ? (rand() % (size - offset)) : 0);
		mDNS::record_parse_aaaa(buffer.get(), size, offset, length, addr_ipv6);
		offset = (size ? (rand() % size) : 0);
		length = (size ? (rand() % (size - offset)) : 0);
		mDNS::record_parse_txt(buffer.get(), size, offset, length, reintepret_cast<record_txt_t *>(strbuffer.get()), MAX_FUZZ_SIZE);
		if (ipass && (0 == (ipass % 10000)))
		{
			std::cout << "Completed fuzzing pass " << ipass << std::endl;
		}
	}
}
#endif /* defined(MDNS_FUZZING) */

static void
strip_domain
	(char *	inBuff)
{
	char *	dot_pos = strchr(inBuff, '.');

	if (nullptr != dot_pos)
	{
		*dot_pos = 0;
	}
}

int
main
	(const int            argc,
	 const char * const * argv)
{
	int          mode = 0;
	const char * service = "_test-mdns._tcp.local.";
	const char * hostname = "dummy-host";
	int          query_record = mDNS::kRecordTypePTR;
	int          service_port = 42424;
#if defined(_WIN32)
	WORD         versionWanted = MAKEWORD(1, 1);
	WSADATA      wsaData;

	if (WSAStartup(versionWanted, &wsaData))
	{
		std::cout << "Failed to initialize WinSock" << std::endl;
		return -1;

	}
	char  hostname_buffer[256];
	DWORD hostname_size = static_cast<DWORD>(sizeof(hostname_buffer));

	if (GetComputerNameA(hostname_buffer, &hostname_size))
	{
		strip_domain(hostname_buffer);
		hostname = hostname_buffer;
	}
#else /* not defined(_WIN32) */
	char   hostname_buffer[256];
	size_t hostname_size = sizeof(hostname_buffer);

	if (gethostname(hostname_buffer, hostname_size) == 0)
	{
		strip_domain(hostname_buffer);
		hostname = hostname_buffer;
	}
#endif /* not defined(_WIN32) */
	for (int iarg = 0; iarg < argc; ++iarg)
	{
		if (strcmp(argv[iarg], "--discovery") == 0)
		{
			mode = 0;
		}
		else if (strcmp(argv[iarg], "--query") == 0)
		{
			mode = 1;
			++iarg;
			if (iarg < argc)
			{
				service = argv[iarg++];
			}
			if (iarg < argc)
			{
				const char * record_name = argv[iarg++];
				
				if (strcmp(record_name, "PTR") == 0)
				{
					query_record = mDNS::kRecordTypePTR;
				}
				else if (strcmp(record_name, "SRV") == 0)
				{
					query_record = mDNS::kRecordTypeSRV;
				}
				else if (strcmp(record_name, "A") == 0)
				{
					query_record = mDNS::kRecordTypeA;
				}
				else if (strcmp(record_name, "AAAA") == 0)
				{
					query_record = mDNS::kRecordTypeAAAA;
				}
				else if (strcmp(record_name, "TXT") == 0)
				{
					query_record = mDNS::kRecordTypeTXT;
				}
			}
		}
		else if (strcmp(argv[iarg], "--service") == 0)
		{
			mode = 2;
			++iarg;
			if (iarg < argc)
			{
				service = argv[iarg];
			}
		}
		else if (strcmp(argv[iarg], "--hostname") == 0)
		{
			++iarg;
			if (iarg < argc)
			{
				hostname = argv[iarg];
			}
		}
		else if (strcmp(argv[iarg], "--port") == 0)
		{
			++iarg;
			if (iarg < argc)
			{
				service_port = atoi(argv[iarg]);
			}
		}
	}
#if defined(MDNS_FUZZING)
	fuzz_mdns();
#else /* not defined(MDNS_FUZZING) */
	int ret;

	if (mode == 0)
	{
		ret = send_dns_sd();
	}
	else if (mode == 1)
	{
		ret = send_mdns_query(service, query_record);
	}
	else if (mode == 2)
	{
		ret = service_mdns(hostname, service, service_port);
	}
#endif /* not defined(MDNS_FUZZING) */
#if defined(_WIN32)
	WSACleanup();
#endif /* defined(_WIN32) */
	return 0;
}
