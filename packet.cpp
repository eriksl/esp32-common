#include <stdint.h>
#include <string.h>

#include "crypt.h"
#include "exception.h"

#include "packet.h"

#include <string>
#include <iostream>
#include <boost/format.hpp>

bool Packet::valid(std::string_view packet)
{
	const packet_header_t *packet_header = reinterpret_cast<const packet_header_t *>(packet.data());

	return((packet.length() >= sizeof(*packet_header)) &&
			(packet_header->soh == packet_header_soh) &&
			(packet_header->version == packet_header_version) &&
			(packet_header->id == packet_header_id));
}

unsigned int Packet::length(std::string_view data)
{
	const packet_header_t *packet_header = reinterpret_cast<const packet_header_t *>(data.data());

    return(packet_header->header_length + packet_header->payload_length + packet_header->oob_length);
}

bool Packet::complete(std::string_view packet)
{
	const packet_header_t *packet_header = (const packet_header_t *)packet.data();
	unsigned int packet_length = packet.length();
	unsigned int expected_length = packet_header->header_length + packet_header->payload_length + packet_header->oob_length;

	if(packet_length < expected_length)
		return(false);

	return(true);
}

std::string Packet::encapsulate(bool packetised, std::string_view data, std::string_view oob_data)
{
	packet_header_t packet_header;
	std::string packet;
	Crypt::CRC32 crc;

	if(packetised)
	{
		memset(&packet_header, 0, sizeof(packet_header));
		packet_header.soh = packet_header_soh;
		packet_header.version = packet_header_version;
		packet_header.id = packet_header_id;
		packet_header.header_length = sizeof(packet_header);
		packet_header.payload_length = data.length();
		packet_header.oob_length = oob_data.length();
		packet_header.header_checksum = Crypt::crc32(std::string_view(reinterpret_cast<const char *>(&packet_header), offsetof(packet_header_t, header_checksum)));

		crc.init();
		crc.update(std::string_view(reinterpret_cast<const char *>(&packet_header), offsetof(packet_header_t, packet_checksum)));
		crc.update(data);
		crc.update(oob_data);
		packet_header.packet_checksum = Crypt::string_to_uint32(crc.finish());

		packet.assign(reinterpret_cast<const char *>(&packet_header), sizeof(packet_header));
		packet.append(data);
		packet.append(oob_data);
	}
	else
	{
		packet = data;

		if(!packet.empty() && (packet.back() != '\n'))
			packet.append("\n");

		if(oob_data.length() > 0)
		{
			packet.append(1, '\0');
			packet.append(oob_data);
		}
	}

	return(packet);
}

void Packet::decapsulate(bool packetised, std::string_view packet, std::string &data, std::string &oob_data)
{
	uint32_t our_checksum;
	Crypt::CRC32 crc;

#define assert_field(name, field, offset) static_assert(offsetof(name, field) == offset)

assert_field(Packet::packet_header_t, soh, 0);
assert_field(Packet::packet_header_t, version, 1);
assert_field(Packet::packet_header_t, id, 2);
assert_field(Packet::packet_header_t, header_length, 4);
assert_field(Packet::packet_header_t, payload_length, 6);
assert_field(Packet::packet_header_t, oob_length, 8);
assert_field(Packet::packet_header_t, flag, 10);
assert_field(Packet::packet_header_t, flags, 10);
assert_field(Packet::packet_header_t, spare[0], 12);
assert_field(Packet::packet_header_t, spare[1], 14);
assert_field(Packet::packet_header_t, header_checksum, 16);
assert_field(Packet::packet_header_t, packet_checksum, 20);
assert_field(Packet::packet_header_t, data, 24);
static_assert(sizeof(Packet::packet_header_t) == 24);
static_assert((sizeof(Packet::packet_header_t) % 4) == 0);

	try
	{
		if(packetised)
		{
			const packet_header_t *packet_header = reinterpret_cast<const packet_header_t *>(packet.data());

			if(packet_header->header_length != sizeof(*packet_header))
				throw(hard_exception(boost::format("invalid packet header length, expected: %u, received: %u") % sizeof(*packet_header) % packet_header->header_length));

			if(static_cast<unsigned int>(packet_header->header_length + packet_header->payload_length + packet_header->oob_length) != packet.length())
				throw(hard_exception(boost::format("invalid packet length, expected: %u, received: %u") %
						(packet_header->header_length + packet_header->payload_length + packet_header->oob_length) %
						packet.length()));

			our_checksum = Crypt::crc32(std::string_view(reinterpret_cast<const char *>(packet_header), offsetof(packet_header_t, header_checksum)));

			if(our_checksum != packet_header->header_checksum)
				throw(hard_exception(boost::format("invalid header checksum, ours: 0x%x, theirs: 0x%x") % our_checksum % packet_header->header_checksum));

			data = packet.substr(packet_header->header_length, packet_header->payload_length);
			oob_data = packet.substr(packet_header->header_length + packet_header->payload_length);

			crc.init();
			crc.update(std::string_view(reinterpret_cast<const char *>(packet_header), offsetof(packet_header_t, packet_checksum)));
			crc.update(data);
			crc.update(oob_data);
			our_checksum = Crypt::string_to_uint32(crc.finish());

			if(our_checksum != packet_header->packet_checksum)
				throw(hard_exception(boost::format("invalid packet checksum, ours: 0x%x, theirs: 0x%x") % our_checksum % packet_header->packet_checksum));
		}
		else
		{
			size_t oob_offset;

			oob_offset = packet.find('\0', 0);

			if(oob_offset == std::string::npos)
			{
				data = packet;
				oob_data.clear();
			}
			else
			{
				if((oob_offset + 1) > packet.length())
					throw(hard_exception(boost::format("invalid unpacketised oob data, data length: %u, oob_offset: %u") % data.length() % oob_offset));

				data = packet.substr(0, oob_offset);
				oob_data = packet.substr(oob_offset + 1);
			}
		}

		if((data.back() == '\n') || (data.back() == '\r'))
			data.pop_back();

		if((data.back() == '\n') || (data.back() == '\r'))
			data.pop_back();
	}
	catch(hard_exception &e)
	{
		throw(hard_exception(std::string("Packet::decapsulate: ") + e.what()));
	}
	catch(std::exception &e)
	{
		throw(hard_exception(std::string("Packet::decapsulate: ") + e.what()));
	}
}
