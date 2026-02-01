#pragma once

#include <string>
#include <stdint.h>

class Packet final
{
	public:

		enum
		{
			packet_header_soh = 0x01,
			packet_header_version = 3,
			packet_header_id = 0x4afb,
		};

		Packet() = delete;
		Packet(const Packet &) = delete;

		static bool valid(std::string_view packet);
		static bool complete(std::string_view packet);
		static unsigned int length(std::string_view data);
		static std::string encapsulate(bool packetised, std::string_view data, std::string_view oob_data);
		static void decapsulate(bool packetised, std::string_view packet, std::string &data, std::string &oob_data);

	private:

		typedef struct __attribute__((packed))
		{
			uint8_t soh;
			uint8_t version;
			uint16_t id;
			uint16_t header_length;
			uint16_t payload_length;
			uint16_t oob_length;

			union
			{
				struct __attribute__((packed))
				{
					unsigned int spare_0:1;
					unsigned int spare_1:1;
					unsigned int spare_2:1;
					unsigned int spare_3:1;
					unsigned int spare_4:1;
					unsigned int spare_5:1;
					unsigned int spare_6:1;
					unsigned int spare_7:1;
					unsigned int spare_8:1;
					unsigned int spare_9:1;
					unsigned int spare_10:1;
					unsigned int spare_11:1;
					unsigned int spare_12:1;
					unsigned int spare_13:1;
					unsigned int spare_14:1;
					unsigned int spare_15:1;
				} flag;
				uint16_t flags;
			};
			uint16_t spare[2];
			uint32_t header_checksum;
			uint32_t packet_checksum;
			uint8_t data[];
		} packet_header_t;

	public:

		static unsigned int packet_header_size()
		{
			return(sizeof(packet_header_t));
		}
};
