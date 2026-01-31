#pragma once

#include <stdint.h>
#include <string>

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

namespace Crypt
{
	class Generic
	{
		public:

			Generic();
			Generic(const Generic &) = delete;
			virtual ~Generic() = 0;

			static constexpr uint8_t password_salt[4] = { 0x4a, 0xfb, 0xfc, 0x55 };
			static constexpr uint8_t init_vector[16] = { 0x5f, 0x8e, 0xee, 0x60, 0xf9, 0x56, 0x4d, 0xff, 0x82, 0xf1, 0x8a, 0xf5, 0x8d, 0x1c, 0x08, 0xe6 };

			static std::string password_to_aes256_key(std::string_view password);
			static std::string hash_to_text(std::string_view hash);

			static uint32_t		crc32(std::string_view in);
			static std::string	sha256(std::string_view input);
			static std::string	aes256(bool encrypt, std::string_view key, std::string_view input);

			virtual	void		init(bool encrypt = false, std::string_view key = "") = 0;
			virtual std::string	update(std::string_view data) = 0;
			virtual std::string	finish() = 0;

		protected:

			bool active;
	};

	class CRC32 : public Generic
	{
		public:

			CRC32();
			CRC32(const CRC32 &) = delete;
			virtual ~CRC32();

			static std::string uint32_to_string(uint32_t);
			static uint32_t string_to_uint32(std::string_view);

			void		init(bool encrypt = false, std::string_view key = "");
			std::string	update(std::string_view data);
			std::string	finish();

		private:

			static const uint32_t crc32_table[];
			uint32_t crc;
			unsigned int checksummed;
	};

	class SHA256 : public Generic
	{
		public:

			SHA256();
			SHA256(const CRC32 &) = delete;
			virtual ~SHA256();

			void		init(bool encrypt = false, std::string_view key = "");
			std::string	update(std::string_view input);
			std::string	finish();

		private:

			mbedtls_md_context_t ctx;
	};

	class AES256 : public Generic
	{
		public:

			AES256();
			AES256(const CRC32 &) = delete;
			virtual ~AES256();

			void		init(bool encrypt, std::string_view key);
			std::string update(std::string_view in);
			std::string	finish();

		private:

			mbedtls_cipher_context_t ctx;

	};

	std::string password_to_aes256_key(std::string_view password);
	std::string hash_to_text(std::string_view hash);
	uint32_t crc32(std::string_view in);
	std::string sha256(std::string_view in);
	std::string aes256(bool encrypt, std::string_view key, std::string_view in);
}
