#pragma once

#include <stdint.h>
#include <string>

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>

namespace Crypt
{
	class Generic
	{
		protected:

			bool active;

			Generic();
			Generic(const Generic &) = delete;
			virtual ~Generic() = 0;

			virtual	void		init(bool encrypt = false, std::string_view key = "") = 0;
			virtual std::string	update(std::string_view data) = 0;
			virtual std::string	finish() = 0;
	};

	class CRC32 final : private Generic
	{
		public:

			CRC32();
			CRC32(const CRC32 &) = delete;
			virtual ~CRC32();

			void		init(bool encrypt = false, std::string_view key = "") override;
			std::string	update(std::string_view data) override;
			std::string	finish() override;

		private:

			uint32_t crc;
			unsigned int checksummed;
	};

	class SHA256 final : private Generic
	{
		public:

			SHA256();
			SHA256(const CRC32 &) = delete;
			virtual ~SHA256();

			void		init(bool encrypt = false, std::string_view key = "") override;
			std::string	update(std::string_view input) override;
			std::string	finish() override;

		private:

			mbedtls_md_context_t ctx;
	};

	class AES256 final : private Generic
	{
		public:

			AES256();
			AES256(const CRC32 &) = delete;
			virtual ~AES256();

			void		init(bool encrypt, std::string_view key) override;
			std::string update(std::string_view in) override;
			std::string	finish() override;

		private:

			mbedtls_cipher_context_t ctx;

	};

	std::string password_to_aes256_key(std::string_view password);
	std::string hash_to_text(std::string_view hash);
	std::string uint32_to_string(uint32_t);
	uint32_t string_to_uint32(std::string_view);

	uint32_t crc32(std::string_view in);
	std::string sha256(std::string_view in);
	std::string aes256(bool encrypt, std::string_view key, std::string_view in);
}
