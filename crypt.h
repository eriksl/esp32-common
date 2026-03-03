#pragma once

#include <cstdint>
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
			Generic(const Generic &&) = delete;
			Generic& operator =(const Generic &) = delete;
			virtual ~Generic() = 0;

			virtual	void		init(bool encrypt = false, std::string_view key = "") = 0;
			virtual std::string	update(std::string_view data) = 0;
			virtual std::string	finish() = 0;
	};

	class CRC8_31 final : private Generic
	{
		public:

			CRC8_31();
			CRC8_31(const CRC8_31 &) = delete;
			CRC8_31(const CRC8_31 &&) = delete;
			CRC8_31& operator =(const CRC8_31 &) = delete;
			virtual ~CRC8_31();

			void		init(bool encrypt = false, std::string_view key = "") override;
			std::string	update(std::string_view data) override;
			std::string	finish() override;

		private:

			static const std::array<std::uint8_t, 256> crc8_31_table;
			std::uint8_t crc;
			unsigned int checksummed;
	};

	class CRC32 final : private Generic
	{
		public:

			CRC32();
			CRC32(const CRC32 &) = delete;
			CRC32(const CRC32 &&) = delete;
			CRC32& operator =(const CRC32 &) = delete;
			virtual ~CRC32();

			void		init(bool encrypt = false, std::string_view key = "") override;
			std::string	update(std::string_view data) override;
			std::string	finish() override;

		private:

			static const std::array<std::uint32_t, 256> crc32_table;
			std::uint32_t crc;
			unsigned int checksummed;
	};

	class SHA256 final : private Generic
	{
		public:

			SHA256();
			SHA256(const CRC32 &) = delete;
			SHA256(const CRC32 &&) = delete;
			SHA256& operator =(const SHA256 &) = delete;
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
			AES256(const CRC32 &&) = delete;
			AES256& operator =(const AES256 &) = delete;
			virtual ~AES256();

			static const std::array<std::uint8_t, 4> password_salt;

			void		init(bool encrypt, std::string_view key) override;
			std::string update(std::string_view in) override;
			std::string	finish() override;

		private:

			static const std::array<std::uint8_t, 16> init_vector;
			mbedtls_cipher_context_t ctx;

	};

	std::string password_to_aes256_key(std::string_view password);
	std::string hash_to_text(std::string_view hash);
	std::string uint8_to_string(std::uint8_t);
	std::string uint32_to_string(std::uint32_t);
	std::uint8_t string_to_uint8(std::string_view in);
	std::uint32_t string_to_uint32(std::string_view);

	std::uint8_t crc8_31(std::string_view in, std::uint8_t initial = 0xff);
	std::uint32_t crc32(std::string_view in);
	std::string sha256(std::string_view in);
	std::string aes256(bool encrypt, std::string_view key, std::string_view in);
}
