/*
 Copyright (c) 2023 Silas Parker

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef SESSION_DESCRIPTION_HPP
#define SESSION_DESCRIPTION_HPP

#include <string>
#include <vector>
#include <optional>

#include <boost/asio.hpp>

class session_description
{
    public:
        struct origin_field_t
        {
            std::string username;
            unsigned session_id;
            unsigned session_version;
            std::string net_type;
            std::string addr_type;
            std::string addr;
        };

        struct connection_field_t
        {
            std::string net_type;
            std::string addr_type;
            std::string addr;
        };

        struct bandwidth_field_t
        {
            std::string bw_type;
            unsigned bandwidth;
        };

        struct time_field_t
        {
            unsigned start;
            unsigned stop;
        };

        struct media_description_line
        {
            std::string media;
            unsigned port;
            std::optional<unsigned> number_of_ports;
            std::string proto;
            std::vector<std::string> formats;
        };

        struct media_description
        {
            media_description_line header;
            std::string information_field;
            std::vector<connection_field_t> connection_fields;
            std::vector<bandwidth_field_t> bandwidth_fields;
            std::vector<std::string> attribute_fields;
        };

        session_description(
            const boost::asio::ip::address& source_address = boost::asio::ip::address(),
            uint16_t message_id_hash = 0,
            const std::string& payload = std::string()
        );

        unsigned protocol_version() const noexcept {return m_protocol_version;}
        const origin_field_t& origin_field() const noexcept {return m_origin_field;}
        const std::string& session_name_field() const noexcept {return m_session_name_field;}
        const std::string& information_field() const noexcept {return m_information_field;}
        const std::string& uri_field() const noexcept {return m_uri_field;}
        const connection_field_t& connection_field() const noexcept {return m_connection_field;}
        const std::vector<bandwidth_field_t>& bandwidth_fields() const noexcept {return m_bandwidth_fields;}
        const std::vector<time_field_t>& time_fields() const noexcept {return m_time_fields;}
        const std::vector<std::string>& attribute_fields() const noexcept {return m_attribute_fields;}
        const std::vector<media_description>& media_descriptions() const noexcept {return m_media_descriptions;}

    private:
        boost::asio::ip::address m_source_address;
        uint16_t m_message_id_hash;

        unsigned m_protocol_version;
        origin_field_t m_origin_field;
        std::string m_session_name_field;
        std::string m_information_field;
        std::string m_uri_field;
        connection_field_t m_connection_field;
        std::vector<bandwidth_field_t> m_bandwidth_fields;
        std::vector<time_field_t> m_time_fields;
        std::vector<std::string> m_attribute_fields;
        std::vector<media_description> m_media_descriptions;


        void parse(const std::string& payload);
        void parse_proto_version(const std::string_view& value);
        void parse_origin_field(const std::string_view& value);
        void parse_information_field(const std::string_view& value, std::optional<media_description>& current_media_desc);
        void parse_connection_field(const std::string_view& value, std::optional<media_description>& current_media_desc);
        void parse_bandwidth_field(const std::string_view& value, std::optional<media_description>& current_media_desc);
        void parse_time_field(const std::string_view& value);
        void parse_attribute_field(const std::string_view& value, std::optional<media_description>& current_media_desc);
        void parse_media_field(const std::string_view& value, media_description& current_media_desc);
};




#endif /* SESSION_DESCRIPTION_HPP */
