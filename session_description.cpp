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

#include "session_description.hpp"

#include <regex>

#include <boost/log/trivial.hpp>


session_description::session_description(
    const boost::asio::ip::address& source_address,
    uint16_t message_id_hash,
    const std::string& payload
):
    m_source_address(source_address),
    m_message_id_hash(message_id_hash),
    m_protocol_version(0),
    m_origin_field(),
    m_session_name_field(),
    m_information_field(),
    m_uri_field(),
    m_connection_field(),
    m_bandwidth_fields(),
    m_time_fields()
{
    if (!payload.empty())
    {
        parse(payload);
    }
}

void session_description::parse(const std::string& payload)
{
    std::istringstream payload_stream(payload);
    std::optional<media_description> current_media_desc;

    for (std::string line; std::getline(payload_stream, line); /* NO OP */)
    {
        if (line.size() < 3)
            continue;
        if (line[1] != '=')
            continue;
        char line_type = line.front();
        std::string_view line_value(line);
        line_value.remove_prefix(2);
        if (line_value.back() == '\r')
            line_value.remove_suffix(1);

        switch (line_type)
        {
            case 'v': parse_proto_version(line_value); break;
            case 'o': parse_origin_field(line_value); break;
            case 's': m_session_name_field = line_value; break;
            case 'i': parse_information_field(line_value, current_media_desc); break;
            case 'u': m_uri_field = line_value; break;
            case 'c': parse_connection_field(line_value, current_media_desc); break;
            case 'b': parse_bandwidth_field(line_value, current_media_desc); break;
            case 't': parse_time_field(line_value); break;
            case 'a': parse_attribute_field(line_value, current_media_desc); break;
            case 'm':
            {
                if (current_media_desc.has_value())
                    m_media_descriptions.push_back(std::move(*current_media_desc));
                current_media_desc = media_description();
                parse_media_field(line_value, *current_media_desc);
            }
            break;
            default:
                BOOST_LOG_TRIVIAL(error) << "Warning: Unknown SDP line type: " << line_type;
                break;
        }
    }

    if (current_media_desc.has_value())
        m_media_descriptions.push_back(std::move(*current_media_desc));
    current_media_desc.reset();

#if 0
    BOOST_LOG_TRIVIAL(info) << "m_protocol_version=" << m_protocol_version;
    BOOST_LOG_TRIVIAL(info) << "m_origin_field.username=" << m_origin_field.username;
    BOOST_LOG_TRIVIAL(info) << "m_origin_field.session_id=" << m_origin_field.session_id;
    BOOST_LOG_TRIVIAL(info) << "m_origin_field.session_version=" << m_origin_field.session_version;
    BOOST_LOG_TRIVIAL(info) << "m_origin_field.addr_type=" << m_origin_field.addr_type;
    BOOST_LOG_TRIVIAL(info) << "m_origin_field.net_type=" << m_origin_field.net_type;
    BOOST_LOG_TRIVIAL(info) << "m_origin_field.addr=" << m_origin_field.addr;
    BOOST_LOG_TRIVIAL(info) << "m_session_name_field=" << m_session_name_field;
    BOOST_LOG_TRIVIAL(info) << "m_information_field=" << m_information_field;
    BOOST_LOG_TRIVIAL(info) << "m_uri_field=" << m_uri_field;
    BOOST_LOG_TRIVIAL(info) << "m_connection_field.net_type=" << m_connection_field.net_type;
    BOOST_LOG_TRIVIAL(info) << "m_connection_field.addr_type=" << m_connection_field.addr_type;
    BOOST_LOG_TRIVIAL(info) << "m_connection_field.addr=" << m_connection_field.addr;

    for (const auto& x : std::as_const(m_attribute_fields))
        BOOST_LOG_TRIVIAL(info) << "m_attribute_fields[]=" << x;

    for (const auto& x : std::as_const(m_media_descriptions))
    {
        BOOST_LOG_TRIVIAL(info) << "m_media_descriptions[].header.media=" << x.header.media;
        BOOST_LOG_TRIVIAL(info) << "m_media_descriptions[].header.port=" << x.header.port;
        BOOST_LOG_TRIVIAL(info) << "m_media_descriptions[].header.number_of_ports=" << x.header.number_of_ports.value_or(0);
        BOOST_LOG_TRIVIAL(info) << "m_media_descriptions[].header.proto=" << x.header.proto;
        for (const auto& f : x.header.formats)
            BOOST_LOG_TRIVIAL(info) << "m_media_descriptions[].header.formats[]=" << f;
        for (const auto& b : x.bandwidth_fields)
            BOOST_LOG_TRIVIAL(info) << "m_media_descriptions[].bandwidth_fields[]=" << b.bw_type << " : " << b.bandwidth;
    }
#endif
}

void session_description::parse_proto_version(const std::string_view& value)
{
    std::from_chars(value.begin(), value.end(), m_protocol_version);
    if (m_protocol_version != 0)
    {
        BOOST_LOG_TRIVIAL(error) << "Warning: Expected protocol version 0, found: " << m_protocol_version;
    }
}

void session_description::parse_origin_field(const std::string_view& value)
{
    std::istringstream value_stream{std::string(value)};
    value_stream >>
        m_origin_field.username >> std::ws >>
        m_origin_field.session_id >>
        m_origin_field.session_version >>
        m_origin_field.net_type >> std::ws >>
        m_origin_field.addr_type >> std::ws >>
        m_origin_field.addr;
}

void session_description::parse_information_field(
    const std::string_view& value,
    std::optional<media_description>& current_media_desc)
{
    if (current_media_desc.has_value())
    {
        current_media_desc->information_field = value;
    }
    else
    {
        m_information_field = value;
    }
}

void session_description::parse_connection_field(
    const std::string_view& value,
    std::optional<media_description>& current_media_desc)
{
    std::istringstream value_stream{std::string(value)};
    connection_field_t field;
    value_stream >>
        field.net_type >> std::ws >>
        field.addr_type >> std::ws >>
        field.addr;
    if (current_media_desc.has_value())
    {
        current_media_desc->connection_fields.push_back(std::move(field));
    }
    else
    {
        m_connection_field = std::move(field);
    }
}

void session_description::parse_bandwidth_field(
    const std::string_view& value,
    std::optional<media_description>& current_media_desc)
{
    std::regex bw_regex("([[:alnum:]]+):([[:digit:]]+)", std::regex::extended);
    std::cmatch results;
    if (std::regex_match(value.begin(), value.end(), results, bw_regex))
    {
        bandwidth_field_t field;
        field.bw_type = results[1].str();
        std::csub_match bw_submatch = results[2];
        std::from_chars(std::get<0>(bw_submatch), std::get<1>(bw_submatch), field.bandwidth);
        if (current_media_desc.has_value())
        {
            current_media_desc->bandwidth_fields.push_back(std::move(field));
        }
        else
        {
            m_bandwidth_fields.push_back(std::move(field));
        }
    }
    else
    {
        BOOST_LOG_TRIVIAL(error) << "Warning: Failed to parse bandwidth field value: " << value;
    }
}

void session_description::parse_time_field(const std::string_view& value)
{
    time_field_t field;
    std::istringstream value_stream{std::string(value)};
    value_stream >> field.start >> field.stop;
}

void session_description::parse_attribute_field(
    const std::string_view& value,
    std::optional<media_description>& current_media_desc)
{
    if (current_media_desc.has_value())
    {
        current_media_desc->attribute_fields.emplace_back(value);
    }
    else
    {
        m_attribute_fields.emplace_back(value);
    }
}

void session_description::parse_media_field(const std::string_view& value, media_description& current_media_desc)
{
    std::istringstream value_stream{std::string(value)};
    value_stream >>
        current_media_desc.header.media >>
        current_media_desc.header.port;
    char ch;
    value_stream.get(ch);
    if (ch == '/')
    {
        unsigned num_ports;
        value_stream >> num_ports;
        current_media_desc.header.number_of_ports = num_ports;
    }
    value_stream >> current_media_desc.header.proto;
    while (value_stream.good())
    {
        std::string fmt;
        value_stream >> std::ws >> fmt;
        current_media_desc.header.formats.push_back(std::move(fmt));
    }
}