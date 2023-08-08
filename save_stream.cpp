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

#include "save_stream.hpp"

#include <cassert>
#include <regex>

#include <boost/log/trivial.hpp>

#include "session_description.hpp"

static std::string convert_addr(const std::string& addr)
{
    auto addr_slash = addr.find('/');
    if (addr_slash == std::string::npos)
        return addr;
    return addr.substr(0, addr_slash);
}

static std::array<uint8_t,2> uint16_le(uint16_t v)
{
    std::array<uint8_t,2> rval;
    rval[0] = (v & 0x00FF);
    rval[1] = ((v >> 8) & 0x00FF);
    return rval;
}

static std::array<uint8_t,4> uint32_le(uint32_t v)
{
    std::array<uint8_t,4> rval;
    rval[0] = (v & 0x000000FF);
    rval[1] = ((v >> 8) & 0x000000FF);
    rval[2] = ((v >> 16) & 0x000000FF);
    rval[3] = ((v >> 24) & 0x000000FF);
    return rval;
}

// template <typename CharT>
// void ostream_write_uint16_le(std::basic_ostream<CharT>& stream, uint16_t v)
// {
//     const auto data = uint16_le(v);
//     stream.write(reinterpret_cast<const CharT*>(data.data()), data.size());
// }

// template <typename CharT>
// void ostream_write_uint32_le(std::basic_ostream<CharT>& stream, uint32_t v)
// {
//     const auto data = uint32_le(v);
//     stream.write(reinterpret_cast<const CharT*>(data.data()), data.size());
// }


struct save_stream::save_stream_data
{
    asio::io_context& context;
    session_description session_desc;
    unsigned session_idx;
    asio::ip::udp::socket socket;
    asio::ip::udp::endpoint endpoint;
    std::array<uint8_t, 1500> recv_buffer;
    asio::ip::udp::endpoint remote_endpoint;
    //std::ofstream out_file;
    asio::random_access_file out_file;
    size_t out_file_size;
    std::vector<std::vector<uint8_t>> current_write_data;
    std::vector<std::vector<uint8_t>> pending_write_data;

    save_stream_data(
        asio::io_context& context_,
        const session_description& session_desc_,
        unsigned session_idx_
    ):
        context(context_),
        session_desc(session_desc_),
        session_idx(session_idx_),
        socket(context),
        endpoint(),
        recv_buffer(),
        remote_endpoint(),
        out_file(context_),
        out_file_size(0),
        current_write_data(),
        pending_write_data()
    {
        init_endpoint();
        init_socket();
        init_out_file();
        add_wav_header();
        start_receive();
    }

    ~save_stream_data()
    {
        close(std::function<void()>());
    }

    void close(std::function<void()> callback)
    {
        if (socket.is_open())
        {
            socket.cancel();
            socket.set_option(asio::ip::multicast::leave_group(endpoint.address()));
            socket.close();
        }
        if (out_file.is_open())
        {
            finalise_wav_header(callback);
        }
    }

    void init_endpoint()
    {
        assert(session_idx < session_desc.media_descriptions().size());
        const auto& media_desc = session_desc.media_descriptions()[session_idx];

        boost::asio::ip::address stream_addr = boost::asio::ip::address::from_string(convert_addr(session_desc.connection_field().addr));
        if (!media_desc.connection_fields.empty())
        {
            stream_addr = boost::asio::ip::address::from_string(media_desc.connection_fields[0].addr);
        }

        endpoint = asio::ip::udp::endpoint(stream_addr, (asio::ip::port_type)media_desc.header.port);
    }

    void init_socket()
    {
        asio::ip::udp::endpoint any_endpoint(
            (endpoint.address().is_v6() ? asio::ip::address(asio::ip::address_v6::any()) : asio::ip::address(asio::ip::address_v4::any())),
            endpoint.port());

        socket.open(endpoint.protocol());
        socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));
        socket.bind(any_endpoint);
        socket.set_option(asio::ip::multicast::join_group(endpoint.address()));
    }

    void init_out_file()
    {
        std::string addr_str(endpoint.address().to_string());
        std::regex addr_sanitise("[:.]", std::regex::basic);

        std::stringstream file_name;
        file_name << "stream-";
        std::regex_replace(std::ostreambuf_iterator<char>(file_name), addr_str.begin(), addr_str.end(), addr_sanitise, "-");
        file_name << "-" << endpoint.port() << ".wav";

        const std::string file_name_str(file_name.str());
        BOOST_LOG_TRIVIAL(info) << "Saving stream to: " << file_name_str;
        out_file.open(file_name_str.c_str(), asio::file_base::read_write | asio::file_base::create | asio::file_base::truncate);
        out_file_size = 0;
    }

    void add_wav_header()
    {
        uint16_t channels = 1;
        uint16_t bits_per_sample = 16;
        uint32_t sample_rate = 8000;
        uint32_t bytes_per_second = (sample_rate * bits_per_sample * channels) / 8;
        uint16_t block_size_bytes = (bits_per_sample * channels) / 8;

        const char wav_hdr[] =
            "RIFF"  // File type tag
            "\0\0\0\0" // File length - to be filled in at the end
            "WAVE"  // File type header
            "fmt " // Format block header
            "\x10\0\0\0" // Format block length = 16 uint32 LE
            "\x01\0"; // Type of format = PCM = 1 uint16 LE
        add_write_data((const uint8_t*)wav_hdr, sizeof(wav_hdr) - 1); // -1 to ignore c-string nul terminator

        add_write_data(uint16_le(channels));
        add_write_data(uint32_le(sample_rate));
        add_write_data(uint32_le(bytes_per_second));
        add_write_data(uint16_le(block_size_bytes));
        add_write_data(uint16_le(bits_per_sample));

        // out_file.write("data\0\0\0\0", 8);
        // assert(out_file.tellp() == 44);

        add_write_data((const uint8_t*)"data\0\0\0\0", 8);

#ifndef NDEBUG
        wait_for_write_finished();
        assert(out_file_size == 44);
#endif
    }

    void finalise_wav_header(std::function<void()> callback)
    {
        // out_file.flush();
        // size_t file_size = out_file.tellp();
        // out_file.seekp(4);
        // ostream_write_uint32_le(out_file, file_size - 8);
        // out_file.seekp(40);
        // size_t samples = (file_size - 44) / 2;
        // ostream_write_uint32_le(out_file, samples);

        // size_t file_size = out_file_size;
        // size_t samples = (file_size - 44) / 2;
        // wait_for_write_finished();

        // out_file_size = 4;
        // add_write_data(uint32_le(file_size - 8));
        // wait_for_write_finished();

        // out_file_size = 40;
        // add_write_data(uint32_le(samples));
        // wait_for_write_finished();

        BOOST_LOG_TRIVIAL(info) << "Starting write of wav file header size";
        auto data = std::make_shared<std::array<uint8_t,4>>(uint32_le(out_file_size - 8));
        asio::async_write_at(
            out_file,
            4,
            asio::const_buffer(data->data(), data->size()),
            [this, data, callback](const boost::system::error_code& error, std::size_t size) mutable
            {
                (void)size;
                if (error)
                    BOOST_LOG_TRIVIAL(error) << "Write of wav file header size failed: " << error.what();
                data.reset();
                finalise_data_header(callback);
            }
        );
    }

    void finalise_data_header(std::function<void()> callback)
    {
        BOOST_LOG_TRIVIAL(info) << "Starting write of wav data header size";
        auto data = std::make_shared<std::array<uint8_t,4>>(uint32_le(out_file_size - 44));
        asio::async_write_at(
            out_file,
            40,
            asio::const_buffer(data->data(), data->size()),
            [this, data, callback](const boost::system::error_code& error, std::size_t size) mutable
            {
                (void)error;
                (void)size;
                if (error)
                    BOOST_LOG_TRIVIAL(error) << "Write of wav data header size failed: " << error;
                data.reset();
                BOOST_LOG_TRIVIAL(info) << "Wav header finalised";
                out_file.sync_all();
                out_file.close();
                if (callback)
                    callback();
            }
        );
    }

    void start_receive()
    {
        if (!socket.is_open())
            return;
        socket.async_receive_from(
            asio::buffer(recv_buffer),
            remote_endpoint,
            [this](const boost::system::error_code& err, std::size_t size){handle(err, size);}
        );
    }

    void handle(const boost::system::error_code& error, std::size_t size)
    {
        if (error)
        {
            BOOST_LOG_TRIVIAL(error) << "Failed to receive packet: " << error.what();
        }
        else
        {
            // BOOST_LOG_TRIVIAL(info) << "RECV " << size << " from " << remote_endpoint;
            // out_file.write(reinterpret_cast<char*>(recv_buffer.data()), size);

            handle_packet(size);
        }
        start_receive();
    }

    void handle_packet(std::size_t size)
    {
        if (size < 12)
        {
            BOOST_LOG_TRIVIAL(error) << "RTP packet too small";
            return;
        }

        uint8_t ver_flags_cc = recv_buffer[0];
        uint8_t ver = (ver_flags_cc >> 6) & 0x03;
        bool padding = ver_flags_cc & 0x20;
        bool extension = ver_flags_cc & 0x10;
        uint8_t csrc_count = ver_flags_cc & 0x0f;

        uint8_t marker_payload_type = recv_buffer[1];
        bool marker = marker_payload_type & 0x80;
        uint8_t payload_type = marker_payload_type & 0x7f;

        uint16_t sequence_number = (recv_buffer[2] << 8) & recv_buffer[3];
        uint32_t timestamp = (recv_buffer[4] << 24) & (recv_buffer[5] << 16) & (recv_buffer[6] << 24) & recv_buffer[7];
        uint32_t ssrc = (recv_buffer[8] << 24) & (recv_buffer[9] << 16) & (recv_buffer[10] << 24) & recv_buffer[11];

        if (ver != 2)
        {
            BOOST_LOG_TRIVIAL(error) << "RTP packet wrong version, expected 2, got: " << ver;
            return;
        }

        BOOST_LOG_TRIVIAL(debug) <<
            "RTP, V:" << unsigned(ver) <<
            " P:" << padding <<
            " X:" << extension <<
            " CC:" << unsigned(csrc_count) <<
            " M:" << marker <<
            " PT:" << unsigned(payload_type) <<
            " SEQ:" << sequence_number <<
            " TS:" << timestamp <<
            " SSRC:" << ssrc;

        unsigned start_offset = 12 + (4 * csrc_count);
        if (start_offset >= size)
        {
            BOOST_LOG_TRIVIAL(error) << "RTP packet malformed, start calculated as: " << start_offset << ", packet length: " << size;
            return;
        }
        unsigned end_offset = size - (padding ? recv_buffer[size-1] : 0);
        // unsigned data_len = end_offset - start_offset;

        //out_file.write(reinterpret_cast<char*>(recv_buffer.data() + start_offset), data_len);

        add_write_data(std::vector<uint8_t>(recv_buffer.data() + start_offset, recv_buffer.data() + end_offset));
    }

    void add_write_data(std::vector<uint8_t>&& data)
    {
        pending_write_data.push_back(data);
        if (current_write_data.empty())
        {
            start_writing();
        }
    }

    template <size_t N>
    void add_write_data(const std::array<uint8_t,N>& data)
    {
        add_write_data(std::vector<uint8_t>(data.data(), data.data() + data.size()));
    }

    void add_write_data(const uint8_t* data, size_t length)
    {
        add_write_data(std::vector<uint8_t>(data, data + length));
    }

    void start_writing()
    {
        current_write_data = std::move(pending_write_data);
        pending_write_data.clear();

        std::vector<asio::const_buffer> buffers;
        size_t buffers_size = 0;
        for (const auto& buf : current_write_data)
        {
            buffers.emplace_back(buf.data(), buf.size());
            buffers_size += buf.size();
        }

        asio::async_write_at(
            out_file,
            out_file_size,
            buffers,
            [this](const boost::system::error_code& error, std::size_t size){write_finished(error, size);}
        );
        out_file_size += buffers_size;
    }

    void write_finished(const boost::system::error_code& error, std::size_t size)
    {
        if (error)
        {
            BOOST_LOG_TRIVIAL(error) << "Write file error: " << error.what();
        }
        else
        {
            BOOST_LOG_TRIVIAL(debug) << "Wrote " << size << " B";
        }
        current_write_data.clear();

        if (!pending_write_data.empty())
        {
            start_writing();
        }
    }

    void wait_for_write_finished()
    {
        while (!pending_write_data.empty() && !current_write_data.empty())
        {
            context.run_one();
        }
    }

};


save_stream::save_stream(
    asio::io_context& context,
    const session_description& session_desc,
    unsigned session_idx
):
    m_data(std::make_unique<save_stream_data>(context, session_desc, session_idx))
{}

save_stream::save_stream(save_stream&& other):
    m_data(std::move(other.m_data))
{}

save_stream::~save_stream()
{}

void save_stream::close(std::function<void()> callback)
{
    m_data->close(callback);
}