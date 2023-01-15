/*

Copyright (c) 2007-2022, Arvid Norberg
Copyright (c) 2015, Mikhail Titov
Copyright (c) 2016-2018, 2020, Alden Torres
Copyright (c) 2016, Andrei Kurushin
Copyright (c) 2017, Jan Berkel
Copyright (c) 2017, Steven Siloti
Copyright (c) 2019, patch3proxyheaders915360
Copyright (c) 2020, Paul-Louis Ageneau
Copyright (c) 2022, AlexeyKhrolenko
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in
the documentation and/or other materials provided with the distribution.
* Neither the name of the author nor the names of its
contributors may be used to endorse or promote products derived
from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#include "libtorrent/http_connection.hpp"
#include "libtorrent/aux_/escape_string.hpp"
#include "libtorrent/aux_/instantiate_connection.hpp"
#include "libtorrent/gzip.hpp"
#include "libtorrent/parse_url.hpp"
#include "libtorrent/socket.hpp"
#include "libtorrent/aux_/socket_type.hpp" // for async_shutdown
#include "libtorrent/aux_/resolver_interface.hpp"
#include "libtorrent/aux_/bind_to_device.hpp"
#include "libtorrent/settings_pack.hpp"
#include "libtorrent/aux_/time.hpp"
#include "libtorrent/random.hpp"
#include "libtorrent/debug.hpp"
#include "libtorrent/time.hpp"
#include "libtorrent/io_context.hpp"
#include "libtorrent/i2p_stream.hpp"
#include "libtorrent/aux_/ip_helpers.hpp"
#include "libtorrent/ssl.hpp"

#include <functional>
#include <string>
#include <algorithm>
#include <sstream>

using namespace std::placeholders;

namespace libtorrent {

	void http_connection::close(bool force)
	{
		if (m_abort) return;

		if (m_sock)
		{
			error_code ec;
			if (force)
			{
				m_sock->close(ec);
				m_timer.cancel();
			}
			else
			{
				async_shutdown(*m_sock, shared_from_this());
			}
		}
		else
			m_timer.cancel();

		m_limiter_timer.cancel();

		m_hostname.clear();
		m_port = 0;
		m_handler = nullptr;
		m_abort = true;
	}

#if TORRENT_USE_I2P
	void http_connection::connect_i2p_tracker(char const* destination)
	{
		TORRENT_ASSERT(boost::get<i2p_stream>(m_sock.get_ptr()));
#if TORRENT_USE_SSL
		TORRENT_ASSERT(m_ssl == false);
#endif
		boost::get<i2p_stream>(*m_sock).set_destination(destination);
		boost::get<i2p_stream>(*m_sock).set_command(i2p_stream::cmd_connect);
		boost::get<i2p_stream>(*m_sock).set_session_id(m_i2p_conn->session_id());
		ADD_OUTSTANDING_ASYNC("http_connection::on_connect");
		TORRENT_ASSERT(!m_connecting);
		m_connecting = true;
		m_sock->async_connect(tcp::endpoint(), std::bind(&http_connection::on_connect
			, shared_from_this(), _1));
	}

	void http_connection::on_i2p_resolve(error_code const& e, char const* destination)
	{
		COMPLETE_ASYNC("http_connection::on_i2p_resolve");
		if (e)
		{
			callback(e);
			return;
		}
		connect_i2p_tracker(destination);
	}
#endif

	void http_connection::on_resolve(error_code const& e
		, std::vector<address> const& addresses)
	{
		COMPLETE_ASYNC("http_connection::on_resolve");
		m_resolving_host = false;
		if (e)
		{
			callback(e);
			return;
		}

		if (m_abort) return;

		TORRENT_ASSERT(!addresses.empty());

		// reset timeout
		m_start_time = clock_type::now();

		for (auto const& addr : addresses)
			m_endpoints.emplace_back(addr, m_port);

		if (m_filter_handler) m_filter_handler(*this, m_endpoints);
		if (m_endpoints.empty())
		{
			close();
			return;
		}

		aux::random_shuffle(m_endpoints);

		// if we have been told to bind to a particular address
		// only connect to addresses of the same family
		if (m_bind_addr)
		{
			auto const new_end = std::remove_if(m_endpoints.begin(), m_endpoints.end()
				, [&](tcp::endpoint const& ep) { return aux::is_v4(ep) != m_bind_addr->ip.is_v4(); });

			m_endpoints.erase(new_end, m_endpoints.end());
			if (m_endpoints.empty())
			{
				callback(error_code(boost::system::errc::address_family_not_supported, generic_category()));
				close();
				return;
			}
		}

		connect();
	}

	void http_connection::connect()
	{
		TORRENT_ASSERT(m_next_ep < int(m_endpoints.size()));

		std::shared_ptr<http_connection> me(shared_from_this());

		if (m_proxy.proxy_hostnames
			&& (m_proxy.type == settings_pack::socks5
				|| m_proxy.type == settings_pack::socks5_pw))
		{
			// test to see if m_hostname really just is an IP (and not a hostname). If it
			// is, ec will be represent "success". If so, don't set it as the socks5
			// hostname, just connect to the IP
			error_code ec;
			address adr = make_address(m_hostname, ec);

			if (ec)
			{
				// we're using a socks proxy and we're resolving
				// hostnames through it
#if TORRENT_USE_SSL
				if (m_ssl)
				{
					TORRENT_ASSERT(boost::get<ssl_stream<socks5_stream>>(m_sock.get_ptr()));
					boost::get<ssl_stream<socks5_stream>>(*m_sock).next_layer().set_dst_name(m_hostname);
				}
				else
#endif
				{
					TORRENT_ASSERT(boost::get<socks5_stream>(m_sock.get_ptr()));
					boost::get<socks5_stream>(*m_sock).set_dst_name(m_hostname);
				}
			}
			else
			{
				m_endpoints[0].address(adr);
			}
		}

		TORRENT_ASSERT(m_next_ep < int(m_endpoints.size()));
		if (m_next_ep >= int(m_endpoints.size())) return;

		tcp::endpoint target_address = m_endpoints[m_next_ep];
		++m_next_ep;

		ADD_OUTSTANDING_ASYNC("http_connection::on_connect");
		TORRENT_ASSERT(!m_connecting);
		m_connecting = true;
		m_sock->async_connect(target_address, std::bind(&http_connection::on_connect
			, me, _1));
	}

	void http_connection::on_connect(error_code const& e)
	{
		COMPLETE_ASYNC("http_connection::on_connect");
		TORRENT_ASSERT(m_connecting);
		m_connecting = false;

		m_last_receive = clock_type::now();
		m_start_time = m_last_receive;
		if (!e)
		{
			if (m_connect_handler) m_connect_handler(*this);
			ADD_OUTSTANDING_ASYNC("http_connection::on_write");
			async_write(*m_sock, boost::asio::buffer(m_sendbuffer)
				, std::bind(&http_connection::on_write, shared_from_this(), _1));
		}
		else if (m_next_ep < int(m_endpoints.size()) && !m_abort)
		{
			// The connection failed. Try the next endpoint in the list.
			error_code ec;
			m_sock->close(ec);
			connect();
		}
		else
		{
			error_code ec;
			m_sock->close(ec);
			callback(e);
		}
	}

	void http_connection::callback(error_code e, span<char> data)
	{
		if (m_bottled && m_called) return;

		std::vector<char> buf;
		if (!data.empty() && m_bottled && m_parser.header_finished())
		{
			data = m_parser.collapse_chunk_headers(data);

			std::string const& encoding = m_parser.header("content-encoding");
			if (encoding == "gzip" || encoding == "x-gzip")
			{
				error_code ec;
				inflate_gzip(data, buf, m_max_bottled_buffer_size, ec);

				if (ec)
				{
					if (m_handler) m_handler(ec, m_parser, data, *this);
					return;
				}
				data = buf;
			}

			// if we completed the whole response, no need
			// to tell the user that the connection was closed by
			// the server or by us. Just clear any error
			if (m_parser.finished()) e.clear();
		}
		m_called = true;
		m_timer.cancel();
		if (m_handler) m_handler(e, m_parser, data, *this);
	}

	void http_connection::on_write(error_code const& e)
	{
		COMPLETE_ASYNC("http_connection::on_write");

		if (e == boost::asio::error::operation_aborted) return;

		if (e)
		{
			callback(e);
			return;
		}

		if (m_abort) return;

		std::string().swap(m_sendbuffer);
		m_recvbuffer.resize(4096);

		int amount_to_read = int(m_recvbuffer.size()) - m_read_pos;
		if (m_rate_limit > 0 && amount_to_read > m_download_quota)
		{
			amount_to_read = m_download_quota;
			if (m_download_quota == 0)
			{
				if (!m_limiter_timer_active)
				{
					ADD_OUTSTANDING_ASYNC("http_connection::on_assign_bandwidth");
					on_assign_bandwidth(error_code());
				}
				return;
			}
		}
		ADD_OUTSTANDING_ASYNC("http_connection::on_read");
		m_sock->async_read_some(boost::asio::buffer(m_recvbuffer.data() + m_read_pos
			, std::size_t(amount_to_read))
			, std::bind(&http_connection::on_read
				, shared_from_this(), _1, _2));
	}

	void http_connection::on_read(error_code const& e
		, std::size_t bytes_transferred)
	{
		COMPLETE_ASYNC("http_connection::on_read");

		if (m_rate_limit)
		{
			m_download_quota -= int(bytes_transferred);
			TORRENT_ASSERT(m_download_quota >= 0);
		}

		if (e == boost::asio::error::operation_aborted) return;

		if (m_abort) return;

		// keep ourselves alive even if the callback function
		// deletes this object
		std::shared_ptr<http_connection> me(shared_from_this());

		// when using the asio SSL wrapper, it seems like
		// we get the shut_down error instead of EOF
		if (e == boost::asio::error::eof || e == boost::asio::error::shut_down)
		{
			error_code ec = boost::asio::error::eof;
			TORRENT_ASSERT(bytes_transferred == 0);
			span<char> body;
			if (m_bottled && m_parser.header_finished())
			{
				body = span<char>(m_recvbuffer.data() + m_parser.body_start()
					, m_parser.get_body().size());
			}
			callback(ec, body);
			return;
		}

		if (e)
		{
			TORRENT_ASSERT(bytes_transferred == 0);
			callback(e);
			return;
		}

		m_read_pos += int(bytes_transferred);
		TORRENT_ASSERT(m_read_pos <= int(m_recvbuffer.size()));

		if (m_bottled || !m_parser.header_finished())
		{
			span<char const> rcv_buf(m_recvbuffer);
			bool error = false;
			m_parser.incoming(rcv_buf.first(m_read_pos), error);
			if (error)
			{
				// HTTP parse error
				error_code ec = errors::http_parse_error;
				callback(ec);
				return;
			}

			// having a nonempty path means we should handle redirects
			if (m_redirects && m_parser.header_finished())
			{
				int code = m_parser.status_code();

				if (is_redirect(code))
				{
					// attempt a redirect
					std::string const& location = m_parser.header("location");
					if (location.empty())
					{
						// missing location header
						callback(error_code(errors::http_missing_location));
						return;
					}

					error_code ec;
					// it would be nice to gracefully shut down SSL here
					// but then we'd have to do all the reconnect logic
					// in its handler. For now, just kill the connection.
					//				async_shutdown(m_sock, me);
					m_sock->close(ec);

					std::string url = resolve_redirect_location(m_url, location);
					get(url, m_completion_timeout, &m_proxy, m_redirects - 1
						, m_user_agent, m_bind_addr, m_resolve_flags, m_auth
#if TORRENT_USE_I2P
						, m_i2p_conn
#endif
					);
					return;
				}

				m_redirects = 0;
			}

			if (!m_bottled && m_parser.header_finished())
			{
				if (m_read_pos > m_parser.body_start())
				{
					callback(e, span<char>(m_recvbuffer)
						.first(m_read_pos)
						.subspan(m_parser.body_start()));
				}
				m_read_pos = 0;
				m_last_receive = clock_type::now();
			}
			else if (m_bottled && m_parser.finished())
			{
				m_timer.cancel();
				callback(e, span<char>(m_recvbuffer)
					.first(m_read_pos)
					.subspan(m_parser.body_start()));
			}
		}
		else
		{
			TORRENT_ASSERT(!m_bottled);
			callback(e, span<char>(m_recvbuffer).first(m_read_pos));
			m_read_pos = 0;
			m_last_receive = clock_type::now();
		}

		// if we've hit the limit, double the buffer size
		if (int(m_recvbuffer.size()) == m_read_pos)
			m_recvbuffer.resize(std::min(m_read_pos * 2, m_max_bottled_buffer_size));

		if (m_read_pos == m_max_bottled_buffer_size)
		{
			// if we've reached the size limit, terminate the connection and
			// report the error
			callback(error_code(boost::system::errc::file_too_large, generic_category()));
			return;
		}
		int amount_to_read = int(m_recvbuffer.size()) - m_read_pos;
		if (m_rate_limit > 0 && amount_to_read > m_download_quota)
		{
			amount_to_read = m_download_quota;
			if (m_download_quota == 0)
			{
				if (!m_limiter_timer_active)
				{
					ADD_OUTSTANDING_ASYNC("http_connection::on_assign_bandwidth");
					on_assign_bandwidth(error_code());
				}
				return;
			}
		}
		ADD_OUTSTANDING_ASYNC("http_connection::on_read");
		m_sock->async_read_some(boost::asio::buffer(m_recvbuffer.data() + m_read_pos
			, std::size_t(amount_to_read))
			, std::bind(&http_connection::on_read
				, me, _1, _2));
	}

	void http_connection::on_assign_bandwidth(error_code const& e)
	{
		COMPLETE_ASYNC("http_connection::on_assign_bandwidth");
		if ((e == boost::asio::error::operation_aborted
			&& m_limiter_timer_active)
			|| !m_sock->is_open())
		{
			callback(boost::asio::error::eof);
			return;
		}
		m_limiter_timer_active = false;
		if (e) return;

		if (m_abort) return;

		if (m_download_quota > 0) return;

		m_download_quota = m_rate_limit / 4;

		int amount_to_read = int(m_recvbuffer.size()) - m_read_pos;
		if (amount_to_read > m_download_quota)
			amount_to_read = m_download_quota;

		if (!m_sock->is_open()) return;

		ADD_OUTSTANDING_ASYNC("http_connection::on_read");
		m_sock->async_read_some(boost::asio::buffer(m_recvbuffer.data() + m_read_pos
			, std::size_t(amount_to_read))
			, std::bind(&http_connection::on_read
				, shared_from_this(), _1, _2));

		m_limiter_timer_active = true;
		m_limiter_timer.expires_after(milliseconds(250));
		ADD_OUTSTANDING_ASYNC("http_connection::on_assign_bandwidth");
		m_limiter_timer.async_wait(std::bind(&http_connection::on_assign_bandwidth
			, shared_from_this(), _1));
	}

	void http_connection::rate_limit(int limit)
	{
		if (!m_sock->is_open()) return;

		if (!m_limiter_timer_active)
		{
			m_limiter_timer_active = true;
			m_limiter_timer.expires_after(milliseconds(250));
			ADD_OUTSTANDING_ASYNC("http_connection::on_assign_bandwidth");
			m_limiter_timer.async_wait(std::bind(&http_connection::on_assign_bandwidth
				, shared_from_this(), _1));
		}
		m_rate_limit = limit;
	}

}
