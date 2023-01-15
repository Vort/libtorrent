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

http_connection::http_connection(io_context& ios
	, aux::resolver_interface& resolver
	, http_handler handler
	, bool bottled
	, int max_bottled_buffer_size
	, http_connect_handler ch
	, http_filter_handler fh
	, hostname_filter_handler hfh
#if TORRENT_USE_SSL
	, ssl::context* ssl_ctx
#endif
	)
	: m_ios(ios)
	, m_next_ep(0)
#if TORRENT_USE_SSL
	, m_ssl_ctx(ssl_ctx)
#endif
#if TORRENT_USE_I2P
	, m_i2p_conn(nullptr)
#endif
	, m_resolver(resolver)
	, m_handler(std::move(handler))
	, m_connect_handler(std::move(ch))
	, m_filter_handler(std::move(fh))
	, m_hostname_filter_handler(std::move(hfh))
	, m_timer(ios)
	, m_completion_timeout(seconds(5))
	, m_limiter_timer(ios)
	, m_last_receive(aux::time_now())
	, m_start_time(aux::time_now())
	, m_read_pos(0)
	, m_redirects(5)
	, m_max_bottled_buffer_size(max_bottled_buffer_size)
	, m_rate_limit(0)
	, m_download_quota(0)
	, m_resolve_flags{}
	, m_port(0)
	, m_bottled(bottled)
{
	TORRENT_ASSERT(m_handler);
}

http_connection::~http_connection() = default;

void http_connection::get(std::string const& url, time_duration timeout
	, aux::proxy_settings const* ps, int handle_redirects, std::string const& user_agent
	, boost::optional<bind_info_t> const& bind_addr
	, aux::resolver_flags const resolve_flags, std::string const& auth_
#if TORRENT_USE_I2P
	, i2p_connection* i2p_conn
#endif
	)
{
	m_user_agent = user_agent;
	m_resolve_flags = resolve_flags;

	std::string protocol;
	std::string auth;
	std::string hostname;
	std::string path;
	error_code ec;
	int port;

	std::tie(protocol, auth, hostname, port, path)
		= parse_url_components(url, ec);

	if (auth.empty()) auth = auth_;

	m_auth = auth;

	int default_port = protocol == "https" ? 443 : 80;
	if (port == -1) port = default_port;

	// keep ourselves alive even if the callback function
	// deletes this object
	std::shared_ptr<http_connection> me(shared_from_this());

	if (ec)
	{
		post(m_ios, std::bind(&http_connection::callback
			, me, ec, span<char>{}));
		return;
	}

	if (m_hostname_filter_handler && !m_hostname_filter_handler(*this, hostname))
	{
		error_code err(errors::blocked_by_idna);
		post(m_ios, std::bind(&http_connection::callback
			, me, err, span<char>{}));
		return;
	}

	if (protocol != "http"
#if TORRENT_USE_SSL
		&& protocol != "https"
#endif
		)
	{
		error_code err(errors::unsupported_url_protocol);
		post(m_ios, std::bind(&http_connection::callback
			, me, err, span<char>{}));
		return;
	}

	bool const ssl = (protocol == "https");

	std::stringstream request;

	// exclude ssl here, because SSL assumes CONNECT support in the
	// proxy and is handled at the lower layer
	if (ps && (ps->type == settings_pack::http
		|| ps->type == settings_pack::http_pw)
		&& !ssl)
	{
		// if we're using an http proxy and not an ssl
		// connection, just do a regular http proxy request
		request << "GET " << url << " HTTP/1.1\r\n";
		if (ps->type == settings_pack::http_pw)
			request << "Proxy-Authorization: Basic " << base64encode(
				ps->username + ":" + ps->password) << "\r\n";

		request << "Host: " << hostname;
		if (port != default_port) request << ":" << port << "\r\n";
		else request << "\r\n";

		hostname = ps->hostname;
		port = ps->port;
	}
	else
	{
		request << "GET " << path << " HTTP/1.1\r\nHost: " << hostname;
		if (port != default_port) request << ":" << port << "\r\n";
		else request << "\r\n";
	}

//	request << "Accept: */*\r\n";

	if (!m_user_agent.empty())
		request << "User-Agent: " << m_user_agent << "\r\n";

	if (m_bottled)
		request << "Accept-Encoding: gzip\r\n";

	if (!auth.empty())
		request << "Authorization: Basic " << base64encode(auth) << "\r\n";

	request << "Connection: close\r\n\r\n";

	m_sendbuffer.assign(request.str());
	m_url = url;
	start(hostname, port, timeout
		, ps, ssl, handle_redirects, bind_addr, m_resolve_flags
#if TORRENT_USE_I2P
		, i2p_conn
#endif
		);
}

void http_connection::start(std::string const& hostname, int port
	, time_duration timeout, aux::proxy_settings const* ps, bool ssl
	, int handle_redirects
	, boost::optional<bind_info_t> const& bind_addr
	, aux::resolver_flags const resolve_flags
#if TORRENT_USE_I2P
	, i2p_connection* i2p_conn
#endif
	)
{
	m_redirects = handle_redirects;
	m_resolve_flags = resolve_flags;
	if (ps) m_proxy = *ps;

	// keep ourselves alive even if the callback function
	// deletes this object
	std::shared_ptr<http_connection> me(shared_from_this());

	m_completion_timeout = timeout;
	m_timer.expires_after(m_completion_timeout);
	ADD_OUTSTANDING_ASYNC("http_connection::on_timeout");
	m_timer.async_wait(std::bind(&http_connection::on_timeout
		, std::weak_ptr<http_connection>(me), _1));
	m_called = false;
	m_parser.reset();
	m_recvbuffer.clear();
	m_read_pos = 0;

#if TORRENT_USE_SSL
	TORRENT_ASSERT(!ssl || m_ssl_ctx != nullptr);
#endif

	if (m_sock && m_sock->is_open() && m_hostname == hostname && m_port == port
		&& m_ssl == ssl && m_bind_addr == bind_addr)
	{
		ADD_OUTSTANDING_ASYNC("http_connection::on_write");
		async_write(*m_sock, boost::asio::buffer(m_sendbuffer)
			, std::bind(&http_connection::on_write, me, _1));
	}
	else
	{
		m_ssl = ssl;
		m_bind_addr = bind_addr;
		error_code err;
		if (m_sock && m_sock->is_open()) m_sock->close(err);

		aux::proxy_settings const* proxy = ps;

#if TORRENT_USE_I2P
		bool is_i2p = false;
		char const* top_domain = strrchr(hostname.c_str(), '.');
		aux::proxy_settings i2p_proxy;
		if (top_domain && top_domain == ".i2p"_sv && i2p_conn)
		{
			// this is an i2p name, we need to use the sam connection
			// to do the name lookup
			is_i2p = true;
			m_i2p_conn = i2p_conn;
			// quadruple the timeout for i2p destinations
			// because i2p is sloooooow
			m_completion_timeout *= 4;

#if TORRENT_USE_I2P
			if (i2p_conn->proxy().type != settings_pack::i2p_proxy)
			{
				post(m_ios, std::bind(&http_connection::callback
					, me, error_code(errors::no_i2p_router), span<char>{}));
				return;
			}
#endif

			i2p_proxy = i2p_conn->proxy();
			proxy = &i2p_proxy;
		}
#endif

		// in this case, the upper layer is assumed to have taken
		// care of the proxying already. Don't instantiate the socket
		// with this proxy
		if (proxy && (proxy->type == settings_pack::http
			|| proxy->type == settings_pack::http_pw)
			&& !ssl)
		{
			proxy = nullptr;
		}
		aux::proxy_settings null_proxy;

		void* userdata = nullptr;
#if TORRENT_USE_SSL
		if (m_ssl)
		{
			TORRENT_ASSERT(m_ssl_ctx != nullptr);
			userdata = m_ssl_ctx;
		}
#endif
		// assume this is not a tracker connection. Tracker connections that
		// shouldn't be subject to the proxy should pass in nullptr as the proxy
		// pointer.
		m_sock.emplace(instantiate_connection(m_ios
			, proxy ? *proxy : null_proxy, userdata, nullptr, false, false));

		if (m_bind_addr)
		{
			error_code ec;
			m_sock->open(m_bind_addr->ip.is_v4() ? tcp::v4() : tcp::v6(), ec);
#if TORRENT_HAS_BINDTODEVICE
			error_code ignore;
			bind_device(*m_sock, m_bind_addr->device.c_str(), ignore);
#endif
			m_sock->bind(tcp::endpoint(m_bind_addr->ip, 0), ec);
			if (ec)
			{
				post(m_ios, std::bind(&http_connection::callback
					, me, ec, span<char>{}));
				return;
			}
		}

		error_code ec;
		setup_ssl_hostname(*m_sock, hostname, ec);
		if (ec)
		{
			post(m_ios, std::bind(&http_connection::callback
				, me, ec, span<char>{}));
			return;
		}

		m_endpoints.clear();
		m_next_ep = 0;

#if TORRENT_USE_I2P
		if (is_i2p)
		{
			if (hostname.length() < 516) // Base64 encoded  destination with optional .i2p
			{
				ADD_OUTSTANDING_ASYNC("http_connection::on_i2p_resolve");
				i2p_conn->async_name_lookup(hostname.c_str(), std::bind(&http_connection::on_i2p_resolve
					, me, _1, _2));
			}
			else
				connect_i2p_tracker(hostname.c_str());
		}
		else
#endif
		{
			m_hostname = hostname;
			if (ps && ps->proxy_hostnames
				&& (ps->type == settings_pack::socks5
					|| ps->type == settings_pack::socks5_pw))
			{
				m_port = std::uint16_t(port);
				m_endpoints.emplace_back(address(), m_port);
				connect();
			}
			else
			{
				m_resolving_host = true;
				ADD_OUTSTANDING_ASYNC("http_connection::on_resolve");
				m_resolver.async_resolve(hostname, m_resolve_flags
					, std::bind(&http_connection::on_resolve
						, me, _1, _2));
			}
		}
		m_hostname = hostname;
		m_port = std::uint16_t(port);
	}
}

void http_connection::on_timeout(std::weak_ptr<http_connection> p
	, error_code const& e)
{
	COMPLETE_ASYNC("http_connection::on_timeout");
	std::shared_ptr<http_connection> c = p.lock();
	if (!c) return;

	if (e == boost::asio::error::operation_aborted) return;

	if (c->m_abort) return;

	time_point const now = clock_type::now();

	// be forgiving of timeout while we're still resolving the hostname
	// it may be delayed because we're queued up behind another slow lookup
	if (c->m_resolving_host
		&& (c->m_start_time + (c->m_completion_timeout * 2) > now))
	{
		ADD_OUTSTANDING_ASYNC("http_connection::on_timeout");
		c->m_timer.expires_at(c->m_start_time + c->m_completion_timeout * 2);
		c->m_timer.async_wait(std::bind(&http_connection::on_timeout, p, _1));
		return;
	}

	if (c->m_start_time + c->m_completion_timeout <= now)
	{
		// the connection timed out. If we have more endpoints to try, just
		// close this connection. The on_connect handler will try the next
		// endpoint in the list.
		if (c->m_next_ep < int(c->m_endpoints.size()))
		{
			error_code ec;
			c->m_sock->close(ec);
			if (!c->m_connecting) c->connect();
			c->m_last_receive = now;
			c->m_start_time = c->m_last_receive;
		}
		else
		{
			// the socket may have an outstanding operation, that keeps the
			// http_connection object alive. We want to cancel all that.
			error_code ec;
			c->m_sock->close(ec);
			c->callback(lt::errors::timed_out);
			return;
		}
	}

	ADD_OUTSTANDING_ASYNC("http_connection::on_timeout");
	c->m_timer.expires_at(c->m_start_time + c->m_completion_timeout);
	c->m_timer.async_wait(std::bind(&http_connection::on_timeout, p, _1));
}

}
