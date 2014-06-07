-module(snifer).
-export([start/0, acceptor/1]).

-include_lib("ssl/src/tls_handshake.hrl").
-include_lib("ssl/src/tls_record.hrl").

-define(MARK_FILE, "hosts.txt").
-define(MARK_PORT, 4000).
-define(LISTEN_PORT, 5000).
-define(DEFAULT_PORT, 6000).

start() ->
	{ok, LSock} = gen_tcp:listen(?LISTEN_PORT, [binary, {active, true}, {packet, raw}]),
	acceptor(LSock).

acceptor(LSock) ->
	{ok, Sock} = gen_tcp:accept(LSock),
	gen_tcp:controlling_process(LSock, spawn(?MODULE, acceptor, [LSock])),
	receive
		{tcp, Sock, ClientHello} ->
			Target = get_target(ClientHello),
			case gen_tcp:connect("localhost", Target, [binary, {active, true}, {packet, raw}]) of
				{ok, TargetSock} -> gen_tcp:send(TargetSock, ClientHello), forwarder(Sock, TargetSock);
				{error, Reason} -> io:format("Couldn't connect to target: ~p~n", [Reason])
			end;
		_ -> ok
	end.

forwarder(Socket1, Socket2) ->
	Continue = receive
		{tcp, Socket1, Data} -> gen_tcp:send(Socket2, Data), true;
		{tcp, Socket2, Data} -> gen_tcp:send(Socket1, Data), true;
		{tcp_closed, Socket1} -> gen_tcp:close(Socket2), false;
		{tcp_closed, Socket2} -> gen_tcp:close(Socket1), false;
		{tcp_error, S, _} when S =:= Socket1; S =:= Socket2 -> false
	end,
	case Continue of
		true -> forwarder(Socket1, Socket2);
		false -> ok
	end.

get_target(Packet) ->
	try get_server_name(Packet) of
		Name ->
			{ok, File} = file:open(?MARK_FILE, [read, raw, read_ahead]),
			case match_lines(File, Name) of
				true -> ?MARK_PORT;
				false -> ?DEFAULT_PORT
			end
	catch
		E -> io:format("Couldn't extract SNI: ~p~n", [E]), ?DEFAULT_PORT
	end.

match_lines(File, Name) ->
	case file:read_line(File) of
		{ok, Line} ->
			Name == string:strip(Line, right, $\n) orelse match_lines(File, Name);
		eof -> file:close(File), false
	end.

get_server_name(Packet) ->
	{[Record | _], _} = tls_record:get_tls_records(Packet, <<>>),
	{[{ClientHello, _}], _} = tls_handshake:get_tls_handshake(
		Record#ssl_tls.version, Record#ssl_tls.fragment, <<>>),
	ClientHello#client_hello.extensions#hello_extensions.sni#sni.hostname.
