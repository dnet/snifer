-module(snifer).
-export([start/0, acceptor/1]).

-include_lib("ssl/src/ssl_cipher.hrl").
-include_lib("ssl/src/ssl_internal.hrl").
-include_lib("ssl/src/tls_handshake.hrl").
-include_lib("ssl/src/tls_record.hrl").

-define(MARK_DIR, "redirs/").
-define(LISTEN_PORT, 443).
-define(DEFAULT_PORT, 5000).
-define(SSL_TLS_VERSIONS, [{3, 1}, {3, 2}, {3, 3}]).

start() ->
	{ok, LSock} = gen_tcp:listen(?LISTEN_PORT, [binary,{reuseaddr, true}, {active, true}, {packet, raw}]),
   logger:start(),
	acceptor(LSock).

acceptor(LSock) ->
	{ok, Sock} = gen_tcp:accept(LSock),
	gen_tcp:controlling_process(LSock, spawn(?MODULE, acceptor, [LSock])),
	receive
		{tcp, Sock, ClientHello} ->
			{Name, Target} = get_target(ClientHello),
			case gen_tcp:connect("localhost", Target, [binary, {active, true}, {packet, raw}]) of
				{ok, TargetSock} -> 
               {ok, {Source, _ }} = inet:peername(Sock),
               logger:log(Name, Source, Target),
					gen_tcp:send(TargetSock, ClientHello), forwarder(Sock, TargetSock);
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
         case file:open(?MARK_DIR ++ Name, [read, raw, read_ahead]) of
            {ok, File} ->
               case file:read_line(File) of
                 {ok, Line} -> { Name, list_to_integer(string:strip(Line, right, $\n))}
               end;
            {error,enoent} -> io:format("Couldn't open file: ~p~n", [?MARK_DIR ++ Name]), {"file err", ?DEFAULT_PORT}
         end
	catch
		E -> io:format("Couldn't extract SNI: ~p~n", [E]), {"no sni", ?DEFAULT_PORT}
	end.

get_server_name(Packet) ->
	{[Record | _], _} = tls_record:get_tls_records(Packet, ?SSL_TLS_VERSIONS, <<>>),
	{[{ClientHello, _}], _} = tls_handshake:get_tls_handshake(
		Record#ssl_tls.version, Record#ssl_tls.fragment, <<>>, #ssl_options{v2_hello_compatible=true} ),
	ClientHello#client_hello.extensions#hello_extensions.sni#sni.hostname.
