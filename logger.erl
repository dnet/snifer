-module(logger).
-behaviour(gen_server).

-export([start/0]).
-export([log/3]).
-export([init/1, handle_cast/2]).

-define(LOG_FILE, "snifer.log").

iso_8601_fmt(DateTime) ->
    {{Year,Month,Day},{Hour,Min,Sec}} = DateTime,
    io_lib:format("~4.10.0B-~2.10.0B-~2.10.0B ~2.10.0B:~2.10.0B:~2.10.0B", [Year, Month, Day, Hour, Min, Sec]).

start() ->
    gen_server:start({local, logger}, logger, [?LOG_FILE], []).

log(Name, Source, Target) ->
    gen_server:cast(logger, {log, Name, Source, Target}).

init([LogFile]) ->
   file:open(LogFile, [append, raw]).

handle_cast({log, Name, Source, Target}, Logfile) ->
   Msg = io_lib:format("~s ~s from ~s dispatched to ~p~n", [iso_8601_fmt(erlang:localtime()), Name, inet_parse:ntoa(Source), Target]),
   io:format(Msg),
   file:write(Logfile, Msg),
   {noreply, Logfile}. 
