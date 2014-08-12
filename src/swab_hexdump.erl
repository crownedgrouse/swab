%%%-------------------------------------------------------------------
%%% File:      swab_hexdump.erl
%%% @author    Eric Pailleau <swab@crownedgrouse.com>
%%% @copyright 2014 crownedgrouse.com
%%% @doc  
%%%             hexdump module for swab
%%% @end  
%%%
%%% Permission to use, copy, modify, and/or distribute this software
%%% for any purpose with or without fee is hereby granted, provided
%%% that the above copyright notice and this permission notice appear
%%% in all copies.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
%%% WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
%%% WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
%%% AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
%%% CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
%%% LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
%%% NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
%%% CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%%%
%%% Created : 2014-07-14
%%%-------------------------------------------------------------------
-module(swab_hexdump).

-export([hexdump/1, hexdump/2]).

-include("swab_hexdump.hrl").

%%-------------------------------------------------------------------------
%%@doc Main function call
%%@end
%%-------------------------------------------------------------------------
-spec hexdump(binary() | [any()]) -> 'ok'.

hexdump(Data) when is_binary(Data)  -> hexdump(binary_to_list(Data), #hexdump{});
hexdump(Data) when is_list(Data)    -> hexdump(Data, #hexdump{}).

%%-------------------------------------------------------------------------
%%@doc Treat data
%%@end
%%-------------------------------------------------------------------------
-spec hexdump(list(), #hexdump{prefix::string(),data::string(),width::integer(),nb::integer(),canonical::boolean(),sep::string(),line::integer(),io::atom() | pid()}) -> 'ok'. 

hexdump(L, R) when is_list(L),
                   is_tuple(R),
                   (length(L)=< (R#hexdump.width * R#hexdump.nb)) -> hexdump_line(L, R);
hexdump(L, R) when is_list(L),
                   is_tuple(R),
                   (length(L)> R#hexdump.width * R#hexdump.nb)    -> % Take width*nb octets , and let's treat it, then the remaining
					                                                 {A, B} = lists:split(R#hexdump.width * R#hexdump.nb, L),
					                                                 hexdump_line(A, R),
					                                                 case B of
						                                                [] -> io:fwrite(R#hexdump.io, "",[]);
						                                                _  -> hexdump(B, R#hexdump{line= (R#hexdump.line + 1)})
					                                                 end.

%%-------------------------------------------------------------------------
%%@doc Treat line
%%@end
%%-------------------------------------------------------------------------
-spec hexdump_line(list(), #hexdump{}) -> 'ok'.

hexdump_line(A, R) 
        when R#hexdump.canonical =:= true ->    io:fwrite(R#hexdump.io, R#hexdump.prefix, [R#hexdump.line * R#hexdump.width * R#hexdump.nb] ),
                                                lists:foreach(fun(X) -> io:fwrite(R#hexdump.io, R#hexdump.data, [X]) end,A)	,
                                                % If the line is not complete, do it with blanks
                                                io:fwrite(R#hexdump.io, string:copies("   ",round(R#hexdump.width * R#hexdump.nb) - length(A)),[]),
                                                io:fwrite(R#hexdump.io, " ~s",[R#hexdump.sep]),
                                                lists:foreach(fun(X) -> io:fwrite(R#hexdump.io, "~s", [hexdump_printable(X)]) end,A),
                                                io:fwrite(R#hexdump.io, "~s",[R#hexdump.sep]),
                                                io:fwrite(R#hexdump.io, "~n",[]);

hexdump_line(A, R) 
        when R#hexdump.canonical =:= false ->   io:fwrite(R#hexdump.io, R#hexdump.prefix, [R#hexdump.line * R#hexdump.width * R#hexdump.nb] ),
                                                lists:foreach(fun(X) -> io:fwrite(R#hexdump.io, R#hexdump.data, [X]) end,A)	,
                                                % If the line is not complete, do it with blanks
                                                io:fwrite(R#hexdump.io, string:copies("   ",round(R#hexdump.width * R#hexdump.nb) - length(A)),[]),
                                                io:fwrite(R#hexdump.io, " ",[]),
                                                io:fwrite(R#hexdump.io, "~n",[]).

%%-------------------------------------------------------------------------
%%@doc Is character printable or not ?
%%@end
%%-------------------------------------------------------------------------
-spec hexdump_printable(_) -> [any(),...].

hexdump_printable(X) -> case ((X>31) and (X<128)) of
			                true -> [X] ;
			                false -> "."
		                end.


