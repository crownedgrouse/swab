%%%-------------------------------------------------------------------
%%% File:      swab_hexdump.hrl
%%% @author    Eric Pailleau <swab@crownedgrouse.com>
%%% @copyright 2014 crownedgrouse.com
%%% @doc  
%%% General purpose buffer handling - SWAB hexdump library
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

-record(hexdump, {  prefix      = "~8.16.0b " :: string(), 
                    data        = " ~2.16.0b" :: string(), 
                    width       = 8 :: integer(), 
                    nb          = 2 :: integer(), 
                    canonical   = 'true' :: 'true' | 'false', 
                    sep         = "|" :: string(), 
                    line        = 0 :: integer(), 
                    io          = standard_io :: pid() | atom()}).

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
-spec hexdump(list(), #hexdump{}) -> 'ok'. 

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

hexdump_line(A, R) ->   io:fwrite(R#hexdump.io, R#hexdump.prefix, [R#hexdump.line * R#hexdump.width * R#hexdump.nb] ),
		                lists:foreach(fun(X) -> io:fwrite(R#hexdump.io, R#hexdump.data, [X]) end,A)	,
		                % If the line is not complete, do it with blanks
		                io:fwrite(R#hexdump.io, string:copies("   ",round(R#hexdump.width * R#hexdump.nb) - length(A)),[]),
		                case R#hexdump.canonical of
			                'false'   -> io:fwrite(R#hexdump.io, " ",[]) ;
			                'true'    -> io:fwrite(R#hexdump.io, " ~s",[R#hexdump.sep]),
				                        lists:foreach(fun(X) -> io:fwrite(R#hexdump.io, "~s", [hexdump_printable(X)]) end,A),
				                        io:fwrite(R#hexdump.io, "~s",[R#hexdump.sep])
		                end,
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

%%-------------------------------------------------------------------------
%%@doc Zulu time to local time
%%@end
%%-------------------------------------------------------------------------
-spec zulu_to_localtime(iolist()) -> iolist().

zulu_to_localtime(Z) -> {A1,A2,M1,M2,D1,D2,H1,H2,I1,I2,S1,S2,_} = list_to_tuple(Z),
			            {{Year, Month, Day},{Hour, Min, Sec}} = calendar:universal_time_to_local_time({{
								                                        list_to_integer("20"++[A1,A2]), 
								                                        list_to_integer([M1,M2]), 
								                                        list_to_integer([D1,D2])},
								                                        {list_to_integer([H1,H2]), 
								                                        list_to_integer([I1,I2]), 
								                                        list_to_integer([S1,S2])} }),
			            io_lib:fwrite("~4.10.0b-~2.10.0b-~2.10.0b ~2.10.0b:~2.10.0b:~2.10.0b",[Year,Month,Day,Hour,Min,Sec]).

%%-------------------------------------------------------------------------
%%@doc Timezone
%%@end
%%-------------------------------------------------------------------------
-spec timezone() -> list() .
timezone() ->   {{_, _, UD},{UH,_, _}} = calendar:universal_time(),
	            {{_, _, LD},{LH,_, _}} = calendar:local_time(),
	            Offset = (LD*24 + LH) - (UD*24 + UH),
	            case (Offset >= 0) of
		            true  -> [Offset,"+"] ;
		            false -> [abs(Offset),"-"] 
	            end.
			
