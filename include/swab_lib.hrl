%%%-------------------------------------------------------------------
%%% File:      swab_lib.hrl
%%% @author    Eric Pailleau <swab@crownedgrouse.com>
%%% @copyright 2014 crownedgrouse.com
%%% @doc  
%%% General purpose buffer handling - Internal library
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

%%*************************************************************************
%%***                      Internal libraries                           ***
%%*************************************************************************

%%-------------------------------------------------------------------------
%%@doc convertion wrapper to Unicode.
%%@end
%%-------------------------------------------------------------------------
-spec to_unicode(iolist(), latin1 | unicode | utf8 | utf16 | {utf16, big}| {utf16, little} | utf32 | {utf32, big}| {utf32, little}) -> iolist().
to_unicode(Buff,Type) -> Newbuff = case unicode:characters_to_list(Buff, Type) of
                        		{error, NB, _} 	    -> throw({error, "to_unicode : Error"}), NB ;
                        		{incomplete, NB, _} -> throw({error, "to_unicode : Buffer not completely converted."}), NB ;
                        		NB -> NB
                      		end,
                      Newbuff .
%%-------------------------------------------------------------------------
%%@doc convertion wrapper from Unicode.
%%@end
%%-------------------------------------------------------------------------
-spec from_unicode(binary(), latin1 | unicode | utf8 | utf16 | {utf16, big}| {utf16, little} | utf32 | {utf32, big}| {utf32, little}) -> binary().
from_unicode(Buff,Type) -> Newbuff = case unicode:characters_to_binary(Buff, unicode, Type) of
                        		{error, NB, _} 	    -> throw({error, "from_unicode : Error"}), NB ;
                        		{incomplete, NB, _} -> throw({error, "from_unicode : Buffer not completely converted."}), NB ;
                        		NB -> NB
                      		end,
                      Newbuff .

%%-------------------------------------------------------------------------
%%@doc Newline suppression.
%%@end
%%-------------------------------------------------------------------------
-spec nonl(iolist(), iolist()) -> iolist().
nonl([H | T], L) when (H == $\r) -> nonl(T, L) ;
nonl([H | T], L) when (H == $\n) -> nonl(T, L) ;
nonl([H | T], L) when (H == $\f) -> nonl(T, L) ;
nonl([H | T], L) when (H == $\x85) -> nonl(T, L) ;
nonl([H | T], L) when (H == $\x0b) -> nonl(T, L) ;
nonl([H | T], L) -> nonl(T, L ++ [H]) ;
nonl([], L) -> L.

%%-------------------------------------------------------------------------
%%@doc Fold
%%@end
%%-------------------------------------------------------------------------
fold(Len, [], Acc) when is_integer(Len) -> Acc ;
fold(Len, In, []) when  is_integer(Len),
                          is_binary(In),
                    byte_size(In) < Len -> binary_to_list(In) ;
fold(Len, In, Acc) when is_integer(Len),
                          is_binary(In),
                    byte_size(In) < Len,
                        is_list(Acc)    -> Acc ++ io_lib:nl() ++ binary_to_list(In) ;
fold(Len, In, []) when  is_integer(Len),
                          is_binary(In),
                   byte_size(In) >= Len-> {B1, B2} = split_binary(In, Len),
                                           fold(Len, B2, binary_to_list(B1)) ;
fold(Len, In, Acc) when is_integer(Len),
                          is_binary(In),
                   byte_size(In) >= Len,
                        is_list(Acc)    -> {B1, B2} = split_binary(In, Len),
                                           fold(Len, B2, Acc ++ io_lib:nl() ++ binary_to_list(B1)) .

%%-------------------------------------------------------------------------
%%@doc Queue init.
%%@end
%%-------------------------------------------------------------------------
-spec queue_init() -> ok.
queue_init() -> case get(qinit) of
                     true -> ok ;
                     _ -> put(queue,queue:new()),put(qinit,true), ok
                end.

%%-------------------------------------------------------------------------
%%@doc Wrapper for ram/cpu optimization.
%%     note : TODO: Minimize ram or cpu on big treatments.
%%@end
%%-------------------------------------------------------------------------
optimize(Val) -> Val.


