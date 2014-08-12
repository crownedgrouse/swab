%%%-----------------------------------------------------------------------
%%% File:      swab_asn1.erl
%%% @author    Eric Pailleau <swab@crownedgrouse.com>
%%% @copyright 2014 crownedgrouse.com
%%% @doc  
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
%%%-----------------------------------------------------------------------
-module(swab_asn1).

-export([asn1_pp/1, asn1_pp/2]).

-include("swab_hexdump.hrl").
-include("swab_asn1_otp.hrl"). % External code, thanks Ericsson AB.

%%*************************************************************************
%% ASN 1
%%*************************************************************************
%%asn1_struct(B) -> asn1rt:decode(B).

-record(asn1_pp, {  module      = undefined, 
                    indent      = true :: 'true' | 'false', 
                    tab         = ".  ", 
                    hexdump     = true :: 'true' | 'false', 
                    hexdump_conf= #hexdump{}, 
                    depth       = 0 , 
                    context     = undefined, 
                    io          = standard_io}).

%%-------------------------------------------------------------------------
%%@doc ASN1 pretty printer
%%     Default.
%%@end
%%-------------------------------------------------------------------------
-spec asn1_pp(list() | binary()) -> 'ok' | tuple().

asn1_pp(P) -> _ =   asn1_pp(P, #asn1_pp{}).

%%-------------------------------------------------------------------------
%%@doc ASN1 pretty printer
%%     Custom.
%%@end
%%-------------------------------------------------------------------------
-spec asn1_pp(list() | binary(), #asn1_pp{} | true | false) -> 'ok' | tuple().

asn1_pp(P, true)  ->  asn1_pp(P, #asn1_pp{} );
asn1_pp(P, false) ->  asn1_pp(P, #asn1_pp{indent=false} );
asn1_pp(P, R) when is_list(P),is_tuple(R) -> % Assuming it is a path to a file
			      case file:read_file(P) of 
                    {ok, B} ->  asn1_print(asn1_parse(B), R#asn1_pp{depth=0, context=undefined}),ok;
                    {error, E} -> {error, E}
			      end;
asn1_pp(B, R) when is_binary(B)-> asn1_print(asn1_parse(B), R#asn1_pp{depth=0, context=undefined}),ok.

%%-------------------------------------------------------------------------
%%@doc ASN1 formatter
%%@end
%%-------------------------------------------------------------------------
-spec asn1_print(list() | binary() | tuple(), #asn1_pp{}) -> _.

asn1_print(L, R) when is_list(L) -> N= R#asn1_pp{depth= (R#asn1_pp.depth + 1)},
				                    lists:foreach(fun(A) -> asn1_print(A, N) end, L),
				                    io:fwrite(R#asn1_pp.io, "~s~n", [asn1_indent(N) ++ "END"]);
asn1_print(B, R) when is_binary(B)->
               case R#asn1_pp.context of
				        undefined      ->   ok ;
                        context        ->   io:fwrite(R#asn1_pp.io, "~n",[]) ;
				        integer        ->   io:fwrite(R#asn1_pp.io, "~.10# (~.16#)~n",[binary:decode_unsigned(B),binary:decode_unsigned(B)]);
				        bit_string     ->   io:fwrite(R#asn1_pp.io, "~n",[]),
                                            asn1_hexdump(B, R);
				        octet_string   ->   io:fwrite(R#asn1_pp.io, "~n",[]),
                                            asn1_hexdump(B, R);
				        null           ->   io:fwrite(R#asn1_pp.io, "~w~n",[B]);
				        object         ->   OID= ber_to_oid(B),
                                            io:fwrite(R#asn1_pp.io, "~s ~w~n",[oid_to_name(R#asn1_pp.module, OID), OID]);
				        printablestring ->  io:fwrite(R#asn1_pp.io, "~s~n",[binary_to_list(B)]);
				        t61string      ->   io:fwrite(R#asn1_pp.io, "~w~n",[B]);
				        ia5string      ->   io:fwrite(R#asn1_pp.io, "~s~n",[binary_to_list(B)]),
                                            asn1_hexdump(B, R);
				        utctime        ->   io:fwrite(R#asn1_pp.io, "~s (",[binary_to_list(B)]),
                                            io:fwrite(R#asn1_pp.io, "~s", [zulu_to_localtime(binary_to_list(B))]),
                                            io:fwrite(R#asn1_pp.io, " UTC~X)~n",timezone());
				        _              ->   case io_lib:printable_list(binary_to_list(B)) of
                                                true -> io:fwrite(R#asn1_pp.io, "~s~n",[binary_to_list(B)]) ;
                                                false -> io:fwrite(R#asn1_pp.io, "~w~n",[B]) 
                                            end
			    end;
asn1_print(T, R) when is_tuple(T)-> 
	case T of
	    {seq, indef, _, _}            -> io:fwrite(R#asn1_pp.io, "~s~n", [asn1_indent(R#asn1_pp{context=sequence}) ++"INDEF SEQUENCE"]),sequence ;
	    {seq, _, _}                   -> io:fwrite(R#asn1_pp.io, "~s~n", [asn1_indent(R#asn1_pp{context=sequence}) ++"SEQUENCE"]),sequence  ;
	    {set, _, _}                   -> io:fwrite(R#asn1_pp.io, "~s~n", [asn1_indent(R#asn1_pp{context=set}) ++"SET"]),set ;
	    {constructor, indef, _, _}    -> io:fwrite(R#asn1_pp.io, "~s~n", [asn1_indent(R#asn1_pp{context=constructor}) ++"INDEF CONSTRUCTOR"]),constructor ;
	    {constructor, _, _}           -> io:fwrite(R#asn1_pp.io, "~s~n", [asn1_indent(R#asn1_pp{context=constructor}) ++"CONSTRUCTOR"]),constructor ;
        {tag, _, 0}                   -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=integer}) ++"CONTEXT"]),context ;
	    {tag, _, 2}                   -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=integer}) ++"INTEGER\t: "]),integer ;
	    {tag, _, 3}                   -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=bit_string}) ++"BIT STRING\t: "]),bit_string ;
	    {tag, _, 4}                   -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=octet_string}) ++"OCTET STRING\t: "]),octet_string ;
	    {tag, _, 5}                   -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=null}) ++"NULL\t: "]),null ;
	    {tag, _, 6}                   -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=object}) ++"OBJECT\t: "]),object ;
        {tag, _, 12}                  -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=univ}) ++"VALUE\t: "]),univ ;
	    {tag, _, 19}                  -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=printablestring}) ++"PRINTABLESTRING\t: "]),printablestring ;
	    {tag, _, 20}                  -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=t61string}) ++"T61STRING\t: "]),t61string ;
	    {tag, _, 22}                  -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=ia5string}) ++"IA5STRING\t: "]),ia5string ;
	    {tag, _, 23}                  -> io:fwrite(R#asn1_pp.io, "~s", [asn1_indent(R#asn1_pp{context=utctime}) ++"UTCTIME\t: "]),utctime ;
	    X when is_tuple(X),(size(X)==2) -> {A, B} = X, asn1_print(B, R#asn1_pp{context=asn1_print(A, R)}) ;
	    Z                             -> io:fwrite(R#asn1_pp.io, asn1_indent(R#asn1_pp{context=undefined}) ++"??? ~w~n",[Z]),undefined
	end.

%%-------------------------------------------------------------------------
%%@doc Indent
%%@end
%%-------------------------------------------------------------------------
-spec asn1_indent(tuple()) -> _.

asn1_indent(R) when is_tuple(R) -> case R#asn1_pp.indent of
					'false'    -> "" ;
					'true'     -> string:copies(R#asn1_pp.tab, max(0,R#asn1_pp.depth - 1))
				    end.

%%-------------------------------------------------------------------------
%%@doc BER to OID
%%@end
%%-------------------------------------------------------------------------
-spec ber_to_oid(binary()) -> tuple().

ber_to_oid(<<A/integer,R/binary>>) -> X=(A div 40), 
				    list_to_tuple(lists:flatten([X, (A - (X*40))] ++ b128_decode(binary_to_list(R)))) .

%%-------------------------------------------------------------------------
%%@doc Decoding 
%%@end
%%-------------------------------------------------------------------------
-spec b128_decode(list()) -> _.

b128_decode(B) when is_list(B) -> P = lists:takewhile(fun(X)-> X >= 128 end, B),
				    Z = lists:subtract(B, P),
				    A = case Z of
				        [] -> P;
				        _  -> P ++ [hd(Z)]
				      end,
                    R = case Z of
				        [] -> [];
				        _  -> tl(Z)
                      end,
				    case A of
				        [] -> [];
				        B  -> [b128_to_b10(B)];
				        _  -> [b128_to_b10(lists:flatten([A]))] ++ [b128_decode(lists:flatten([R]))]
				    end.

%%-------------------------------------------------------------------------
%%@doc Decoding
%%@end
%%-------------------------------------------------------------------------
-spec b128_to_b10(list()) -> _ .

b128_to_b10(B) when is_list(B) ->   b128_to_b10(lists:reverse(B), 0).

-spec b128_to_b10(list(), integer()) -> _ .

b128_to_b10([], _) -> 0;
b128_to_b10(B, Pow) when is_list(B),(length(B)==1) -> H = hd(B),
						      case H of
                                H when (H <128) ->  erlang:round(H * math:pow(128,Pow));
                                H when (H >= 128) ->  erlang:round((H-128) * math:pow(128,Pow))
						      end;
b128_to_b10(B, Pow) when is_list(B),(length(B)>1) -> H = hd(B),
						     T = tl(B),
						     case H of
                                H when (H < 128) -> erlang:round(H * math:pow(128,Pow))+ b128_to_b10(T, (Pow + 1));
                                H when (H >= 128) -> erlang:round((H - 128) * math:pow(128,Pow))+ b128_to_b10(T, (Pow + 1))
						     end.

%%-------------------------------------------------------------------------
%%@doc OID to Name
%%@end
%%-------------------------------------------------------------------------
-spec oid_to_name(atom(),tuple()) -> _ .

oid_to_name(M, Oid) when is_atom(M),is_tuple(Oid) ->
                        case M of
                              undefined -> "" ;
                              _ -> L = M:module_info(exports),
                                   case lists:keyfind(oid_to_name,1,L) of
                                        false -> "";
                                        _ -> apply(M, oid_to_name, [Oid])
                                   end
						      end.

%%-------------------------------------------------------------------------
%%@doc Hexdump non printable data
%%@end
%%-------------------------------------------------------------------------
-spec asn1_hexdump(binary(),#asn1_pp{indent::'false' | 'true',hexdump::'false' | 'true',depth::non_neg_integer(),context::atom()}) -> 'ok'.

asn1_hexdump(B, R) -> case R#asn1_pp.hexdump of
                        true -> swab_hexdump:hexdump(binary_to_list(B), R#asn1_pp.hexdump_conf) ;
                        _    -> io:fwrite(R#asn1_pp.io, "~w~n",[B])
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
