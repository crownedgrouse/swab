%%%-------------------------------------------------------------------
%%% File:      swab_tests.erl
%%% @author    Eric Pailleau <swab@crownedgrouse.com>
%%% @copyright 2014 crownedgrouse.com
%%% @doc  
%%% General purpose buffer handling - Unit tests
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
-module(swab_tests).
-include_lib("eunit/include/eunit.hrl").

-define(NL, io_lib:nl()).

-ifdef(EUNIT).

analyze_test() -> 
		   % cast
		    ?assertEqual({ok, "   I LOVE ERLANG   "}, swab:sync([{cast, upper}], "   I love Erlang   "))
		   ,?assertEqual({ok, "   I LOVE ERLANG   "}, swab:sync({cast, upper}, "   I love Erlang   "))
		   ,?assertEqual({ok, "   i love erlang   "}, swab:sync([{cast, lower}], "   I love Erlang   "))
		   ,?assertEqual({ok, "   i love erlang   "}, swab:sync({cast, lower}, "   I love Erlang   "))
           % trim
		   ,?assertEqual({ok, "I love Erlang !"}, swab:sync({trim, both },"   I love Erlang !   "))
		   ,?assertEqual({ok, "I love Erlang !   "}, swab:sync({trim, left },"   I love Erlang !   "))
		   ,?assertEqual({ok, "   I love Erlang !"}, swab:sync({trim, right },"   I love Erlang !   "))
		   ,?assertEqual({ok, []}, swab:sync({trim, {both, $.} },"................."))
           % feed
           ,?assertEqual({ok,"abc       \nadcdefghij\n12345678  \n987654321 "},swab:sync({feed,10}, "abc\nadcdefghij\n12345678\n987654321"))
           ,?assertEqual({ok,"abc*******\nadcdefghij\n12345678**\n987654321*"},swab:sync({feed, {10, $*}}, "abc\nadcdefghij\n12345678\n987654321"))
           ,?assertEqual({ok,"*******abc\nadcdefghij\n**12345678\n*987654321"},swab:sync({feed, {-10, $*}}, "abc\nadcdefghij\n12345678\n987654321"))
           % fold
           ,?assertEqual({ok,"1234567890\n123456789a\nbcdefghijk\nl"},swab:sync({fold, 10}, "1234567890123456789abcdefghijkl"))
           ,?assertEqual({ok,"1234567\n89\n0123456789\nabc\ndefghi\njkl"},swab:sync({fold, 10}, "1234567\n890123456789abc\ndefghijkl"))
		   % sort
		   ,?assertEqual({ok, "aaa\nbbb\nccc\nddd"}, swab:sync([{sort, normal}], "aaa\nccc\nbbb\nddd\n"))
		   ,?assertEqual({ok, "aaa\nbbb\nccc\nddd"}, swab:sync({sort, normal}, "aaa\nccc\nbbb\nddd\n"))
		   ,?assertEqual({ok, "ddd\nccc\nbbb\naaa"}, swab:sync([{sort, reverse}], "aaa\nccc\nbbb\nddd\n"))
		   ,?assertEqual({ok, "ddd\nccc\nbbb\naaa"}, swab:sync({sort, reverse}, "aaa\nccc\nbbb\nddd\n"))
		   ,?assertEqual({ok, "ddd\nbbb\nccc\naaa"}, swab:sync([{sort, inverse}], "aaa\nccc\nbbb\nddd\n"))
		   ,?assertEqual({ok, "ddd\nbbb\nccc\naaa"}, swab:sync({sort, inverse}, "aaa\nccc\nbbb\nddd\n"))
		   % decode
		   ,{ok, EBCDIC} = file:read_file(filename:join([code:priv_dir(swab), "ebcdic.seq"]))
		   ,?assertEqual( {ok, lists:seq(1,255)}, swab:sync([{decode, ebcdic}], binary_to_list(EBCDIC)))
		   ,?assertEqual( {ok, lists:seq(1,255)}, swab:sync({decode, ebcdic}, binary_to_list(EBCDIC)))
		   % encode
		   ,?assertEqual( {ok, binary_to_list(EBCDIC)}, swab:sync([{encode, ebcdic}], lists:seq(1,255)))
		   ,?assertEqual( {ok, binary_to_list(EBCDIC)}, swab:sync({encode, ebcdic}, lists:seq(1,255)))
		   % convert
		   ,?assertEqual({ok, "abcdefg"}, swab:sync([{convert, nonl}], "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "abcdefg"}, swab:sync({convert, nonl}, "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "a"++?NL++"b"++?NL++"c"++?NL++"d"++?NL++"e"++?NL++"f"++?NL++"g"}, 
			swab:sync([{convert, local_nl}], "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "a"++?NL++"b"++?NL++"c"++?NL++"d"++?NL++"e"++?NL++"f"++?NL++"g"}, 
			swab:sync({convert, local_nl}, "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   % sub_word
		   ,?assertEqual({ok, "love"}, swab:sync([{sub_word, 2}], "   I love Erlang   "))
		   ,?assertEqual({ok, "love"}, swab:sync({sub_word, 2}, "   I love Erlang   "))
		   ,?assertEqual({ok, "love"}, swab:sync([{sub_word, 2}], "   I\n love Erlang   "))
		   ,?assertEqual({ok, "love"}, swab:sync({sub_word, 2}, "   I\n love Erlang   "))
		   % jump
		   ,?assertEqual({ok, "d"++?NL++"e"++?NL++"f"++?NL++"g"}, swab:sync([{jump, 3}], "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "d"++?NL++"e"++?NL++"f"++?NL++"g"}, swab:sync({jump, 3}, "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "a"++?NL++"b"++?NL++"c"++?NL++"d"++?NL++"e"++?NL++"f"++?NL++"g"}, 
			swab:sync([{jump, 0}], "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "a"++?NL++"b"++?NL++"c"++?NL++"d"++?NL++"e"++?NL++"f"++?NL++"g"}, 
			swab:sync({jump, 0}, "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "f"++?NL++"g"}, swab:sync([{jump, -2}], "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "f"++?NL++"g"}, swab:sync({jump, -2}, "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   % nblines
		   ,?assertEqual({ok, "a"}, swab:sync([{nblines, first}], "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "a"}, swab:sync({nblines, first}, "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "g"}, swab:sync([{nblines, last}], "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "g"}, swab:sync({nblines, last}, "a\r\nb\nc\rd\fe\x85f\x0bg"))
		   ,?assertEqual({ok, "123" }, swab:sync([{nblines, 1}], "123" ++ ?NL ++ "456" ++ ?NL ++ "789"))
		   ,?assertEqual({ok, "123" }, swab:sync({nblines, 1}, "123" ++ ?NL ++ "456" ++ ?NL ++ "789"))
		   ,?assertEqual({ok, "123" ++ ?NL ++ "456"}, swab:sync([{nblines, 2}], "123" ++ ?NL ++ "456" ++ ?NL ++ "789"))
		   ,?assertEqual({ok, "123" ++ ?NL ++ "456"}, swab:sync({nblines, 2}, "123" ++ ?NL ++ "456" ++ ?NL ++ "789"))
		   ,?assertEqual({ok, "789"}, swab:sync([{nblines, -1}], "123" ++ ?NL ++ "456" ++ ?NL ++ "789"))
		   ,?assertEqual({ok, "789"}, swab:sync({nblines, -1}, "123" ++ ?NL ++ "456" ++ ?NL ++ "789"))
		   ,?assertEqual({ok, "456" ++ ?NL ++ "789"}, swab:sync([{nblines, -2}], "123" ++ ?NL ++ "456" ++ ?NL ++ "789"))
		   ,?assertEqual({ok, "456" ++ ?NL ++ "789"}, swab:sync({nblines, -2}, "123" ++ ?NL ++ "456" ++ ?NL ++ "789"))
           % grab
           ,?assertEqual({ok,"abc"},swab:sync({grab, "^(...)"},"abcdefg"))
           ,?assertEqual({ok,"abcf"},swab:sync({grab, "^(...)..(.)"},"abcdefg"))
           %*** MATCH ***
           % equal
           ,?assertEqual({match, {equal, <<"abcdef">>}, <<"abcdef">>},swab:sync({equal, <<"abcdef">>},<<"abcdef">>))
           ,?assertEqual({match, {equal, "abcdef"}, "abcdef"},swab:sync({equal, "abcdef"},"abcdef"))
           % fread
           ,?assertEqual({match, {fread, "~f~f~f"},"1.9 35.5e3 15.0"},swab:sync({fread, "~f~f~f"},"1.9 35.5e3 15.0"))
           ,?assertEqual({match, {fread, "~10f~d"},"     5.67899"},swab:sync({fread, "~10f~d"},"     5.67899"))
           ,?assertEqual({match, {fread, ":~10s:~10c:"},":   alan   :   joe    :"},swab:sync({fread, ":~10s:~10c:"},":   alan   :   joe    :"))
           % regexp
           ,?assertEqual({match, {regexp, {"^[A-Z]",[]}},"ABCDEFG"},swab:sync([{cast, upper}, {regexp, "^[A-Z]"}, {cast, lower}], "abcdefg"))
           ,ok.

-endif.
