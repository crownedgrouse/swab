%%%-------------------------------------------------------------------
%%% File:      swab.erl
%%% @author    Eric Pailleau <swab@crownedgrouse.com>
%%% @copyright 2014 crownedgrouse.com
%%% @doc
%%% General purpose buffer handling
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

-module(swab).
-author("Eric Pailleau <swab@crownedgrouse.com>").

-export([sync/2, async/2, sync/3, async/3]).

-include_lib("public_key/include/public_key.hrl").

% Pre-compiled regexps for better performances.
% (?>\r\n|\n|\x0b|\f|\r|\x85)
-define(REG_LINES, "(?>\r\n|\n|\x0b|\f|\r|\x85)").


-include("swab_lib.hrl").

-define(SWAB_DBG(Tuple,Buf), case get(swab_dbg) of
                                'on'        -> io:fwrite("~s : ~p => ~p~n",[pid_to_list(self()),Tuple, Buf]),
                                               case get(swab_dbgqueue) of
                                                    on -> queue_init(),
                                                          io:fwrite("           ~p~n",[queue:to_list(get(queue))]);
                                                    _  -> ok
                                               end;
                                'hexdump'   -> io:fwrite("~s : ~p => ~n"  ,[pid_to_list(self()),Tuple]), swab_hexdump:hexdump(Buf), ok ;
                                'asn1_pp'   -> io:fwrite("~s : ~p => ~n"  ,[pid_to_list(self()),Tuple]), _ = swab_asn1:asn1_pp(Buf), ok ;
                                _ -> ok
                             end  ).

%%-------------------------------------------------------------------------
%% @doc Apply rules and return synchronously.
%%      <br/>Return values can be : <br/><tt>{ok, LastBuffer}</tt><br/>
%%      <tt>{error, OffendingDirective, Message}</tt><br/>
%%      and if match directive is used and matching :<br/>
%%      <tt>{match, MatchingDirective, MatchingBuffer}</tt><br/>
%%      MatchingDirective could have been rewritten with default values (See Overview).
%% @end
%%-------------------------------------------------------------------------
-spec sync(list()|tuple(), iolist()|binary()) -> tuple().

sync(Rules, Buffer) when is_tuple(Rules);
                         is_list(Rules) ->  try analyze(Buffer, Rules) of
								                Term -> {ok, Term}
      					    		            catch throw:Term -> Term
					    		            end.

%%-------------------------------------------------------------------------
%% @doc Apply rules and return synchronously, but send result to a Pid.
%%      Caller Pid get atom <tt>ok</tt>.<br/>
%%      Target Pid receives message <tt>{swab, CallerPid, SwabSyncResult}</tt>.
%% @end
%%-------------------------------------------------------------------------
-spec sync(list()|tuple(), iolist(), pid()) -> ok.

sync(Rules, Buffer, Pid) when is_pid(Pid) -> Return = analyze(Buffer, Rules),
					     Pid ! {swab, self(), Return},
					     ok.

%%-------------------------------------------------------------------------
%% @doc Apply rules asynchronously, and send result to caller Pid.
%%      Caller Pid get tuple <tt>{ok, SwabSpawnPid}</tt>.<br/>
%%      Caller Pid receives message <tt>{swab, SwabSpawnPid, SwabSyncResult}</tt>.<br/>
%%      The caller might store the returned value <tt>SwabSpawnPid</tt> as reference
%%      if several messages are expected to be received.
%% @end
%%-------------------------------------------------------------------------
-spec async(list()|tuple(), iolist()) -> {ok, pid()}.

async(Rules, Buffer) -> {ok, spawn(swab, sync, [Rules, Buffer, self()])}.

%%-------------------------------------------------------------------------
%% @doc Apply rules asynchronously, but send result to a Pid.
%%      Caller Pid get tuple <tt>{ok, SwabSpawnPid}</tt>.<br/>
%%      Target Pid receives message <tt>{swab, SwabSpawnPid, SwabSyncResult}</tt>.<br/>
%%      The caller might store the returned value <tt>SwabSpawnPid</tt> as reference
%%      if a correlation must be done with the target.
%% @end
%%-------------------------------------------------------------------------
-spec async(list()|tuple(), iolist(), pid()) -> {ok, pid()}.

async(Rules, Buffer, Pid) when is_pid(Pid) -> {ok, spawn(swab, sync, [Rules, Buffer, Pid])}.

%%*************************************************************************
%%***                        Debugging                                  ***
%%*************************************************************************
-spec analyze(iolist(), list()|tuple()) -> iolist()| tuple().
%%-------------------------------------------------------------------------
%%@doc Debug. Display in shell next rules and buffers state until {debug, off}.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {debug, queue})-> put(swab_dbgqueue, on),
                                ?SWAB_DBG({debug, queue}, Buff),
                                Buff ;
analyze(Buff, {debug, off})  -> put(swab_dbg, off),
                                put(swab_dbgqueue, off),
                                ?SWAB_DBG({debug, off}, Buff),
                                Buff ;
analyze(Buff, {debug, Val})   -> put(swab_dbg,Val),
                                 ?SWAB_DBG({debug, Val}, Buff),
                                 Buff ;

%%*************************************************************************
%%***                         Buffers                                   ***
%%*************************************************************************

%%-------------------------------------------------------------------------
%%@doc Inserts current buffer at the rear (tail) of queue.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {buffer, in})      -> queue_init(),
				                    Q=get(queue),
                                    put(queue,queue:in(optimize(Buff), Q)),
                                    ?SWAB_DBG({buffer, in},Buff),
                                    Buff ;

%%-------------------------------------------------------------------------
%%@doc Inserts current buffer at the front (head) of queue.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {buffer, ni})      -> analyze(Buff, {buffer, in_r}) ;
analyze(Buff, {buffer, in_r})    -> queue_init(),
				                    Q=get(queue),
                                    put(queue,queue:in_r(optimize(Buff), Q)),
                                    ?SWAB_DBG({buffer, in_r}, Buff),
                                    Buff ;

%%-------------------------------------------------------------------------
%%@doc Get and removes the saved buffer at the front (head) of queue.
%%     The extracted buffer becomes then the current buffer, while current
%%     is saved in REAR of queue if non empty.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {buffer, out})     -> queue_init(),Q=get(queue),
                                    NewBuff = case queue:out(Q) of
                                       		{{value, NB}, _} -> NB;
                                       		{empty, _} -> ""
                                    	      end,
                                    case Buff of
                                       [] -> ok;
                                       _  -> put(queue,queue:in(optimize(Buff), Q))
                                    end,
                                    ?SWAB_DBG({buffer, out},NewBuff),
                                    NewBuff;

%%-------------------------------------------------------------------------
%%@doc Get and removes the saved buffer at the rear (tail) of the queue.
%%     The extracted buffer becomes then the current buffer, while current
%%     is saved in FRONT of queue if non empty.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {buffer, tuo})     -> analyze(Buff, {buffer, out_r}) ;
analyze(Buff, {buffer, out_r})   -> queue_init(),
				                    Q=get(queue),
                                    NewBuff = case queue:out_r(Q) of
                                       		{{value, NB}, _} -> NB;
                                       		{empty, _} -> ""
                                    	      end,
                                    case Buff of
                                       [] -> ok;
                                       _  -> put(queue,queue:in_r(optimize(Buff), Q))
                                    end,
                                    ?SWAB_DBG({buffer, out_r},NewBuff),
                                    NewBuff;

%%-------------------------------------------------------------------------
%%@doc Delete the current buffer.
%%     Next buffer will be the first in queue (head), if any.
%%@end
%%-------------------------------------------------------------------------
analyze(_Buff, {buffer, del})    -> queue_init(),
				                    Q=get(queue),
                                    NewBuff = case queue:out(Q) of
                                       		{{value, NB}, Q2} -> put(queue,Q2), NB;
                                       		{empty, Q1} -> put(queue,Q1), ""
                                    	      end,
                                    ?SWAB_DBG({buffer, del},NewBuff),
                                    NewBuff;

%%-------------------------------------------------------------------------
%%@doc Delete the current buffer.
%%     Next buffer will be the last in queue (tail), if any.
%%@end
%%-------------------------------------------------------------------------
analyze(_Buff, {buffer, led})    -> analyze(_Buff, {buffer, del_r}) ;
analyze(_Buff, {buffer, del_r})  -> queue_init(),
				                    Q=get(queue),
                                    NewBuff = case queue:out_r(Q) of
                                       		{{value, NB}, Q2} -> put(queue,Q2), NB;
                                       		{empty, Q1} -> put(queue,Q1), ""
                                    	      end,
                                    ?SWAB_DBG({buffer, del_r},NewBuff),
                                    NewBuff;

%%-------------------------------------------------------------------------
%%@doc Merge all buffers in only one buffer in queue.
%%     Current buffer is left unchanged !
%%     Local newlines are separating merged buffers.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {buffer, merge})   -> queue_init(),
				                    Q=get(queue),
                                    B = string:join(queue:to_list(Q),io_lib:nl()),
                                    NewQ = queue:new(),
                                    put(queue,queue:in(optimize(B),NewQ)),
                                    ?SWAB_DBG({buffer, merge}, Buff),
                                    Buff;

%%-------------------------------------------------------------------------
%%@doc Merge all buffers in only one buffer in queue, but reverse order.
%%     Current buffer is left unchanged !
%%     Local newlines are separating merged buffers.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {buffer, egrem})   -> analyze(Buff, {buffer, merge_r});
analyze(Buff, {buffer, merge_r}) -> queue_init(),
				                    Q=get(queue),
                                    B = string:join(queue:to_list(queue:reverse(Q)),io_lib:nl()),
                                    NewQ = queue:new(),
                                    put(queue,queue:in(optimize(B),NewQ)),
                                    ?SWAB_DBG({buffer, merge_r}, Buff),
                                    Buff;

%%-------------------------------------------------------------------------
%%@doc Concatenate all buffers in only one buffer in queue.
%%     Current buffer is left unchanged !
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {buffer, concat})  -> queue_init(),
				                    Q=get(queue),
                                    B = string:join(queue:to_list(Q),""),
                                    NewQ = queue:new(),
                                    put(queue,queue:in(optimize(B),NewQ)),
                                    ?SWAB_DBG({buffer, merge}, Buff),
                                    Buff;

%%-------------------------------------------------------------------------
%%@doc Concatenate all buffers in only one buffer in queue, but reverse order.
%%     Current buffer is left unchanged !
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {buffer, tacnoc})  -> analyze(Buff, {buffer, concat_r});
analyze(Buff, {buffer, concat_r})-> queue_init(),
				                    Q=get(queue),
                                    B = string:join(queue:to_list(queue:reverse(Q)),""),
                                    NewQ = queue:new(),
                                    put(queue,queue:in(optimize(B),NewQ)),
                                    ?SWAB_DBG({buffer, merge_r}, Buff),
                                    Buff;

%%-------------------------------------------------------------------------
%%@doc Push data as new current buffer in your directive chain
%%     Current buffer is overwritten.
%%@end
%%-------------------------------------------------------------------------
analyze(_, {push, Data}) when is_binary(Data);
                                 is_list(Data) -> Data ;

%%-------------------------------------------------------------------------
%%@doc Push data directly in front (head) of buffer queue.
%%     Current buffer is left unchanged.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {store, Data}) when is_binary(Data);
                                  is_list(Data) -> _ = analyze(Data, {buffer, in_r}),
                                                   Buff ;

%%-------------------------------------------------------------------------
%%@doc Push data directly in rear (tail) of buffer queue.
%%     Current buffer is left unchanged.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {erots, Data})        -> analyze(Buff, {store_r, Data});
analyze(Buff, {store_r, Data}) when is_binary(Data);
                                    is_list(Data) -> _ = analyze(Data, {buffer, in}),
                                                     Buff ;

%%**************************************************************************
%%***                             Refactoring                            ***
%%**************************************************************************

%%-------------------------------------------------------------------------
%%@doc Cast the current buffer content.
%%     Lowercase or uppercase.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {cast, Type }) -> NewBuff = case Type of
                                    		lower -> string:to_lower(Buff) ;
                                    		upper -> string:to_upper(Buff) ;
                                    		_        -> Buff, throw({badarg,"Invalid type."})
                                	      end,
                                ?SWAB_DBG({cast, Type},NewBuff),
                                NewBuff ;

%%-------------------------------------------------------------------------
%%@doc Returns the word in position Integer of String in current buffer.
%%     Words are separated by blanks.
%%     (Usefull for getting version from program output).
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {sub_word, Integer} ) -> NewBuff = case is_list(Buff) of
                                             		true ->
                                                      		case is_integer(Integer) of
                                                            		false -> Buff, throw({badarg,"Invalid integer."}) ;
                                                            		true  -> string:sub_word(Buff, Integer)
                                                      		end;
                                             		false -> Buff, throw({badarg, "Buffer is not a valid string."})
                                       		      end,
                                       ?SWAB_DBG({sub_word, Integer}, NewBuff),
                                       NewBuff;

%%-------------------------------------------------------------------------
%%@doc Trim blanks left/right/both on buffer
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {trim, Type}) when is_atom(Type) -> analyze(Buff, {trim, {Type, $\040 }}) ;

%%-------------------------------------------------------------------------
%%@doc Trim character left/right/both on buffer
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {trim, {Type, Char}}) when is_integer(Char),
                                         (Type==both);
                                         (Type==left);
                                         (Type==right) -> string:strip(Buff, Type, Char) ;

%%-------------------------------------------------------------------------
%%@doc Feed blanks on buffer lines up to integer length
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {feed, Len}) when is_integer(Len) -> analyze(Buff, {feed, {Len, $\040 }}) ;

%%-------------------------------------------------------------------------
%%@doc Feed character on buffer lines up to integer length
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {feed, {Len, Char}}) when is_integer(Len),
                                        is_integer(Char) -> L = re:split(Buff,?REG_LINES,[{return,list}]),
                                                            R = case (Len < 0) of
                                                                    true  -> lists:flatmap(fun(X) -> [string:right(X, (- Len), Char)] end, L) ;
                                                                    false -> lists:flatmap(fun(X) -> [string:left(X, Len, Char)] end, L)
                                                                end,
                                                            string:join(R, io_lib:nl());

%%-------------------------------------------------------------------------
%%@doc Fold buffer to integer length
%%     any already existing carriages returns are kept,
%%     but new ones are local new lines.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {fold, Len}) when is_integer(Len),
                                is_binary(Buff)     ->  fold(Len, Buff, []) ;

analyze(Buff, {fold, Len}) when is_integer(Len),
                                is_list(Buff)       ->  fold(Len, list_to_binary(Buff), []) ;

%%-------------------------------------------------------------------------
%%@doc Convertion of current buffer.
%%     a) der | pem - Only certificate DER <-> PEM format
%%     b) base64 | mime - Same as 'decode' but for base64 encoding and mime RFC4648.
%%        'mime' strips away illegal characters, while 'base64' only strips
%%        away whitespace characters.
%%     c) uncompress | unzip | gunzip | compress | zip | gzip
%%        Same as a) but for main compression algorithms.
%%        Result is expected to be a string if a match is needed...
%%        uncompress : Uncompress a binary (with zlib headers and checksum).
%%        unzip : Uncompress a binary (without zlib headers and checksum).
%%        gunzip : Uncompress a binary (with gz headers and checksum).
%%     d) nonl - Removes any new lines separators whatever the OS type
%%        (\r, \r\n, \n but also \f, \x85 and \x0b).
%%     e) local_nl - Convert any new lines to local new lines.
%%     f) swab - exchange adjacent even and odd bytes.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {convert, Type}) -> NewBuff = case Type of
                                            der         -> [{_, Der, _}] = public_key:pem_decode(Buff), Der ;
                                            pem         -> binary_to_list(public_key:pem_encode([{'Certificate',Buff, not_encrypted}])) ;
                                       		base64 		-> (catch base64:decode_to_string(Buff));
                                       		mime 		-> (catch base64:mime_decode_to_string(Buff));
                                       		uncompress 	-> (catch zlib:uncompress(Buff));
                                       		unzip 		-> (catch zlib:unzip(Buff)) ;
                                       		gunzip 		-> (catch zlib:gunzip(Buff)) ;
                                       		compress 	-> (catch zlib:compress(Buff));
                                       		zip 		-> (catch zlib:zip(Buff)) ;
                                       		gzip 		-> (catch zlib:gzip(Buff)) ;
                                       		nonl 		-> nonl(Buff, []);
						                    local_nl    -> analyze(Buff, {jump, 0}) ;
                                            swab        -> swab(Buff);
                                       		_ 		-> throw(badarg), Buff
                                  	    end,
                                  case NewBuff of
                                    {'EXIT', _} -> throw(badarg) ;
                                    _ -> ok
                                  end,
                                  ?SWAB_DBG({convert, Type}, NewBuff),
                                  NewBuff;

%%-------------------------------------------------------------------------
%%@doc Decode current buffer to Unicode.
%%     [latin1 | unicode | utf8 | utf16 | utf32 | {utf16, big} | {utf16, little} | {utf32, big} | {utf32, little} | ebcdic]
%%     Converts the current buffer from the given format to pure Unicode.
%%     The purpose of the function is mainly to be able to convert
%%     combinations of unicode characters into a pure unicode string.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {decode, Type}) -> NewBuff = case Type of
                                       		latin1 		-> (catch to_unicode(Buff,Type));
                                       		unicode 	-> (catch to_unicode(Buff,Type));
                                       		utf8 		-> (catch to_unicode(Buff,Type));
                                       		{utf16, big}	-> (catch to_unicode(Buff,Type));
                                       		{utf16, little}	-> (catch to_unicode(Buff,Type));
                                       		utf16 		-> (catch to_unicode(Buff,Type));
                                       		{utf32, big}	-> (catch to_unicode(Buff,Type));
                                       		{utf32, little}	-> (catch to_unicode(Buff,Type));
                                       		utf32 		-> (catch to_unicode(Buff,Type));
                                       		ebcdic 		-> swab_ebcdic:e2a(Buff);
                                       		_ 		-> throw(badarg), Buff
                                  	    end,
                                  case NewBuff of
                                    {'EXIT', _} -> throw(badarg) ;
                                    _ -> ok
                                  end,
                                  ?SWAB_DBG({decode, Type}, NewBuff),
                                  NewBuff;

%%-------------------------------------------------------------------------
%%@doc Encode current buffer from Unicode to something.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {encode, Type}) -> NewBuff = case Type of
                                       		latin1 		-> (catch from_unicode(Buff,Type));
                                       		unicode 	-> (catch from_unicode(Buff,Type));
                                       		utf8 		-> (catch from_unicode(Buff,Type));
                                       		{utf16, big}	-> (catch from_unicode(Buff,Type));
                                       		{utf16, little}	-> (catch from_unicode(Buff,Type));
                                       		utf16 		-> (catch from_unicode(Buff,Type));
                                       		{utf32, big}	-> (catch from_unicode(Buff,Type));
                                       		{utf32, little}	-> (catch from_unicode(Buff,Type));
                                       		utf32 		-> (catch from_unicode(Buff,Type));
						                    ebcdic		-> swab_ebcdic:a2e(Buff);
                                       		_ 		-> throw(badarg), Buff
                                  	    end,
                                  case NewBuff of
                                    {'EXIT', _} -> throw(badarg) ;
                                    _ -> ok
                                  end,
                                  ?SWAB_DBG({encode, Type}, NewBuff),
                                  NewBuff;

%%-------------------------------------------------------------------------
%%@doc Line extracting on current buffer (jump)
%%       Jump to the given line number and bring only lines after.
%%       Be carefull, if line does not exist, it will empty the buffer !
%%       Negative value will bring the lines from the end.
%%       zero will bring all the lines.
%%     Warning : Any new lines will be normalized to local new lines !
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {jump, Mode}) -> L = re:split(Buff,"(?>\r\n|\n|\x0b|\f|\r|\x85)",[{return,list}]),
                               NewBuff = case Mode of
                                    		Int when (Int == 0)         -> {T,_} = lists:split(length(L), L),
                                                                  	       string:join(T, io_lib:nl());
                                    		Int when (Int < 0)          -> {_,T} = lists:split(length(L) + Int, L),
                                                                  	       string:join(T, io_lib:nl());
                                    		Int when is_integer(Mode)   -> {_,T} = lists:split(Int, L),
                                                                  	       string:join(T, io_lib:nl());
                                    		_  -> throw(badarg), Buff
                               		  end,
                               ?SWAB_DBG({jump, Mode}, NewBuff),
                               NewBuff;

%%-------------------------------------------------------------------------
%%@doc Line extracting on current buffer (nblines)
%%     Get a number of lines of current buffer,
%%     forward in buffer if > 0, from end in buffer if < 0.
%%     1 will pick-up the first line only.
%%     Note : 0 will clear the buffer !
%%     Can be used in conjunction with 'jump' before in order to discard
%%     unwanted lines.
%%     Lines found becomes the next current buffer.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {nblines, first}) -> analyze(Buff, {nblines, 1}) ;
analyze(Buff, {nblines, last})  -> analyze(Buff, {nblines, -1}) ;
analyze(Buff, {nblines, Int}) ->
                                 NewBuff = case is_integer(Int) of
                                    		false -> throw(badarg), Buff ;
						                    true when (Int == 0)-> "";
                                    		true when (Int > 0) ->  L = re:split(Buff,?REG_LINES,[{return,list}]),
                                             		 	            {L2, _} = lists:split(Int, L),
                                             		 	            string:join(L2,io_lib:nl());
                                    		true when (Int < 0) ->  L = re:split(Buff,?REG_LINES,[{return,list}]),
                                             		 	            {L2, _} = lists:split((- Int), lists:reverse(L)),
                                             		 	            string:join(lists:reverse(L2),io_lib:nl())
                               		   end,
                               ?SWAB_DBG({nblines, Int}, NewBuff),
                               NewBuff;

%%-------------------------------------------------------------------------
%%@doc  Sorting current buffer.
%%	normal  : normal alphabetic sort.
%%                When wanting to sort shuffled buffers merge.
%%	reverse : from last line to first line.
%%	numeral : on the numeral order.
%%                Usefull when entries with starting dates are shuffled.
%%                Number is created from all numeral characters until first
%%                alphabetical characters, other separators will be discarded.
%%                This allow valid sorting of ISO dates in lines like
%%                "2010-04-18 12:02:23 Error in PID 3215." evaluated to number
%%                20100418120223.
%%                (Note that the PID number is not part of the evaluated number
%%                as far some alphabetic characters are before it).
%%                Warning : slower than other sorting methods.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {sort, Mode}) -> L = re:split(Buff,?REG_LINES,[{return,list}, trim]),
                               NewBuff = case Mode of
						                    normal  -> string:join(lists:sort(L),io_lib:nl()) ;
                                    		reverse -> string:join(lists:reverse(lists:sort(L)),io_lib:nl()) ;
                                    		inverse -> string:join(lists:reverse(L),io_lib:nl())
                               		 end,
                               ?SWAB_DBG({sort, Mode}, NewBuff),
                               NewBuff;

%%-------------------------------------------------------------------------
%%@doc  Grab data with catching regular expression.
%%      If no catching expression is set, same as match directive.
%%
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {grab, {MP, Opt}})
	 when is_list(Opt) -> 	try re:run(Buff, MP, Opt) of
					{match, [Newbuff]}-> Newbuff ;
					{match, [H | T]}  -> lists:flatten(H ++ T) ;
					match             -> Buff ;
					nomatch           -> "" ;
					{error, ErrType}  -> throw({error, {grab, {MP, Opt}}, ErrType}), Buff
				catch
			    		throw:Term   -> throw(Term);
    					error:Reason -> throw({error, {grab, {MP, Opt}}, Reason})
				end;

analyze(Buff, {grab, MP}) -> analyze(Buff, {grab, {MP, [{capture, all_but_first, 'list'}]}}) ;


%%*************************************************************************
%%***                             Matching                              ***
%%*************************************************************************
%%-------------------------------------------------------------------------
%%@doc  Simple string comparison
%%      If expression is matching, a tuple {match, Directive, Buffer}
%%      is returned  and all next rules are ignored.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {equal, Comp}) -> case (Comp == Buff) of
                                        true  -> throw({match, {equal, Comp}, Buff}), Buff  ;
                                        false -> Buff
                                  end;

%%-------------------------------------------------------------------------
%%@doc  Match in accordance with the formating control sequences of String
%%      If expression is matching, a tuple {match, Directive, Buffer}
%%      is returned  and all next rules are ignored.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {fread, Control}) -> case io_lib:fread(Control, Buff) of
                                         {ok, _, _} -> throw({match, {fread, Control}, Buff}), Buff  ;
                                         _ -> Buff
                                   end;
%%-------------------------------------------------------------------------
%%@doc  Match data with regular expression
%%      If expression is matching, a tuple {match, Directive, Buffer}
%%      is returned  and all next rules are ignored.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {regexp, {MP, Opt}})
	 when is_list(Opt) -> 	try re:run(Buff, MP, Opt) of
					{match, [_]}       -> throw({match, {regexp,{MP, Opt}}, Buff}), Buff ;
					{match, [_H | _T]} -> throw({match, {regexp,{MP, Opt}}, Buff}), Buff ;
					match              -> throw({match, {regexp,{MP, Opt}}, Buff}), Buff ;
					nomatch            -> Buff ;
					{error, ErrType}   -> throw({error, {regexp, {MP, Opt}}, ErrType}), Buff
				catch
			    		throw:Term   -> throw(Term);
    					error:Reason -> throw({error, {regexp, {MP, Opt}}, Reason})
				end;

analyze(Buff, {regexp, MP}) -> analyze(Buff, {regexp, {MP, []}}) ;

%%*************************************************************************
%%***                             Misc                                  ***
%%*************************************************************************
analyze(Buff, {mfa, {M, F, A}}) when is_atom(M),
                                     is_atom(F),
                                     is_list(A) -> try apply(M, F, A ++ [Buff]) of
								                            NewBuff when is_list(NewBuff);
                                                                         is_binary(NewBuff) -> NewBuff ;
                                                            _  -> throw({error, {mfa, {M, F, A}}, "Invalid returned value"}), Buff
      					    		               catch throw:match  -> throw({match, {mfa, {M, F, A}}, Buff});
    					                                 error:undef  -> throw({error, {mfa, {M, F, A}}, "Undefined module or function"});
    					                                 error:Ra when is_atom(Ra)-> throw({error, {mfa, {M, F, A}}, atom_to_list(Ra)});
    					                                 error:R  when is_list(R)-> throw({error, {mfa, {M, F, A}}, R})
					    		                   end;

analyze(Buff, {tar, fakeroot}) -> try
                                       swab_tar:fakeroot(Buff)
                                  catch
                                       throw:invalid -> throw({error, {tar, fakeroot}, "Invalid Tar file"});
                                       error:Reason  -> throw({error, {tar, fakeroot}, Reason})
                                  end;

analyze(Buff, {tar, {Uid, User}})
            when is_integer(Uid),
                 is_list(User) -> try
                                       swab_tar:change_user(Buff, {Uid, User})
                                     catch
                                       throw:invalid -> throw({error, {tar, {Uid, User}}, "Invalid Tar file"});
                                       error:Reason  -> throw({error, {tar, {Uid, User}}, Reason})
                                     end;

analyze(Buff, {tar, {Group, Gid}})
            when is_integer(Gid),
                 is_list(Group) -> try
                                       swab_tar:change_group(Buff, {Gid, Group})
                                     catch
                                       throw:invalid -> throw({error, {tar, {Gid, Group}}, "Invalid Tar file"});
                                       error:Reason  -> throw({error, {tar, {Gid, Group}}, Reason})
                                     end;

%%*************************************************************************
%%***                             Analyze                               ***
%%*************************************************************************

%%-------------------------------------------------------------------------
%%@doc  Main function.
%%      Rules are applied, left to right.
%%      Before result returning :
%%      - Debug is set off.
%%      - Queue is removed and replaced by empty one.
%%@end
%%-------------------------------------------------------------------------
analyze(Buff, {Tag, Val}) when is_atom(Tag) -> throw({error, {Tag, Val}, "Invalid argument"}), Buff ;
analyze(Buff, Rules) when is_list(Rules) -> Final = lists:foldl(fun(R, B) -> analyze(B,R) end, Buff, Rules),
					                        put(swab_dbg, off),
					                        put(queue, queue:new()),
                                            Final;

%%-------------------------------------------------------------------------
%%@doc  Fallback.
%%@end
%%-------------------------------------------------------------------------
analyze(_, Arg) -> {error, Arg, "Invalid arguments"}.


