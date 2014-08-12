%%%-------------------------------------------------------------------
%%% File:      swab_tar.hrl
%%% @author    Eric Pailleau <swab@crownedgrouse.com>
%%% @copyright 2014 crownedgrouse.com
%%% @doc  
%%% 		Tar library
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
%%% Created : 2014-08-11
%%%-------------------------------------------------------------------

%%-------------------------------------------------------------------------
%%@doc Replace Uid and User
%%@end
%%-------------------------------------------------------------------------
tar_change_user(Data, {Uid, User}) when is_integer(Uid),
                                        is_list(User)   -> tar_change_user(Data, {Uid, User}, []).

tar_change_user([], {_, _}, Iolist)                                    -> list_to_binary(lists:flatten(Iolist));
tar_change_user(<<Rest/binary>>, {_, _}, Iolist) when size(Rest)=< 512 -> list_to_binary(lists:flatten(Iolist ++ [Rest]));

tar_change_user(<<Header:512/bytes,Rest/binary>>, 
                {Uid, User}, 
                Iolist) ->    {Skip, NewHeader} = tar_change_header_user(Header, {Uid, User}),
                              case Skip of
                                   0 -> tar_change_user(Rest, {Uid, User}, Iolist ++ [NewHeader])  ;
                                   _ -> <<File:Skip/bytes,Next/binary>> = Rest,
                                        tar_change_user(Next, {Uid, User}, Iolist ++ [NewHeader, File])
                              end.

%%-------------------------------------------------------------------------
%%@doc Replace Gid and Group 
%%@end
%%-------------------------------------------------------------------------
tar_change_group(Data, {Gid, Group}) when is_integer(Gid),
                                          is_list(Group)   ->  tar_change_group(Data, {Gid, Group}, []).

tar_change_group([], {_, _}, Iolist)                                    -> list_to_binary(lists:flatten(Iolist));
tar_change_group(<<Rest/binary>>, {_, _}, Iolist) when size(Rest)=< 512 -> list_to_binary(lists:flatten(Iolist ++ [Rest]));

tar_change_group(<<Header:512/bytes,Rest/binary>>, 
                {Gid, Group}, 
                Iolist) ->   {Skip, NewHeader} = tar_change_header_group(Header, {Gid, Group}),
                             case Skip of
                                 0 -> tar_change_group(Rest, {Gid, Group}, Iolist ++ [NewHeader])  ;
                                 _ -> <<File:Skip/bytes,Next/binary>> = Rest,
                                      tar_change_group(Next, {Gid, Group}, Iolist ++ [NewHeader, File])
                             end.

%%-------------------------------------------------------------------------
%%@doc Replace Uid/Gid and User/Group to 0/root
%%@end
%%-------------------------------------------------------------------------
tar_fakeroot(Data) ->  tar_fakeroot(Data, []).

tar_fakeroot([], Iolist)                                    -> list_to_binary(lists:flatten(Iolist));
tar_fakeroot(<<Rest/binary>>, Iolist) when size(Rest)=< 512 -> list_to_binary(lists:flatten(Iolist ++ [Rest]));

tar_fakeroot(<<Header:512/bytes,Rest/binary>>, Iolist) ->  
                                                            {Skip, NewHeader1} = tar_change_header_user(Header, {0,"root"}),
                                                            {Skip, NewHeader} = tar_change_header_group(NewHeader1, {0,"root"}),
                                                            case Skip of
                                                                   0 -> tar_fakeroot(Rest, Iolist ++ [NewHeader])  ;
                                                                   _ -> <<File:Skip/bytes,Next/binary>> = Rest,
                                                                        tar_fakeroot(Next, Iolist ++ [NewHeader, File])
                                                            end.

%%-------------------------------------------------------------------------
%%@doc 
%%     Return the length to skip in the file (padded Size), and the new header
%%     A match against "ustar" string is done to be sure a valid header is being treated,
%%     or otherwise remaining padding zeroes at end of file.
%%@end
%%-------------------------------------------------------------------------

tar_change_header_user(<<Start:108/bytes,
                        _U:8/bytes,
                        G:8/bytes,
                        Size:11/bytes,
                        Middle:122/bytes,
                        "ustar",_:3/bytes,
                        _User:32/bytes,
                        Group:32/bytes,
                        End:183/bytes>>, 
                       {Uid, UserName})  ->  SkipSize = list_to_integer(binary_to_list(Size),8),
                                             Skip = ((SkipSize + 512 - 1) div 512) * 512,
                                             NewUser = list_to_binary([UserName,binary:copy(<<0>>, 32 - length(UserName))]),
                                             32  = byte_size(NewUser),  %Assertion.
                                             H = list_to_binary(lists:flatten([Start,to_octal(Uid, 8),G,
                                                                               Size,Middle,"ustar",<<0>>,"00",NewUser,Group,End])),
                                             512 = byte_size(H),  %Assertion.
                                             <<Before:148/binary,_Old:8/binary,After/binary>> = H,
                                             New = <<Before:148/binary,"        ",After/binary>>,
                                             ChksumString = to_octal(checksum(New), 6, [0,$\s]),
                                             {Skip,list_to_binary([Before,ChksumString,After])};

tar_change_header_user(X,_) -> tar_change_header(X).

%%-------------------------------------------------------------------------
%%@doc 
%%     Return the length to skip in the file (padded Size), and the new header
%%     A match against "ustar" string is done to be sure a valid header is being treated,
%%     or otherwise remaining padding zeroes at end of file.
%%@end
%%-------------------------------------------------------------------------
tar_change_header_group(<<Start:108/bytes,
                        U:8/bytes,
                        _G:8/bytes,
                        Size:11/bytes,
                        Middle:122/bytes,
                        "ustar",_:3/bytes,
                        User:32/bytes,
                        _Group:32/bytes,
                        End:183/bytes>>, 
                       {Gid, GroupName})  -> SkipSize = list_to_integer(binary_to_list(Size),8),
                                             Skip = ((SkipSize + 512 - 1) div 512) * 512,
                                             NewGroup = list_to_binary([GroupName,binary:copy(<<0>>, 32 - length(GroupName))]),
                                             32  = byte_size(NewGroup),  %Assertion.
                                             H = list_to_binary(lists:flatten([Start,U,to_octal(Gid, 8),
                                                                               Size,Middle,"ustar",<<0>>,"00",User,NewGroup,End])),
                                             512 = byte_size(H),  %Assertion.
                                             <<Before:148/binary,_Old:8/binary,After/binary>> = H,
                                             New = <<Before:148/binary,"        ",After/binary>>,
                                             ChksumString = to_octal(checksum(New), 6, [0,$\s]),
                                             {Skip,list_to_binary([Before,ChksumString,After])};

tar_change_header_group(X,_) -> tar_change_header(X).

%%-------------------------------------------------------------------------
%%@doc Remaining padding zeroes at end of file.
%%@end
%%-------------------------------------------------------------------------
tar_change_header(X) -> case binary:copy(<<0>>, size(X)) of
                                X -> {0, X} ;
                                _ -> throw(invalid) % Neither valid header, nor zeroes padding.
                        end.

%%-------------------------------------------------------------------------
%%@doc Checksum of Tar Header
%%@end
%%-------------------------------------------------------------------------
checksum(H) -> checksum(H, 0).

checksum(<<A,B,C,D,E,F,G,H,T/binary>>, Sum) ->
    checksum(T, Sum+A+B+C+D+E+F+G+H);
checksum(<<A,T/binary>>, Sum) ->
    checksum(T, Sum+A);
checksum(<<>>, Sum) -> Sum.

%%-------------------------------------------------------------------------
%%@doc Cast to Octal
%%@end
%%-------------------------------------------------------------------------
to_octal(Int, Count) when Count > 1 ->
    to_octal(Int, Count-1, [0]).

to_octal(_, 0, Result) -> Result;
to_octal(Int, Count, Result) ->
    to_octal(Int div 8, Count-1, [Int rem 8 + $0|Result]).



