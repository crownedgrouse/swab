%%*************************************************************************
%%***                              WARNING                              ***
%%*** § 3.3 of EPL impose to "include a prominent statement that the    ***
%%*** Modification is derived, directly or indirectly, from Original    ***
%%*** Code provided by the Initial Developer and including the name of  ***
%%*** the Initial Developer"                                            ***                            
%%*************************************************************************
%%***                             STATEMENT                             ***
%%*** Some pieces of below code was copied/modified from ASN1 library   ***
%%*** which is subject to the Erlang Public License and its initial     ***
%%*** developper was Ericsson AB .                                      ***
%%*************************************************************************
%%    EPL : http://www.erlang.org/EPLICENSE

%%-------------------------------------------------------------------------
%%@doc ASN1 Parser.
%% Decode asn1 coded binary into parse tree
%% Handles indefinite length if re-assembly has already been
%% done - should be relatively easy to allow for segmented though
%% as we keep a count of unrequited indefinite length
%% constructor tags.
%%@end
%%-------------------------------------------------------------------------
asn1_parse(Bin) ->
    asn1_parse(Bin, 0).
  
asn1_parse(<<>>, 0) ->
    [];
asn1_parse(Bin, N0) ->
    {Class, Form, Tag, Rest, N} = get_tag(Bin, N0),
    case tag_type(Class, Form, Tag) of
         indefinite_end -> asn1_parse(Rest, N);
         Constructor when Constructor == set;
			Constructor == seq;
			Constructor == constructor ->
                        case get_length(Rest) of
                              {indefinite, Rest1}  -> [{{Constructor, indef, Class, Tag}, asn1_parse(Rest1, N+1)}];
                              {Len, Rest1}         ->  {Data, Rest2} = get_content(Len, Rest1),
                                                      [{{Constructor, Class, Tag}, asn1_parse(Data, 0)}| asn1_parse(Rest2, N)]
                        end;
         tag ->	    {Len, Rest1} = get_length(Rest),				   
                      {Data, Rest2} = get_content(Len, Rest1),
                      [{{tag, fmt_class(Class), Tag}, Data}|asn1_parse(Rest2, N)]
    end.
	    
%%-------------------------------------------------------------------------
%%@doc Get tag data.
%%     0:1, 0:15 gets around old compiler bug, probably fixed now.
%%@end
%%-------------------------------------------------------------------------
get_tag(<<0:1, 0:15, _/binary>>, 0) ->
    exit(unexpected_end_of_indefinite_length);
get_tag(<<0:1, 0:15, Rest/binary>>, N) ->
    {indefinite_end, 0, 0, Rest, N-1};
get_tag(<<Class:2, Form:1, Tag:5, Rest/binary>>, N) ->
    {Tag1, Rest1} = get_tag1(Tag, Rest),
    {Class, Form, Tag1, Rest1, N}.

%%-------------------------------------------------------------------------
%%@doc Handle extension parts of the tag field
%%@end
%%-------------------------------------------------------------------------
get_tag1(31, <<0:1, Tag:7, Rest/binary>>) ->
    {Tag, Rest};
get_tag1(31, <<1:1, Msb:7, _:1, Lsb:7, Rest/binary>>) ->
    {Msb*128+Lsb, Rest};
get_tag1(Tag, Rest) ->
    {Tag, Rest}.

%%-------------------------------------------------------------------------
%%@doc Get length.
%%     Do short and long definite length forms as well indefinite length.
%%@end
%%-------------------------------------------------------------------------

get_length(<<0:1, Len:7, Rest/binary>>) ->
    {Len, Rest};
get_length(<<1:1, 0:7, Rest/binary>>) ->
    {indefinite, Rest};
get_length(<<1:1, Len_len:7, Rest/binary>>) ->
    <<Len:Len_len/unit:8, Rest1/binary>> = Rest,
    {Len, Rest1}.

%%-------------------------------------------------------------------------
%%@doc Get actual content of field.
%%@end
%%-------------------------------------------------------------------------
get_content(Len, Rest) ->
    <<Data:Len/binary, Rest1/binary>> = Rest,
    {Data, Rest1}.

%%-------------------------------------------------------------------------
%%@doc Tag types.
%%@end
%%-------------------------------------------------------------------------
% tag_type(Class, Form, Tag) -> tag|seq|set|constructor
tag_type(indefinite_end, _, _) -> indefinite_end;
tag_type(_, 0, _) -> tag;
tag_type(0, 1, 16)       -> seq;
tag_type(0, 1, 17)       -> set;
tag_type(_, 1, _) -> constructor.

%%-------------------------------------------------------------------------
%%@doc Classes.
%%@end
%%-------------------------------------------------------------------------
fmt_class(0) -> univ;
fmt_class(1) -> app;
fmt_class(2) -> context;
fmt_class(3) -> priv.


