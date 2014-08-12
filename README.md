# swab #

General purpose buffer handling module.

## Overview ##

swab can :

* cast data and sort lines.
* decode, encode and convert data, including EBCDIC. 
* catch data that becomes the new current buffer.
* match data and return the current buffer or otherwise continue next directives, if any.
* store a buffer queue and maybe use it later to compose another buffer for instance, by merging or concatenating.
* do diverse specialized (or custom) actions. (Pull requests welcome !).

swab give the possibility to debug all or part of the directive chain, to do hexdump *à la* `od` and also ASN1 pretty printing *à la* `openssl asn1parse`. 

swab offer a very easy way to chain directives as you would do by chaining commands with pipes in a shell. 

Each step can modify the input buffer that becomes a new current buffer, and so on.

## Documentation ##

A complete documentation is available on all directives.

Simply run `make docs` and open `doc/index.html` in your favorite browser, this will insure you having the documentation related to your version.

## Some examples ##

Bring the penultimate line :

```
[{jump, -2}, {nblines,1}]
```

AS400 data received in EBCDIC without linefeed, from 128 characters length records :

```
[{decode,ebcdic}, {fold, 128}]
```

Replace UID and GID to 0 in a gzip'ed tar :

```
[{convert, gunzip}, {tar, fakeroot}, {convert, gzip}]
```

Merge the two first lines and the last line of a string buffer (explained with debug) :

```
swab:sync([debug, queue}, {debug, on}, {buffer, in_r}, {nblines, 2}, {buffer, in},  
           {buffer, del}, {jump, -1}, {buffer, in}, {buffer, merge}, {buffer, del}],
           "Erlang\n is \n not \ngreat !").
<0.32.0> : {debug,on} => "Erlang\n is \n not \ngreat !"
           []
<0.32.0> : {buffer,in_r} => "Erlang\n is \n not \ngreat !"
           ["Erlang\n is \n not \ngreat !"]
<0.32.0> : {nblines,2} => "Erlang\n is "
           ["Erlang\n is \n not \ngreat !"]
<0.32.0> : {buffer,in} => "Erlang\n is "
           ["Erlang\n is \n not \ngreat !","Erlang\n is "]
<0.32.0> : {buffer,del} => "Erlang\n is \n not \ngreat !"
           ["Erlang\n is "]
<0.32.0> : {jump,-1} => "great !"
           ["Erlang\n is "]
<0.32.0> : {buffer,in} => "great !"
           ["Erlang\n is ","great !"]
<0.32.0> : {buffer,merge} => "great !"
           ["Erlang\n is \ngreat !"]
<0.32.0> : {buffer,del} => "Erlang\n is \ngreat !"
           []
{ok,"Erlang\n is \ngreat !"}
```

Hexdump debug :

```
    swab:sync([{debug,hexdump}], "Call me Ishmael. Some years ago--never mind how long precisely --having little or no money in my purse, and nothing particular to interest me on shore, I thought I would sail about a little and see the watery part of the world.").
    <0.32.0> : {debug,hexdump} => 
    00000000  43 61 6c 6c 20 6d 65 20 49 73 68 6d 61 65 6c 2e |Call me Ishmael.|
    00000010  20 53 6f 6d 65 20 79 65 61 72 73 20 61 67 6f 2d | Some years ago-|
    00000020  2d 6e 65 76 65 72 20 6d 69 6e 64 20 68 6f 77 20 |-never mind how |
    00000030  6c 6f 6e 67 20 70 72 65 63 69 73 65 6c 79 20 2d |long precisely -|
    00000040  2d 68 61 76 69 6e 67 20 6c 69 74 74 6c 65 20 6f |-having little o|
    00000050  72 20 6e 6f 20 6d 6f 6e 65 79 20 69 6e 20 6d 79 |r no money in my|
    00000060  20 70 75 72 73 65 2c 20 61 6e 64 20 6e 6f 74 68 | purse, and noth|
    00000070  69 6e 67 20 70 61 72 74 69 63 75 6c 61 72 20 74 |ing particular t|
    00000080  6f 20 69 6e 74 65 72 65 73 74 20 6d 65 20 6f 6e |o interest me on|
    00000090  20 73 68 6f 72 65 2c 20 49 20 74 68 6f 75 67 68 | shore, I though|
    000000a0  74 20 49 20 77 6f 75 6c 64 20 73 61 69 6c 20 61 |t I would sail a|
    000000b0  62 6f 75 74 20 61 20 6c 69 74 74 6c 65 20 61 6e |bout a little an|
    000000c0  64 20 73 65 65 20 74 68 65 20 77 61 74 65 72 79 |d see the watery|
    000000d0  20 70 61 72 74 20 6f 66 20 74 68 65 20 77 6f 72 | part of the wor|
    000000e0  6c 64 2e                                        |ld.|
    {ok,"Call me Ishmael. Some years ago--never mind how long precisely --having little or no money in my purse, and nothing particular to interest me on shore, I thought I would sail about a little and see the watery part of the world."}
```

ASN1 pretty printing :

```
    {ok, Der} = file:read_file("/tmp/certificate.der").
    {ok,<<48,130,3,193,48,130,2,169,160,3,2,1,2,2,9,0,174,28,
        240,36,102,146,9,116,48,13,6,...>>}

    swab:sync([{debug, asn1_pp}],Der).
    <0.36.0> : {debug,asn1_pp} => 
    SEQUENCE
    .  SEQUENCE
    .  .  CONSTRUCTOR
    .  .  .  INTEGER        : 10#2 (16#2)
    .  .  .  END
    .  .  INTEGER   : 10#12546166701077694836 (16#AE1CF02466920974)
    .  .  SEQUENCE
    .  .  .  OBJECT :  {1,2,840,113549,1,1,5}
    .  .  .  NULL   : <<>>
    .  .  .  END
    .  .  SEQUENCE
    .  .  .  SET
    .  .  .  .  SEQUENCE
    .  .  .  .  .  OBJECT   :  {2,5,4,6}
    .  .  .  .  .  PRINTABLESTRING  : FR
    .  .  .  .  .  END
    .  .  .  .  END
    .  .  .  SET
    .  .  .  .  SEQUENCE
    .  .  .  .  .  OBJECT   :  {2,5,4,8}
    .  .  .  .  .  VALUE    : Some-State
    .  .  .  .  .  END
    .  .  .  .  END

    ---- snip snip -----

    .  .  SEQUENCE
    .  .  .  UTCTIME        : 120708104913Z (2012-07-08 12:49:13 UTC+2)
    .  .  .  UTCTIME        : 281211104913Z (2028-12-11 11:49:13 UTC+2)
    .  .  .  END

    ---- snip snip -----

    .  .  CONSTRUCTOR
    .  .  .  SEQUENCE
    .  .  .  .  SEQUENCE
    .  .  .  .  .  OBJECT   :  {2,5,29,14}
    .  .  .  .  .  OCTET STRING     : 
    00000000  04 14 cd 81 ab 5c e1 59 b1 a4 f3 4d a1 9a 7e ab |.....\.Y...M..~.|
    00000010  ea fc 14 45 19 40                               |...E.@|
    .  .  .  .  .  END

    ---- snip snip -----

    .  END
    END
    {ok,<<48,130,3,193,48,130,2,169,160,3,2,1,2,2,9,0,174,28,
      240,36,102,146,9,116,48,13,6,...>>}
```

## Quick Start ##

```
git clone git://github.com/crownedgrouse/swab.git
cd swab
make
erl -pa `pwd`/ebin
```

## Contributing ##

Contributions are welcome. Please use pull-requests.

