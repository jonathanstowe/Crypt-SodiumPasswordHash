# Crypt::SodiumPasswordHash

Password hashing using the libsodium recommended algorithm

![Build Status](https://github.com/jonathanstowe/Crypt-SodiumPasswordHash/workflows/CI/badge.svg)

## Synopsis


    use Crypt::SodiumPasswordHash;

    my $password =  'somepa55word';

    my $hash     =  sodium-hash($password);

    if sodium-verify($hash, $password ) {

        #  password ok

    }

## Description

This module provides a binding to the password hashing functions provided by [libsodium](https://libsodium.gitbook.io/doc/).

The algorithm used is the one recomended by the installed version of libsodium. as of version 23 this is a variant of Argon2, but older versions may provide a different one as may future versions. Additionally the `sodium-verify` should be able to verify a password hash created by other libraries that support the Argon2 family such as [Crypt::Argon2](|https://github.com/skinkade/p6-crypt-argon2).

The hash returned by `sodium-hash` is in the format used in `/etc/shadow` and can be verified by other libraries that understand the algorithm. By default the *interactive* limits for memory and CPU usage are used, which is a reasonable compromise for the time taken for both hashing and verification. If the `:sensitive` switch is supplied to `sodium-hash` then both hashing and verification take significantly longer (and use more memory,) so this may not suitable for some applications.


## Installation

You will need to have C<libsodium> installed for this to work, it is commonly packaged for various Linux distributions, so you should be able
to use the usual package management tools.

Assuming that you have a working installation of Rakudo then you should be able to install this with *zef* :

    zef install Crypt::SodiumPasswordHash

    # Or from a local clone

    zef install .

The tests take a little longer than might be expected because it tests the _sensitive_ profile which is designed to take longer.

## Support

If you any suggestions/patches feel free to send them via:

https://github.com/jonathanstowe/Crypt-SodiumPasswordHash/issues

I've tested this with libsodium versions from 13 to 23, but if you find it doesn't work please let me know which version you have installed.

## Licence & Copyright

This is free software please see the [LICENCE](LICENCE) file in the distribution
for details.

© Jonathan Stowe 2019 - 2021
