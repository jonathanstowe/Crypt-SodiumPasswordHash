use v6;

use NativeCall :TEST,:DEFAULT;
use NativeLibs:ver<0.0.5+>;
use NativeHelpers::Array;

=begin pod

=head1  NAME

Crypt::SodiumPasswordHash - scrypt password hashing using libsodium


=head1 SYNOPSIS

=begin code

use Crypt::SodiumPasswordHash;

my $password =  'somepa55word';

my $hash     =  sodium-hash($password);

if sodium-verify($hash, $password ) {

    #  password ok

}

=end code

=head1 DESCRIPTION

This module provides a binding to the password hashing functions provided
by L<libsodium|https://libsodium.gitbook.io/doc/>.

The algorithm used is the one recomended by the installed version of
libsodium. as of version 23 this is a variant of Argon2, but older
versions may provide a different one as may future versions. Additionally
the C<sodium-verify> should be able to verify a password hash created
by other libraries that support the Argon2 family such as L<Crypt::Argon2||https://github.com/skinkade/p6-crypt-argon2>.


The hash returned by C<sodium-hash> is in the format used in
C</etc/shadow> and can be verified by other libraries that understand
the algorithm.  By default the I<interactive> limits for memory and
CPU usage are used, which is a reasonable compromise for the time
taken for both hashing and verification.  If the C<:sensitive> switch
is supplied to C<sodium-hash> then both hashing and verification take
significantly longer (and use more memory,) so this may not suitable
for some applications.

=end pod

module Crypt::SodiumPasswordHash {

    constant LIB = NativeLibs::Searcher.at-runtime(
        'sodium',
        'crypto_pwhash_strbytes',
        15..23
    );


    sub crypto_pwhash_alg_argon2i13( --> int32 ) is native(LIB) { * }

    sub crypto_pwhash_alg_argon2id13( --> int32 ) is native(LIB) { * }

    sub crypto_pwhash_alg_default( --> int32 ) is native(LIB) { * }


    enum HashAlgorithm is export (
        ARGON2I13   => crypto_pwhash_alg_argon2i13(),
        ARGON2ID13  => crypto_pwhash_alg_argon2id13()
    );

    sub crypto_pwhash_strbytes( --> size_t ) is native(LIB) { * }

    constant SODIUM_STRBYTES = crypto_pwhash_strbytes();


    sub crypto_pwhash_opslimit_interactive( --> size_t ) is native(LIB) { * }

    constant OPSLIMIT_INTERACTIVE = crypto_pwhash_opslimit_interactive();

    sub crypto_pwhash_memlimit_interactive( --> size_t ) is native(LIB) { * }

    constant MEMLIMIT_INTERACTIVE = crypto_pwhash_memlimit_interactive();

    sub crypto_pwhash_opslimit_sensitive( --> size_t ) is native(LIB) { * }

    constant OPSLIMIT_SENSITIVE = crypto_pwhash_opslimit_sensitive();

    sub crypto_pwhash_memlimit_sensitive( --> size_t ) is native(LIB) { * }

    constant MEMLIMIT_SENSITIVE = crypto_pwhash_memlimit_sensitive();

    sub crypto_pwhash_str_alg(CArray[uint8] $out, Str $passwd, ulonglong $passwdlen, ulonglong $opslimit, size_t $memlimit, int32 $alg --> int32) is native(LIB) { * }

    sub sodium-hash(Str $password, HashAlgorithm $algo = HashAlgorithm(crypto_pwhash_alg_default()), Bool :$sensitive --> Str ) is export {

        my $opslimit = $sensitive ?? OPSLIMIT_SENSITIVE !! OPSLIMIT_INTERACTIVE;
        my $memlimit = $sensitive ?? MEMLIMIT_SENSITIVE !! MEMLIMIT_INTERACTIVE;
        my $password-length = $password.encode.bytes;
        my $hashed        = CArray[uint8].allocate(SODIUM_STRBYTES);

        if crypto_pwhash_str_alg($hashed, $password, $password-length, $opslimit, $memlimit, $algo) {
            die 'out of memory in sodium-hash';
        }

        my $buf = copy-carray-to-buf($hashed, SODIUM_STRBYTES);
        $buf.decode.subst(/\0+$/,'');
    }

    sub crypto_pwhash_str_verify(Str $str, Str $passwd, ulonglong $passwdlen --> int32) is native(LIB) { * }

    sub sodium-verify(Str $hash, Str $password --> Bool ) is export {
        my $password-length = $password.encode.bytes;
        !crypto_pwhash_str_verify($hash, $password, $password-length);
    }

}

# vim: ft=raku
