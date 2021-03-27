#!/usr/bin/env raku

use v6;

use Test;
use LibraryCheck;

sub check-lib-version() {
    my Str $name = 'sodium';
    my Int $lower = 13;
    my Int $upper = 23;

    my $rc = False;

    for $lower .. $upper -> $version-number {
        my $version = Version.new($version-number);

        if library-exists($name, $version) {
            $rc = True;
            last;
        }
    }

    $rc;
}

if check-lib-version() {
    require Crypt::SodiumPasswordHash <&sodium-hash &sodium-verify ARGON2I13 ARGON2ID13>;

    my @chars = (|("a" .. "z"), |("A" .. "Z"), |(0 .. 9));

    subtest  {
        my $password = @chars.pick(20).join;
        my $hash;
        lives-ok { $hash = sodium-hash($password) }, 'sodium-hash';
        lives-ok { ok sodium-verify($hash, $password), "verify ok" }, 'sodium-verify';
        lives-ok { nok sodium-verify($hash, $password.flip), "verify nok with wrong password" }, 'sodium-verify';
    }, 'with interactive profile';
    subtest  {
        my $password = @chars.pick(20).join;
        my $hash;
        lives-ok { $hash = sodium-hash($password, ARGON2ID13) }, 'sodium-hash';
        lives-ok { ok sodium-verify($hash, $password), "verify ok" }, 'sodium-verify';
        lives-ok { nok sodium-verify($hash, $password.flip), "verify nok with wrong password" }, 'sodium-verify';
    }, 'with explicit ARGON2ID13 ';
    todo "ARGON2I13 doesn't seem to work as expected";
    subtest  {
        my $password = @chars.pick(20).join;
        my $hash;
        lives-ok { $hash = sodium-hash($password, ARGON2I13) }, 'sodium-hash';
        lives-ok { ok sodium-verify($hash, $password), "verify ok" }, 'sodium-verify';
        lives-ok { nok sodium-verify($hash, $password.flip), "verify nok with wrong password" }, 'sodium-verify';
    }, 'with explicit ARGON2I13 ';
    subtest  {
        my $password = @chars.pick(20).join;
        my $hash;
        lives-ok { $hash = sodium-hash($password, :sensitive) }, 'sodium-hash';
        lives-ok { ok sodium-verify($hash, $password), "verify ok" }, 'sodium-verify';
        lives-ok { nok sodium-verify($hash, $password.flip), "verify nok with wrong password" }, 'sodium-verify';
    }, 'with sensitive profile';
    subtest {
        if (try require ::('Crypt::Argon2') <&argon2-hash> ) !=== Nil {
            my $password = @chars.pick(20).join;
            my $hash;
            lives-ok { $hash = argon2-hash($password) }, 'use argon2-hash from Crypt::Argon2';
            lives-ok { ok sodium-verify($hash, $password), "verify ok" }, 'sodium-verify should validate ok';
        }
        else {
            skip "No Argon2 module installed";
        }

    }, "hash compatibility";
}
else {
    diag "libsodium is not installed";
    skip "No libsodium, skipping tests";
}



done-testing;
# vim: expandtab shiftwidth=4 ft=raku
