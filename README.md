# mod_hmacauth

mod_hmacauth is an apache 2.2 module that provides hmac-md5 based
authentication of requests. Apache configuration can be used to specify which
files require authentication, and the requester then have to provide
a timestamp and a secret as part of the querystring. The secret is the hmac of
the timestamp and the requesters ip address. mod_hmacauth then checks that the
timestamp doesn't deviate too much from current time, and computes an hmac
secret on the server. If the supplied and server generated secrets match, the
request is allowed to proceed.

Sample config:

    LoadModule hmacauth_module modules/mod_hmacauth.so
    HMACAuthSecret "mysecret"
    <Location /secret.txt>
        SetHandler hmacauth
    </Location>

Sample querystring generation in PHP:

    $time = time();
    echo "?timestamp=".$time."&secret=".hash_hmac("md5", $time."|192.168.0.20", "mysecret")."\n";

Can be installed using:

    sudo apxs -c -i mod_hmacauth.c

(apxs may require some dev package)
