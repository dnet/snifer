SNI Forwarder in Erlang
=======================

Configuration
-------------

 - review and if necessary, update the file name and port numbers in the top of `snifer.erl`
 - `LISTEN_PORT` is where the SSL/TLS listener waits for incoming connections
 - if SNI is sent and it matches a line in `MARK_FILE`, the connection is redirected to `MARK_PORT`
 - otherwise (no SNI is sent or no line matches) the connection is redirected to `DEFAULT_PORT`

Building
--------

	$ erlc snifer.erl

Running
-------

	$ erl -s snifer

 - to stop, enter `q().` and press `Enter`
 - until a [pull request regarding SNI parsing in OTP][pr389] is resolved, append `-pa patch`

  [pr389]: https://github.com/erlang/otp/pull/389
