SNI Forwarder in Erlang
=======================

Configuration
-------------

 - review and if necessary, update the file name and port numbers in the top of `snifer.erl`
 - `LISTEN_PORT` is where the SSL/TLS listener waits for incoming connections
 - if SNI is sent and the hostname matches a file in `MARK_DIR`, the connection is redirected to the port specified in that file.
 - otherwise (no SNI is sent or no line matches) the connection is redirected to `DEFAULT_PORT`

Building
--------

	$ erlc snifer.erl

Running
-------

	$ erl -s snifer

 - to stop, enter `q().` and press `Enter`
