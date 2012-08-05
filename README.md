torchat for BitlBee is a plugin for the torchat protocol
========================================================

Usage
-----

```
account add torchat <username> <password or whatever>
```

Building and Installing
-----------------------

```
$ git clone https://github.com/meh/bitlbee-torchat.git
$ cd bitlbee-torchat
$ autoreconf -fi
$ ./configure
$ make
# make install
```

You also need Ruby 1.9 and to install the torchat gem

```
$ gem install --pre torchat
```
