# socks_inspector
  A simple SOCKS5 proxy to intercept, inspect and edit on the fly the network traffic of any SOCKSv5 capable application. Can be seen as little alternative to BurpSuit's proxy but faster and not only http but everything that supports SOCKS version 5.

### Usage
  ```--port PORT```  : set port number to listen on</br>
  ```--forward```    : enable forwarding of traffic</br>
  ```--log PATH```   : enable logging of the requests and received answers in binary format</br>
  ```--hexdump```    : print hexdump of each request and answer in STDOUT</br>
  ```--edit```       : hex edit requests</br>
  ```--threaded```   : parallelize connection handling (not compatible with --edit)

### Log Format
  Everything is logged in binary format .bin files. Can be viewed with a hexdump program, xxd for example.</br>
  
  Filename format of logged network packages : CLIENTIP_CLIENTPORT-PACKAGETYPE-RANDOMVALUE-COUNT.bin</br>
  CLIENTIP = the IPv4 address of the connected client</br>
  CLIENTPORT = the outbound port of the connected client</br>
  PACKAGETYPE = either request or reply</br>
  RANDOMVALUE = random value generated with arc4random(), one for each connected client</br>
  COUNT = the request/reply count (if there are multiple requests/replies for one destination, HTTP keep-alive connections for example)

  ### TODO
    - Add decrypting functionality for SSL/TLS traffic
