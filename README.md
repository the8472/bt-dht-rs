# Standalone BitTorrent DHT node in Rust

Work In Progress. The node itself works, is spec-compliant and tries to be
[robust against malicious nodes](https://github.com/the8472/mldht/blob/master/docs/sanitizing-algorithms.rst).

## Support for relevant BEPs:

* 5: yes
* 32: no
* 33: no
* 42: local ID is compliant. Not enforced on other nodes, but compliant nodes are treated preferentially. 
* 43: no
* 44: no
* 45: no
* 46: no
* 51: RPC supported. active crawling supported, stores infohashes into sqlite DB
