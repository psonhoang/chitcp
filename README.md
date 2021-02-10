chiTCP - A simple, testable TCP stack
=====================================

The chiTCP documentation is available at http://chi.cs.uchicago.edu/chitcp/

We pass tests for conn_init and conn_term at all LOG level
When we run data_transfer tests at LOG=DEBUG level, we pass all the tests.
However, when LOG level is not specified, we fail 3 tests:
- echo_32768bytes
- half_duplex_client_sends_32768bytes
- half_duplex_server_sends_32768bytes

When we run all tests with LOG=DEBUG, our final grade is 50/50.
When LOG level is not specified, our final grade is 47.78/50

