"""Bounded codec request framing; synthetic payloads and loopback only."""
import http.client
import unittest
from email.message import Message
from unittest.mock import AsyncMock, Mock

from codec_server import MAX_BODY_BYTES, make_handler
import test_cors
from cors import CorsPolicy


class RequestFramingTests(unittest.TestCase):
    def reject_without_read(self, headers, expected):
        handler_type = make_handler(Mock())
        handler = handler_type.__new__(handler_type)
        handler.path = '/decode'
        handler.headers = Message()
        for name, value in headers:
            handler.headers[name] = value
        handler.rfile = Mock()
        handler.send_error = Mock()
        handler.do_POST()
        self.assertEqual(handler.send_error.call_args.args[0], expected)
        handler.rfile.read.assert_not_called()

    def test_invalid_lengths_never_read(self):
        for value in ['-1', '+1', '1.0', 'abc', '', '1, 1', '١', '9' * 5000]:
            with self.subTest(value=value[:20]):
                self.reject_without_read([('Content-Length', value)],
                                         413 if value == '9' * 5000 else 400)

    def test_missing_duplicate_and_transfer_encoding_never_read(self):
        self.reject_without_read([], 411)
        self.reject_without_read([('Content-Length', '2'), ('Content-Length', '2')], 400)
        for value in ['chunked', 'identity']:
            self.reject_without_read([('Content-Length', '2'), ('Transfer-Encoding', value)], 400)

    def test_exact_limit_and_leading_zeros_remain_supported(self):
        codec = Mock()
        codec.decode = AsyncMock(return_value=[])
        handler_type = make_handler(codec)
        handler = handler_type.__new__(handler_type)
        handler.path = '/decode'
        handler.headers = Message()
        handler.headers['Content-Length'] = '000' + str(MAX_BODY_BYTES)
        handler.rfile = Mock()
        handler.rfile.read.return_value = b'{}' + b' ' * (MAX_BODY_BYTES - 2)
        handler.wfile = Mock()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.do_POST()
        handler.rfile.read.assert_called_once_with(MAX_BODY_BYTES)
        handler.send_response.assert_called_once_with(200)
        codec.decode.assert_awaited_once()

    def test_oversize_never_reads(self):
        for value in [str(MAX_BODY_BYTES + 1), '000' + str(MAX_BODY_BYTES + 1)]:
            self.reject_without_read([('Content-Length', value)], 413)


class RequestFramingHttpTests(unittest.TestCase):
    start = test_cors.ServerCorsTests.start
    request = test_cors.ServerCorsTests.request
    post = test_cors.ServerCorsTests.post
    BODY = test_cors.ServerCorsTests.BODY
    def test_negative_length_is_rejected_without_waiting_for_body(self):
        port = self.start(CorsPolicy())
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
        try:
            conn.putrequest('POST', '/decode')
            conn.putheader('Content-Length', '-1')
            conn.endheaders()
            response = conn.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
        finally:
            conn.close()
        # A rejected request must not leave the single server wedged.
        self.assertEqual(self.post(port)[0], 200)


if __name__ == '__main__':
    unittest.main()
