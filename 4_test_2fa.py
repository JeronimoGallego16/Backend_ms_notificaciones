import unittest
from functools import partial
from unittest.mock import Mock, patch

from fastapi import HTTPException

import main


class TwoFactorTests(unittest.TestCase):
    def setUp(self):
        main._challenges.clear()
        main.get_gmail_service.cache_clear()

    def tearDown(self):
        main.get_gmail_service.cache_clear()

    def test_expired_gmail_token_refresh_has_a_timeout(self):
        credentials = Mock(valid=False, expired=True, refresh_token="refresh")

        with (
            patch("main.TOKEN_FILE") as token_file,
            patch("main.CREDENTIALS_DIR") as credentials_dir,
            patch("main.pickle.load", return_value=credentials),
            patch("main.pickle.dump"),
            patch("main.Request", wraps=main.Request) as request,
        ):
            token_file.exists.return_value = True
            token_file.open.return_value.__enter__.return_value = object()

            main.authenticate_gmail()

        request.assert_called_once_with()
        credentials.refresh.assert_called_once()
        refresh_request = credentials.refresh.call_args.args[0]
        self.assertIsInstance(refresh_request, partial)
        self.assertEqual(
            refresh_request.keywords, {"timeout": main.GMAIL_HTTP_TIMEOUT_SECONDS}
        )
        credentials_dir.mkdir.assert_called_once_with(exist_ok=True)

    def test_gmail_api_client_uses_a_bounded_http_transport(self):
        credentials = object()
        resource = object()

        with (
            patch("main.authenticate_gmail", return_value=credentials),
            patch("main.httplib2.Http") as http_factory,
            patch("main.AuthorizedHttp") as authorized_http_factory,
            patch("main.build", return_value=resource) as build,
        ):
            self.assertIs(main.get_gmail_service(), resource)

        http_factory.assert_called_once_with(
            timeout=main.GMAIL_HTTP_TIMEOUT_SECONDS
        )
        authorized_http_factory.assert_called_once_with(
            credentials,
            http=http_factory.return_value,
        )
        build.assert_called_once_with(
            "gmail",
            "v1",
            http=authorized_http_factory.return_value,
            cache_discovery=False,
        )

    @patch("main._send_message", return_value="gmail-message-id")
    def test_request_generates_six_digit_code_without_returning_it(self, send_message):
        response = main.request_two_factor_code(
            main.TwoFactorRequest(email="persona@example.com")
        )

        self.assertEqual(response["expires_in"], main.TFA_CODE_TTL_SECONDS)
        self.assertNotIn("code", response)
        self.assertEqual(len(main._challenges), 1)
        send_message.assert_called_once()
        self.assertNotIn(
            main._challenges[response["challenge_id"]].code_hash,
            send_message.call_args.args[0]["raw"],
        )

    @patch("main.secrets.randbelow", return_value=123456)
    @patch("main._send_message", return_value="gmail-message-id")
    def test_code_is_single_use(self, send_message, randbelow):
        response = main.request_two_factor_code(
            main.TwoFactorRequest(email="persona@example.com")
        )
        code = "123456"

        verified = main.verify_two_factor_code(
            main.TwoFactorVerification(
                email="persona@example.com",
                challenge_id=response["challenge_id"],
                code=code,
            )
        )
        self.assertTrue(verified["verified"])
        with self.assertRaises(HTTPException):
            main.verify_two_factor_code(
                main.TwoFactorVerification(
                    email="persona@example.com",
                    challenge_id=response["challenge_id"],
                    code=code,
                )
            )

    @patch("main._send_message", return_value="gmail-message-id")
    def test_invalid_code_is_rejected(self, send_message):
        response = main.request_two_factor_code(
            main.TwoFactorRequest(email="persona@example.com")
        )

        with self.assertRaises(HTTPException) as error:
            main.verify_two_factor_code(
                main.TwoFactorVerification(
                    email="persona@example.com",
                    challenge_id=response["challenge_id"],
                    code="000000",
                )
            )

        self.assertEqual(error.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
