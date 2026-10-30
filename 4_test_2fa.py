import unittest
from unittest.mock import patch

from fastapi import HTTPException

import main


class TwoFactorTests(unittest.TestCase):
    def setUp(self):
        main._challenges.clear()

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
