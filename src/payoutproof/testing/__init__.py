"""Test-support doubles for PayoutProof.

Everything in this package is test-only by construction: it is injected
in-process by the test suite and is never reachable through configuration,
environment variables, or defaults. Staging and production configuration
paths are untouched.
"""

from payoutproof.testing.fake_oidc import (
    FakeOIDCProvider,
    build_fake_oidc_app,
    TEST_ISSUER,
    TEST_CLIENT_ID,
    TEST_CLIENT_SECRET,
    TEST_REDIRECT_URI,
)

__all__ = [
    "FakeOIDCProvider",
    "build_fake_oidc_app",
    "TEST_ISSUER",
    "TEST_CLIENT_ID",
    "TEST_CLIENT_SECRET",
    "TEST_REDIRECT_URI",
]
