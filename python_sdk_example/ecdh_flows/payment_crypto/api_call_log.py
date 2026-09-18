"""
Lightweight AWS API call recorder for the browser "Select PIN" demo.

The Flask app (webapp.py) calls into ecdh.setup/ecdh.backend/ecdh.crypto_utils, which each
create their own boto3 clients for AWS Payment Cryptography (control plane + data plane) and
AWS Private CA (acm-pca). None of those calls are otherwise visible to the browser demo UI.

To surface "which AWS API was just called" in the browser's crypto log, this module patches
botocore's client dispatch (`BaseClient._make_api_call`) once, process-wide, so every AWS SDK
call made by any boto3 client is recorded -- but ONLY while a request handler has opted in via
the `track_api_calls()` context manager. Outside of that context, recording is a no-op.

This uses a contextvars.ContextVar rather than a plain global list so concurrent Flask requests
(if the dev server is ever run with threaded=True) each see only their own calls.
"""
import contextlib
import contextvars

import botocore.client

_call_log_var: "contextvars.ContextVar[list | None]" = contextvars.ContextVar("_call_log_var", default=None)

_MAX_PARAM_STRING_LENGTH = 120

_original_make_api_call = botocore.client.BaseClient._make_api_call


def _summarize_value(value):
    if isinstance(value, str):
        if len(value) > _MAX_PARAM_STRING_LENGTH:
            return f"{value[:_MAX_PARAM_STRING_LENGTH]}... ({len(value)} chars total)"
        return value
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, dict):
        return {k: _summarize_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_summarize_value(v) for v in value]
    return value


def _summarize_params(params):
    return _summarize_value(params)


def _patched_make_api_call(self, operation_name, api_params):
    call_log = _call_log_var.get()
    if call_log is not None:
        call_log.append({
            "service": self.meta.service_model.service_name,
            "operation": operation_name,
            "params": _summarize_params(api_params),
        })
    return _original_make_api_call(self, operation_name, api_params)


def install():
    """Applies the process-wide botocore patch. Safe to call multiple times."""
    botocore.client.BaseClient._make_api_call = _patched_make_api_call


@contextlib.contextmanager
def track_api_calls():
    """
    Context manager that records every AWS API call made (by any boto3 client, in any module)
    while the `with` block is executing. Yields the list of calls, which is populated
    incrementally as calls happen and can be read after the block exits.
    """
    call_log = []
    token = _call_log_var.set(call_log)
    try:
        yield call_log
    finally:
        _call_log_var.reset(token)
