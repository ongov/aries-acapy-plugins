"""Status list publisher controller."""

from typing import Any, Dict
from datetime import datetime, timedelta, timezone
import gzip
import logging
import os

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import fields

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.error import BaseError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.wallet.util import bytes_to_b64

from ..models import StatusListDef, StatusList
from ..jwt import jwt_sign
from ..config import Config

LOGGER = logging.getLogger(__name__)


class PublishStatusListSchema(OpenAPISchema):
    """Request schema for publish_status_list."""

    issuer_did = fields.Str(
        required=True,
        metadata={
            "description": "issuer did.",
            "example": "did:web:dev.lab.di.gov.on.ca",
        },
    )
    definition_id = fields.Str(
        required=True,
        metadata={"description": "status list definition identifier."},
    )
    publish_format = fields.Str(
        required=True,
        metadata={
            "description": "status list publish format. [w3c|ietf]",
            "example": "w3c",
        },
    )


class PublishStatusListResponseSchema(OpenAPISchema):
    """Response schema for publish_status_list."""

    published = fields.Bool(required=True)
    error = fields.Str(required=False, metadata={"description": "Error text"})
    definition_id = fields.Str(
        required=True, metadata={"description": "Status list definition id."}
    )


@docs(
    tags=["status-list"],
    summary="Publish all status lists under a status list definition",
)
@request_schema(PublishStatusListSchema())
@response_schema(PublishStatusListResponseSchema(), 200, description="")
@tenant_authentication
async def publish_status_list(request: web.BaseRequest):
    """Request handler for publish_status_list."""

    body: Dict[str, Any] = await request.json()
    LOGGER.debug(f"publishing status list with: {body}")

    definition_id = body.get("definition_id", None)
    issuer_did = body.get("issuer_did", None)
    publish_format = body.get("publish_format", None)

    response = []

    try:
        context: AdminRequestContext = request["context"]
        config = Config.from_settings(context.profile.settings)

        async with context.profile.session() as session:
            definition = await StatusListDef.retrieve_by_id(session, definition_id)
            results = await StatusList.query(session, {"definition_id": definition_id})
            if context.metadata:
                wallet_did = context.metadata.get("wallet_id")
            else:
                wallet_did = "89ab9248-47ee-47ba-95d2-6026f3bf1dc8"

            for status_list in results:
                bytes = gzip.compress(status_list.status_bits.tobytes())
                base64 = bytes_to_b64(bytes, True)
                compressed_bitstring = base64.rstrip("=")

                path = config.path_pattern.format(
                    tenant_id=wallet_did,
                    status_list_format=publish_format,
                    status_list_sequence=status_list.sequence,
                )

                now = datetime.now(timezone.utc)
                validUntil = now + timedelta(days=365)
                unix_now = int(now.timestamp())
                unix_validUntil = int(validUntil.timestamp())
                ttl = 43200

                payload = {
                    "iss": issuer_did,
                    "nbf": unix_now,
                    "jti": f"urn:uuid:{status_list.id}",
                    "sub": config.base_url + path,
                }

                if publish_format == "ietf":
                    headers = {"typ": "statuslist+jwt"}
                    payload = {
                        **payload,
                        "iat": unix_now,
                        "exp": unix_validUntil,
                        "ttl": ttl,
                        "status_list": {
                            "bits": status_list.list_size,
                            "lst": compressed_bitstring,
                        },
                    }
                elif publish_format == "w3c":
                    headers = {}
                    payload = {
                        **payload,
                        "vc": {
                            "published": True,
                            "definition_id": definition_id,
                            "issuer_did": issuer_did,
                            "published_at": now.isoformat(),
                            "status_list_credential": {
                                "@context": ["https://www.w3.org/ns/credentials/v2"],
                                "id": config.base_url + path,
                                "type": [
                                    "VerifiableCredential",
                                    "BitstringStatusListCredential",
                                ],
                                "issuer": issuer_did,
                                "validFrom": now.isoformat(),
                                "validUntil": validUntil.isoformat(),
                                "credentialSubject": {
                                    "id": config.base_url + path + "#list",
                                    "type": "BitstringStatusList",
                                    "statusPurpose": definition.status_purpose,
                                    "encodedList": compressed_bitstring,
                                },
                            },
                        },
                    }

                jws = await jwt_sign(
                    context.profile,
                    headers,
                    payload,
                    did=issuer_did,
                )

                # publish status list
                if config.base_dir is not None:
                    file_path = config.base_dir + path
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    with open(file_path, "w") as file:
                        file.write(jws)

                response.append(payload)

    except BaseError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err

    return web.json_response(response)
