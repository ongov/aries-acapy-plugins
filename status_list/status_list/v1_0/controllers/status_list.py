"""Status list controller."""

import logging
from typing import Any, Dict

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
    response_schema,
    match_info_schema,
    querystring_schema,
)
from marshmallow import fields

from ..models import StatusListDef, StatusList, StatusListSchema


LOGGER = logging.getLogger(__name__)


class CreateStatusListRequest(OpenAPISchema):
    """Request schema for ceating a new status list."""

    status_list_def_id = fields.Str(
        required=True,
        metadata={
            "description": "Status list definition identifier",
        },
    )


class CreateStatusListResponse(OpenAPISchema):
    """Response schema for creating a status list."""

    status = fields.Bool(required=True)
    error = fields.Str(required=False, metadata={"description": "Error text"})
    id = fields.Str(required=True, metadata={"description": "status list identifier."})


@docs(
    tags=["status-list"],
    summary="Create a new status list",
)
@request_schema(CreateStatusListRequest())
@response_schema(StatusListSchema(), 200, description="")
@tenant_authentication
async def create_status_list(request: web.BaseRequest):
    """Request handler for creating a new status list."""

    body: Dict[str, Any] = await request.json()
    definition_id = body.get("status_list_def_id", None)

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.transaction() as txn:
            # get status list id from status list definition
            definition = await StatusListDef.retrieve_by_id(
                txn, definition_id, for_update=True
            )

            # update status list definition list cursor
            definition.list_cursor += 1
            await definition.save(txn, reason="Update status list cursor.")

            # create new status list
            list = StatusList(
                definition_id=definition.id,
                sequence=str(definition.list_cursor),
                list_size=definition.list_size,
                status_size=definition.status_size,
            )
            await list.save(txn, reason="Create new status list.")

            # commmit all changes
            await txn.commit()

            LOGGER.debug(f"Created status list: {list}")
            result = list.serialize()

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


class QueryStatusListRequest(OpenAPISchema):
    """Request schema for querying status list."""

    sequence = fields.Str(
        required=False,
        metadata={"description": "Filter by status list sequence number."},
    )
    definition_id = fields.Str(
        required=False,
        metadata={"description": "Filter by status list definition identifier."},
    )


class QueryStatusListResponse(OpenAPISchema):
    """Response schema for querying status list."""

    results = fields.Nested(
        StatusListSchema(),
        many=True,
        metadata={"description": "Status lists."},
    )


class MatchStatusListIdRequest(OpenAPISchema):
    """Match info for request with identifier."""

    id = fields.Str(
        required=True,
        metadata={"description": "status list identifier."},
    )


@docs(
    tags=["status-list"],
    summary="Search status lists by filters.",
)
@querystring_schema(QueryStatusListRequest())
@response_schema(QueryStatusListResponse(), 200, description="")
@tenant_authentication
async def get_status_lists(request: web.BaseRequest):
    """Request handler for querying status lists."""

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.session() as session:
            tag_filter = {
                attr: value
                for attr in ("definition_id", "sequence")
                if (value := request.query.get(attr))
            }
            records = await StatusList.query(session=session, tag_filter=tag_filter)
            results = [record.serialize() for record in records]
    except (StorageError, BaseModelError, StorageNotFoundError) as err:

        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(
    tags=["status-list"],
    summary="Search status list by identifier",
)
@match_info_schema(MatchStatusListIdRequest())
@response_schema(StatusListSchema(), 200, description="")
@tenant_authentication
async def get_status_list(request: web.BaseRequest):
    """Request handler for querying status list by identifier."""

    id = request.match_info["id"]

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.session() as session:
            record = await StatusList.retrieve_by_id(session, id)
            results = [record.serialize()]

    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


class UpdateStatusListRequest(OpenAPISchema):
    """Request schema for ceating status list."""

    sequence = fields.Str(
        required=False,
        metadata={
            "description": "Record sequence number",
            "example": "3",
        },
    )
    seed = fields.Str(
        required=False,
        metadata={
            "description": "Seed string for randomly selecting status list entries",
            "example": "4f7db1adf2",
        },
    )
    list_size = fields.Int(
        required=False,
        default=131072,
        metadata={
            "description": "Number of entries in status list, minimum 131072",
            "example": 131072,
        },
    )
    status_size = fields.Int(
        required=False,
        default=1,
        metadata={
            "description": "Status list entry size in bits",
            "example": 1,
        },
    )
    num_assigned = fields.Int(
        required=False,
        default=0,
        metadata={
            "description": "Number of assigned entries in the list",
            "example": 100,
        },
    )
    status_encoded = fields.Str(
        required=False,
        metadata={
            "description": "Status list bitstring gzipped.",
            "example": "H4sIAEHCVmcC_2NgAAD_EtlBAgAAAA==",
        },
    )
    mask_encoded = fields.Str(
        required=False,
        metadata={
            "description": "Status list mask bitstring gzipped.",
            "example": "H4sIAEbCVmcC__sHAJYwB4gBAAAA",
        },
    )


@docs(
    tags=["status-list"],
    summary="Update status list by identifier",
)
@match_info_schema(MatchStatusListIdRequest())
@request_schema(UpdateStatusListRequest())
@response_schema(StatusListSchema(), 200, description="")
@tenant_authentication
async def update_status_list(request: web.BaseRequest):
    """Request handler for update status list by identifier."""

    id = request.match_info["id"]
    body: Dict[str, Any] = await request.json()
    LOGGER.debug(f"Updating status list {id} with: {body}")

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.session() as session:
            record = await StatusList.retrieve_by_id(session, id)

            for attr, value in body.items():
                setattr(record, attr, value)

            await record.save(session, reason="Update status list.")
            result = record.serialize()

    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


class DeleteStatusListResponse(OpenAPISchema):
    """Delete status list response."""

    deleted = fields.Str(required=True)
    id = fields.Str(required=False)
    error = fields.Str(required=False)


@docs(
    tags=["status-list"],
    summary="Delete a status list",
)
@match_info_schema(MatchStatusListIdRequest())
@response_schema(DeleteStatusListResponse(), 200, description="")
@tenant_authentication
async def delete_status_list(request: web.Request):
    """Request handler for deleting a status list."""

    id = request.match_info["id"]

    try:
        context: AdminRequestContext = request["context"]
        async with context.transaction() as txn:
            # delete status list
            status_list = await StatusList.retrieve_by_id(txn, id, for_update=True)
            await status_list.delete_record(txn)

            # commit transaction
            await txn.commit()

            result = {"deleted": True, "id": id}

    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)
