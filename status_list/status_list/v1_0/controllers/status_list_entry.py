"""Status list entry controller."""

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
)
from marshmallow import fields
from bitarray import bitarray

from ..models import StatusListDef, StatusList


LOGGER = logging.getLogger(__name__)


class MatchStatusListRequest(OpenAPISchema):
    """Match info for request with status list identifier."""

    status_list_id = fields.Str(
        required=True,
        metadata={"description": "Status list identifier."},
    )


class CreateStatusListEntryRequest(OpenAPISchema):
    """Request schema for ceating status list entry."""

    status_list_def_id = fields.Str(
        required=True,
        metadata={
            "description": "Status list definition identifier",
        },
    )


class CreateStatusListEntryResponse(OpenAPISchema):
    """Response schema for creating status list entry."""

    status_list_id = fields.Str(
        required=False,
        metadata={
            "description": "Status list identifier",
        },
    )
    index = fields.Int(
        required=False,
        metadata={"description": "Status index", "example": 3},
    )
    status = fields.Str(
        required=False,
        metadata={"description": "Status bitstring", "example": "10"},
    )


@docs(
    tags=["status-list"],
    summary="Create a status list entry",
)
@request_schema(CreateStatusListEntryRequest())
@response_schema(CreateStatusListEntryResponse(), 200, description="")
@tenant_authentication
async def create_status_list_entry(request: web.BaseRequest):
    """Request handler for creating a status list entry."""

    try:
        context: AdminRequestContext = request["context"]

        async with context.profile.transaction() as txn:
            # get status list id from status list definition
            body: Dict[str, Any] = await request.json()
            definition_id = body.get("status_list_def_id", None)
            definition = await StatusListDef.retrieve_by_id(
                txn, definition_id, for_update=True
            )
            list_cursor = definition.list_cursor

            # get status list instance
            list = None
            if list_cursor >= 0:
                list = await StatusList.retrieve_by_tag_filter(
                    txn,
                    {
                        "definition_id": definition_id,
                        "sequence": str(list_cursor),
                    },
                    for_update=True,
                )

            if list is None or list.num_assigned >= list.list_size:
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

            status_bits = list.status_bits
            mask_bits = list.mask_bits

            # assign a status list entry
            status_index = list.random_entry
            bit_index = status_index * list.status_size
            if mask_bits[status_index]:
                mask_bits[status_index] = False
                list.mask_bits = mask_bits
                list.num_assigned += 1
                await list.save(txn, reason="Assign a status entry")

                result = {
                    "status_list_id": list.id,
                    "index": status_index,
                    "status": status_bits[
                        bit_index : bit_index + list.status_size
                    ].to01(),
                }
                LOGGER.debug(f"Assigned status list entry: {status_index}")
            else:
                raise web.HTTPBadRequest(
                    reason="Status list is full or entry is assigned."
                )

            # commmit all changes
            await txn.commit()

    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


class StatusListEntrySchema(OpenAPISchema):
    """Request schema for querying status list entry."""

    index = fields.Int(
        required=False,
        metadata={"description": "Status index", "example": 3},
    )
    status = fields.Str(
        required=False,
        metadata={"description": "Status bitstring", "example": "10"},
    )


class MatchStatusListEntryRequest(OpenAPISchema):
    """Match info for request with status list identifier."""

    status_list_id = fields.Str(
        required=True,
        metadata={"description": "Status list identifier."},
    )
    index = fields.Int(
        required=True,
        metadata={"description": "Status list index"},
    )


@docs(
    tags=["status-list"],
    summary="Search status list entry by identifier",
)
@match_info_schema(MatchStatusListEntryRequest())
@response_schema(StatusListEntrySchema(), 200, description="")
@tenant_authentication
async def get_status_list_entry(request: web.BaseRequest):
    """Request handler for querying status list entry by identifier."""

    status_list_id = request.match_info["status_list_id"]
    entry_index = int(request.match_info["index"])
    LOGGER.debug(f"Get status list entry: {status_list_id} at {entry_index}")

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.session() as session:
            list = await StatusList.retrieve_by_id(session, status_list_id)
            bit_index = entry_index * list.status_size
            result = {
                "index": entry_index,
                "status": list.status_bits[
                    bit_index : bit_index + list.status_size
                ].to01(),
                "is_assigned": not list.mask_bits[entry_index],
            }
            LOGGER.debug(f"Retrieved status list entry {result}.")

    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


class UpdateStatusListEntryRequest(OpenAPISchema):
    """Request schema for updating status list entry."""

    status = fields.Str(
        required=False,
        default=0,
        metadata={"description": "Status bitstring", "example": "10"},
    )


@docs(
    tags=["status-list"],
    summary="Update status list entry by identifier",
)
@match_info_schema(MatchStatusListEntryRequest())
@request_schema(UpdateStatusListEntryRequest())
@response_schema(StatusListEntrySchema(), 200, description="")
@tenant_authentication
async def update_status_list_entry(request: web.BaseRequest):
    """Request handler for update status list entry by identifier."""

    status_list_id = request.match_info["status_list_id"]
    entry_index = int(request.match_info["index"])
    body: Dict[str, Any] = await request.json()
    bitstring = body.get("status", 0)

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.transaction() as txn:
            list = await StatusList.retrieve_by_id(txn, status_list_id, for_update=True)

            status_bits = list.status_bits
            bit_index = entry_index * list.status_size
            status_bits[bit_index : bit_index + list.status_size] = bitarray(bitstring)
            list.status_bits = status_bits

            await list.save(txn, reason="Update status list entry.")
            await txn.commit()

            result = {
                "index": entry_index,
                "status": status_bits[bit_index : bit_index + list.status_size].to01(),
            }
            LOGGER.debug(f"Updated status list entry {result}.")

    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)


@docs(
    tags=["status-list"],
    summary="Recycle a status list entry",
)
@match_info_schema(MatchStatusListEntryRequest())
@response_schema(StatusListEntrySchema(), 200, description="")
@tenant_authentication
async def recycle_status_list_entry(request: web.BaseRequest):
    """Request handler for releasing a status list entry."""

    status_list_id = request.match_info["status_list_id"]
    entry_index = request.match_info["index"]

    try:
        context: AdminRequestContext = request["context"]
        async with context.profile.transaction() as txn:
            list = await StatusList.retrieve_by_id(txn, status_list_id, for_update=True)

            bit_index = entry_index * list.status_size
            status_bits = list.status_bits
            status_bits[bit_index : bit_index + list.status_size] = False
            list.status_bits = status_bits

            mask_bits = list.mask_bits
            mask_bits[entry_index] = True
            list.mask_bits = mask_bits

            await list.save(txn, reason="Recycle status list entry.")
            await txn.commit()

            result = {
                "index": entry_index,
                "status": list.status_bits[
                    bit_index : bit_index + list.status_size
                ].to01(),
            }
            LOGGER.debug(f"Recycled status list entry at {entry_index}.")

    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(result)
