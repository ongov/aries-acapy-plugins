"""Status List Models."""

import random
import string
from typing import Optional
from bitarray import bitarray, util as bitutil
from marshmallow import fields
from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from acapy_agent.wallet.util import b64_to_bytes, bytes_to_b64

from .feistel import FeistelPermutation


class StatusListDef(BaseRecord):
    """Status List Definition."""

    RECORD_TOPIC = "status-list"
    RECORD_TYPE = "status-list-def"
    RECORD_ID_NAME = "id"
    TAG_NAMES = {"status_purpose"}

    class Meta:
        """Status List Definition Metadata."""

        schema_class = "StatusListDefSchema"

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        status_purpose: Optional[str] = None,
        status_size: Optional[int] = 1,
        status_message: Optional[dict] = None,
        list_size: Optional[int] = 131072,
        list_cursor: Optional[int] = -1,
        **kwargs,
    ) -> None:
        """Initialize a new status list definition instance."""

        super().__init__(id, **kwargs)

        self.status_purpose = status_purpose
        self.status_size = status_size
        self.status_message = status_message
        self.list_size = list_size
        self.list_cursor = list_cursor

    @property
    def id(self) -> str:
        """Accessor for the ID associated with this status list definition."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "status_purpose",
                "status_size",
                "status_message",
                "list_size",
                "list_cursor",
            )
        }


class StatusListDefSchema(BaseRecordSchema):
    """Status List Definition Schema."""

    class Meta:
        """Status list definition schema metadata."""

        model_class = "StatusListDef"

    id = fields.Str(
        required=False,
        metadata={
            "description": "Status list definition identifier",
        },
    )

    status_purpose = fields.Str(
        required=False,
        default="revocation",
        metadata={
            "description": "Status purpose: revocation, suspension or message",
            "example": "revocation",
        },
    )
    status_size = fields.Int(
        required=False,
        default=1,
        metadata={"description": "Status size in bits", "example": 1},
    )
    status_message = fields.Dict(
        required=False,
        default=None,
        metadata={
            "description": "Status List message status",
            "example": {
                "0x00": "active",
                "0x01": "revoked",
                "0x10": "pending",
                "0x11": "suspended",
            },
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
    list_cursor = fields.Int(
        required=False,
        default=-1,
        metadata={"description": "Status list cursor", "example": 10},
    )


class StatusList(BaseRecord):
    """Status List."""

    RECORD_TOPIC = "status-list"
    RECORD_TYPE = "status-list-rec"
    RECORD_ID_NAME = "id"
    TAG_NAMES = {"definition_id", "sequence"}

    class Meta:
        """Status List Metadata."""

        schema_class = "StatusListSchema"

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        definition_id: str = None,
        sequence: Optional[str] = None,
        seed: Optional[str] = None,
        list_size: int,
        status_size: int,
        num_assigned: Optional[int] = 0,
        status_encoded: Optional[str] = None,
        mask_encoded: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Initialize a new status list instance."""

        super().__init__(id, **kwargs)

        self.definition_id = definition_id
        self.sequence = sequence
        self.seed = seed
        self.list_size = list_size
        self.status_size = status_size
        self.num_assigned = num_assigned
        self.status_encoded = status_encoded
        self.mask_encoded = mask_encoded

        if self.seed is None:
            self.seed = "".join(
                random.choices(string.ascii_letters + string.digits, k=32)
            )

        if self.status_encoded is None:
            self.status_bits = bitutil.zeros(self.list_size * self.status_size)

        if self.mask_encoded is None:
            self.mask_bits = bitutil.ones(self.list_size)

    @property
    def id(self) -> str:
        """Accessor for the ID associated with this status list."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "definition_id",
                "sequence",
                "seed",
                "list_size",
                "status_size",
                "num_assigned",
                "status_encoded",
                "mask_encoded",
            )
        }

    @property
    def status_bits(self) -> bitarray:
        """Parse encoded status string to bits."""
        status_bytes = b64_to_bytes(self.status_encoded, True)
        status_bits = bitarray()
        status_bits.frombytes(status_bytes)
        while len(status_bits) > self.list_size * self.status_size:
            for i in range(self.status_size):
                status_bits.pop(0)
        return status_bits

    @status_bits.setter
    def status_bits(self, bits: bitarray):
        """Encode status bits to a string."""
        self.status_encoded = bytes_to_b64(bits.tobytes(), True)

    @property
    def mask_bits(self) -> bitarray:
        """Parse encoded mask string to bits."""
        mask_bytes = b64_to_bytes(self.mask_encoded, True)
        mask_bits = bitarray()
        mask_bits.frombytes(mask_bytes)
        while len(mask_bits) > self.list_size:
            mask_bits.pop(0)
        return mask_bits

    @mask_bits.setter
    def mask_bits(self, bits: bitarray):
        """Encode mask bits to a string."""
        self.mask_encoded = bytes_to_b64(bits.tobytes(), True)

    @property
    def random_entry(self):
        """Return a random entry from the status list."""
        master_key_bytes = self.seed.encode("utf-8")
        feistel = FeistelPermutation(self.list_size, master_key_bytes)
        return feistel.permute(self.num_assigned)


class StatusListSchema(BaseRecordSchema):
    """Status List Schema."""

    class Meta:
        """Status List Schema Metadata."""

        model_class = "StatusList"

    id = fields.Str(
        required=False,
        metadata={
            "description": "Status list identifier",
        },
    )

    definition_id = fields.Str(
        required=True,
        metadata={
            "description": "Status list definition identifier",
        },
    )
    sequence = fields.Str(
        required=True,
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
