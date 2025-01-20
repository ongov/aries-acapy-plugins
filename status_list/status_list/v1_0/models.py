"""Status List Models."""

import random
import string
from typing import Optional
from bitarray import bitarray, util as bitutil
from marshmallow import fields
from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from acapy_agent.wallet.util import b64_to_bytes, bytes_to_b64

from .feistel import FeistelPermutation
from .config import Config


class StatusListDef(BaseRecord):
    """Status List Definition."""

    RECORD_TOPIC = "status-list"
    RECORD_TYPE = "status-list-def"
    RECORD_ID_NAME = "id"
    TAG_NAMES = {"supported_cred_id", "status_purpose"}

    class Meta:
        """Status List Definition Metadata."""

        schema_class = "StatusListDefSchema"

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        supported_cred_id: Optional[str] = None,
        status_purpose: Optional[str] = None,
        status_message: Optional[dict] = None,
        status_size: Optional[int] = 1,
        shard_size: Optional[int] = -1,
        list_size: Optional[int] = -1,
        list_seed: Optional[str] = None,
        list_number: Optional[int] = -1,
        list_index: Optional[int] = -1,
        next_list_number: Optional[int] = -1,
        **kwargs,
    ) -> None:
        """Initialize a new status list definition instance."""

        super().__init__(id, **kwargs)

        self.supported_cred_id = supported_cred_id
        self.status_purpose = status_purpose
        self.status_message = status_message
        self.status_size = status_size
        self.shard_size = shard_size
        self.list_size = list_size
        self.list_seed = list_seed
        self.list_number = list_number
        self.list_index = list_index
        self.next_list_number = next_list_number

        if self.list_seed is None:
            self.seed_list()
        if self.shard_size == -1:
            self.shard_size = int(Config.shard_size)
        if self.list_size == -1:
            self.list_size = int(Config.list_size)

    @property
    def id(self) -> str:
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "status_purpose",
                "status_message",
                "status_size",
                "list_size",
                "shard_size",
                "list_seed",
                "list_number",
                "list_index",
                "next_list_number",
            )
        }

    def get_random_entry(self) -> tuple:
        """Return a random entry from the status list."""
        # generate a random index
        master_key_bytes = self.list_seed.encode("utf-8")
        feistel = FeistelPermutation(self.list_size, master_key_bytes)
        random_index = feistel.permute(self.list_index)
        # calculate shard_number and shard_index
        shard_number = random_index // self.shard_size
        shard_index = random_index % self.shard_size
        return random_index, shard_number, shard_index

    def seed_list(self) -> str:
        """Seed the status list."""
        self.list_seed = "".join(
            random.choices(string.ascii_letters + string.digits, k=32)
        )


class StatusListDefSchema(BaseRecordSchema):
    """Status List Definition Schema."""

    class Meta:
        """Status list definition schema metadata."""

        model_class = "StatusListDef"

    id = fields.Str(
        required=False,
        metadata={"description": "Status list definition identifier"},
    )

    supported_cred_id = fields.Str(
        required=False,
        metadata={"description": "Supported credential identifier"},
    )
    status_purpose = fields.Str(
        required=False,
        default="revocation",
        metadata={
            "description": "Status purpose: revocation, suspension or message",
            "example": "revocation",
        },
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
    status_size = fields.Int(
        required=False,
        default=1,
        metadata={"description": "Status size in bits", "example": 1},
    )
    shard_size = fields.Int(
        required=False,
        metadata={
            "description": "Number of entries in each shard, between 1 and list_size",
            "example": 1024,
        },
    )
    list_size = fields.Int(
        required=False,
        metadata={
            "description": "Number of entries in the list, must be power of two, minimum 131072",
            "example": 131072,
        },
    )
    list_seed = fields.Str(
        required=False,
        metadata={
            "description": "Current status list random seed",
            "example": "abc123",
        },
    )
    list_index = fields.Str(
        required=False,
        metadata={"description": "Current status list index", "example": 10240},
    )
    next_list_number = fields.Int(
        required=False,
        metadata={"description": "Next status list number", "example": 11},
    )


class StatusListShard(BaseRecord):
    """Status List Shard."""

    RECORD_TOPIC = "status-list"
    RECORD_TYPE = "status-list-shard"
    RECORD_ID_NAME = "id"
    TAG_NAMES = {"definition_id", "list_number", "shard_number"}

    class Meta:
        """Status List Shard Metadata."""

        schema_class = "StatusListShardSchema"

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        definition_id: str = None,
        list_number: Optional[str] = None,
        shard_number: Optional[str] = None,
        shard_size: int,
        status_size: int,
        status_encoded: Optional[str] = None,
        mask_encoded: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Initialize a new status list shard instance."""

        super().__init__(id, **kwargs)

        self.definition_id = definition_id
        self.list_number = list_number
        self.shard_number = shard_number
        self.shard_size = shard_size
        self.status_size = status_size
        self.status_encoded = status_encoded
        self.mask_encoded = mask_encoded

        if self.status_encoded is None:
            self.status_bits = bitutil.zeros(self.shard_size * self.status_size)

        if self.mask_encoded is None:
            self.mask_bits = bitutil.ones(self.shard_size)

    @property
    def id(self) -> str:
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "definition_id",
                "list_number",
                "shard_number",
                "shard_size",
                "status_size",
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
        while len(status_bits) > self.shard_size * self.status_size:
            for i in range(self.status_size):
                status_bits.pop(len(status_bits) - 1)
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
        while len(mask_bits) > self.shard_size:
            mask_bits.pop(len(mask_bits) - 1)
        return mask_bits

    @mask_bits.setter
    def mask_bits(self, bits: bitarray):
        """Encode mask bits to a string."""
        self.mask_encoded = bytes_to_b64(bits.tobytes(), True)


class StatusListShardSchema(BaseRecordSchema):
    """Status List Shard Schema."""

    class Meta:
        """Status List Shard Schema Metadata."""

        model_class = "StatusListShard"

    id = fields.Str(
        required=False,
        metadata={
            "description": "Status list shard identifier",
        },
    )

    definition_id = fields.Str(
        required=True,
        metadata={
            "description": "Status list definition identifier",
        },
    )
    list_number = fields.Str(
        required=True,
        metadata={
            "description": "Status list number",
            "example": "3",
        },
    )
    shard_number = fields.Str(
        required=True,
        metadata={
            "description": "Status list shard number",
            "example": "512",
        },
    )
    shard_size = fields.Int(
        required=True,
        metadata={
            "description": "Number of entries in each shard, between 1 and list_size",
            "example": 1024,
        },
    )
    status_size = fields.Int(
        required=False,
        default=1,
        metadata={"description": "Status size in bits", "example": 1},
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


class StatusListCred(BaseRecord):
    """Status List Credential."""

    RECORD_TOPIC = "status-list"
    RECORD_TYPE = "status-list-cred"
    RECORD_ID_NAME = "id"
    TAG_NAMES = {"definition_id", "credential_id"}

    class Meta:
        """Status List Credential Metadata."""

        schema_class = "StatusListCredSchema"

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        definition_id: str = None,
        credential_id: str = None,
        list_number: Optional[str] = None,
        list_index: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Initialize a new status list credential instance."""

        super().__init__(id, **kwargs)

        self.definition_id = definition_id
        self.credential_id = credential_id
        self.list_number = list_number
        self.list_index = list_index

    @property
    def id(self) -> str:
        """Accessor for the ID associated with this record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "definition_id",
                "credential_id",
                "list_number",
                "list_index",
            )
        }


class StatusListCredSchema(BaseRecordSchema):
    """Status List Credential Schema."""

    class Meta:
        """Status List Credential Schema Metadata."""

        model_class = "StatusListCred"

    id = fields.Str(
        required=False,
        metadata={
            "description": "Status list credential identifier",
        },
    )

    definition_id = fields.Str(
        required=True,
        metadata={
            "description": "Status list definition identifier",
        },
    )
    credential_id = fields.Str(
        required=True,
        metadata={
            "description": "Status list credential identifier",
        },
    )
    list_number = fields.Str(
        required=True,
        metadata={
            "description": "Status list number",
            "example": "3",
        },
    )
    list_index = fields.Str(
        required=True,
        metadata={
            "description": "Status list index",
            "example": "512",
        },
    )
