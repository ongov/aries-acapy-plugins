"""DID Cheqd Anoncreds Registry."""

import logging
import time
from datetime import datetime, timezone
from typing import Optional, Pattern, Sequence
from uuid import uuid4

from acapy_agent.anoncreds.base import (
    AnonCredsRegistrationError,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDef,
    CredDefResult,
    CredDefState,
    CredDefValue,
    GetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevListState,
    RevRegDef,
    RevRegDefResult,
    RevRegDefState,
    RevRegDefValue,
)
from acapy_agent.anoncreds.models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from acapy_agent.anoncreds.models.schema_info import AnoncredsSchemaInfo
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.jwt import dict_to_b64

from ..did.manager import CheqdDIDManager
from ..did.registrar import CheqdDIDRegistrar
from ..resolver.resolver import CheqdDIDResolver
from ..validation import CheqdDID

LOGGER = logging.getLogger(__name__)


class DIDCheqdRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """DIDCheqdRegistry."""

    registrar: CheqdDIDRegistrar
    resolver: CheqdDIDResolver

    def __init__(self):
        """Initialize an instance.

        Args:
            None

        """
        self.registrar = CheqdDIDRegistrar()
        self.resolver = CheqdDIDResolver()

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers regex."""
        return CheqdDID.PATTERN

    @staticmethod
    def make_schema_id(schema: AnonCredsSchema, resource_id: str) -> str:
        """Derive the ID for a schema."""
        return f"{schema.issuer_id}/resources/{resource_id}"

    @staticmethod
    def make_credential_definition_id(
        credential_definition: CredDef, resource_id: str
    ) -> str:
        """Derive the ID for a credential definition."""
        return f"{credential_definition.issuer_id}/resources/{resource_id}"

    @staticmethod
    def make_revocation_registry_id(
        revocation_registry_definition: RevRegDef, resource_id: str
    ) -> str:
        """Derive the ID for a revocation registry definition."""
        return f"{revocation_registry_definition.issuer_id}/resources/{resource_id}"

    @staticmethod
    def split_schema_id(schema_id: str) -> (str, str):
        """Derive the ID for a schema."""
        ids = schema_id.split("/")
        return ids[0], ids[2]

    async def setup(self, _context: InjectionContext, registrar_url, resolver_url):
        """Setup."""
        self.registrar = CheqdDIDRegistrar(registrar_url)
        self.resolver = CheqdDIDResolver(resolver_url)
        print("Successfully registered DIDCheqdRegistry")

    async def get_schema_info_by_schema_id(
        self, profile: Profile, schema_id: str
    ) -> AnoncredsSchemaInfo:
        """Get the schema info from the registry."""
        schema = self.get_schema(profile, schema_id)
        return {
            "issuer_id": schema.issuer_id,
            "name": schema.name,
            "version": schema.version,
        }

    async def get_schema(self, _profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        resource_with_metadata = await self.resolver.resolve_resource(schema_id)
        schema = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata

        (did, resource_id) = self.split_schema_id(schema_id)

        anoncreds_schema = AnonCredsSchema(
            issuer_id=did,
            attr_names=schema["attrNames"],
            name=schema["name"],
            version=schema["version"],
        )

        return GetSchemaResult(
            schema_id=schema_id,
            schema=anoncreds_schema,
            schema_metadata=metadata,
            resolution_metadata={},
        )

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        _options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        resource_type = "anonCredsSchema"
        resource_name = f"{schema.name}"
        resource_version = schema.version

        LOGGER.debug("Registering schema")
        cheqd_schema = {
            "name": resource_name,
            "type": resource_type,
            "version": resource_version,
            "data": dict_to_b64(
                {
                    "name": schema.name,
                    "version": schema.version,
                    "attrNames": schema.attr_names,
                }
            ),
        }

        LOGGER.debug("schema value: %s", cheqd_schema)
        try:
            resource_state = await self._create_and_publish_resource(
                profile,
                self.registrar.DID_REGISTRAR_BASE_URL,
                self.resolver.DID_RESOLVER_BASE_URL,
                schema.issuer_id,
                cheqd_schema,
            )
            job_id = resource_state.get("jobId")
            resource = resource_state.get("resource")
            resource_id = resource.get("id")
            schema_id = self.make_schema_id(schema, resource_id)
        except Exception as err:
            raise AnonCredsRegistrationError(f"{err}")
        return SchemaResult(
            job_id=job_id,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED,
                schema_id=schema_id,
                schema=schema,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
        )

    async def get_credential_definition(
        self, _profile: Profile, credential_definition_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""
        resource_with_metadata = await self.resolver.resolve_resource(
            credential_definition_id
        )
        credential_definition = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata
        (did, resource_id) = self.split_schema_id(credential_definition_id)

        anoncreds_credential_definition = CredDef(
            issuer_id=did,
            schema_id=credential_definition["schemaId"],
            type=credential_definition["type"],
            tag=credential_definition["tag"],
            value=CredDefValue.deserialize(credential_definition["value"]),
        )

        return GetCredDefResult(
            credential_definition_id=credential_definition_id,
            credential_definition=anoncreds_credential_definition,
            credential_definition_metadata=metadata,
            resolution_metadata={},
        )

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        _options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        resource_type = "anonCredsCredDef"
        resource_name = f"{schema.schema_value.name}-{credential_definition.tag}"

        cred_def = {
            "name": resource_name,
            "type": resource_type,
            "data": dict_to_b64(
                {
                    "type": credential_definition.type,
                    "tag": credential_definition.tag,
                    "value": credential_definition.value.serialize(),
                    "schemaId": schema.schema_id,
                }
            ),
            "version": credential_definition.tag,
        }

        resource_state = await self._create_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            credential_definition.issuer_id,
            cred_def,
        )
        job_id = resource_state.get("jobId")
        resource = resource_state.get("resource")
        resource_id = resource.get("id")

        credential_definition_id = self.make_credential_definition_id(
            credential_definition, resource_id
        )

        return CredDefResult(
            job_id=job_id,
            credential_definition_state=CredDefState(
                state=CredDefState.STATE_FINISHED,
                credential_definition_id=credential_definition_id,
                credential_definition=credential_definition,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            credential_definition_metadata={},
        )

    async def get_revocation_registry_definition(
        self, _profile: Profile, revocation_registry_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        resource_with_metadata = await self.resolver.resolve_resource(
            revocation_registry_id
        )
        revocation_registry_definition = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata

        (did, resource_id) = self.split_schema_id(revocation_registry_id)

        anoncreds_revocation_registry_definition = RevRegDef(
            issuer_id=did,
            cred_def_id=revocation_registry_definition["credDefId"],
            type=revocation_registry_definition["revocDefType"],
            tag=revocation_registry_definition["tag"],
            value=RevRegDefValue.deserialize(revocation_registry_definition["value"]),
        )

        return GetRevRegDefResult(
            revocation_registry_id=revocation_registry_id,
            revocation_registry=anoncreds_revocation_registry_definition,
            revocation_registry_metadata=metadata,
            resolution_metadata={},
        )

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        _options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""

        cred_def_result = await self.get_credential_definition(
            profile, revocation_registry_definition.cred_def_id
        )
        cred_def_res = cred_def_result.credential_definition_metadata.get("resourceName")
        resource_name = f"{cred_def_res}-{revocation_registry_definition.tag}"

        did = revocation_registry_definition.issuer_id
        resource_type = "anonCredsRevocRegDef"
        rev_reg_def = {
            "name": resource_name,
            "type": resource_type,
            "data": dict_to_b64(
                {
                    "revocDefType": revocation_registry_definition.type,
                    "tag": revocation_registry_definition.tag,
                    "value": revocation_registry_definition.value.serialize(),
                    "credDefId": revocation_registry_definition.cred_def_id,
                }
            ),
            "version": revocation_registry_definition.tag,
        }

        resource_state = await self._create_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            did,
            rev_reg_def,
        )
        job_id = resource_state.get("jobId")
        resource = resource_state.get("resource")
        resource_id = resource.get("id")
        resource_name = revocation_registry_definition.tag

        return RevRegDefResult(
            job_id=job_id,
            revocation_registry_definition_state=RevRegDefState(
                state=RevRegDefState.STATE_FINISHED,
                revocation_registry_definition_id=self.make_revocation_registry_id(
                    revocation_registry_definition, resource_id
                ),
                revocation_registry_definition=revocation_registry_definition,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            revocation_registry_definition_metadata={},
        )

    async def get_revocation_list(
        self,
        profile: Profile,
        revocation_registry_id: str,
        _timestamp_from: Optional[int] = 0,
        timestamp_to: Optional[int] = None,
    ) -> GetRevListResult:
        """Get a revocation list from the registry."""
        revocation_registry_definition = await self.get_revocation_registry_definition(
            profile,
            revocation_registry_id,
        )
        resource_name = revocation_registry_definition.revocation_registry_metadata.get(
            "resourceName"
        )
        (did, resource_id) = self.split_schema_id(revocation_registry_id)

        resource_type = "anonCredsStatusList"
        epoch_time = timestamp_to or int(time.time())
        dt_object = datetime.fromtimestamp(epoch_time, tz=timezone.utc)

        resource_time = dt_object.strftime("%Y-%m-%dT%H:%M:%SZ")
        resource_with_metadata = await self.resolver.resolve_resource(
            f"{did}?resourceType={resource_type}&resourceName={resource_name}&resourceVersionTime={resource_time}"
        )
        status_list = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata

        revocation_list = RevList(
            issuer_id=did,
            rev_reg_def_id=revocation_registry_id,
            revocation_list=status_list.get("revocationList"),
            current_accumulator=status_list.get("currentAccumulator"),
            timestamp=epoch_time,  # fix: return timestamp from resolution metadata
        )

        return GetRevListResult(
            revocation_list=revocation_list,
            resolution_metadata={},
            revocation_registry_metadata=metadata,
        )

    async def get_schema_info_by_id(
        self, profile: Profile, schema_id: str
    ) -> AnoncredsSchemaInfo:
        """Get a schema info from the registry."""
        resource_with_metadata = await self.resolver.resolve_resource(schema_id)
        schema = resource_with_metadata.resource
        (did, resource_id) = self.split_schema_id(schema_id)
        anoncreds_schema = AnoncredsSchemaInfo(
            issuer_id=did,
            name=schema["name"],
            version=schema["version"],
        )
        return anoncreds_schema

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        _options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        revocation_registry_definition = await self.get_revocation_registry_definition(
            profile,
            rev_list.rev_reg_def_id,
        )
        resource_name = revocation_registry_definition.revocation_registry_metadata.get(
            "resourceName"
        )
        resource_type = "anonCredsStatusList"
        rev_status_list = {
            "name": resource_name,
            "type": resource_type,
            "data": dict_to_b64(
                {
                    "revocationList": rev_list.revocation_list,
                    "currentAccumulator": rev_list.current_accumulator,
                    "revRegDefId": rev_list.rev_reg_def_id,
                }
            ),
            "version": str(uuid4()),
        }

        resource_state = await self._create_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            rev_reg_def.issuer_id,
            rev_status_list,
        )
        job_id = resource_state.get("jobId")
        resource = resource_state.get("resource")
        resource_id = resource.get("id")

        return RevListResult(
            job_id=job_id,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=rev_list,
            ),
            registration_metadata={},
            revocation_list_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
        )

    async def update_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        _prev_list: RevList,
        curr_list: RevList,
        _revoked: Sequence[int],
        _options: Optional[dict] = None,
    ) -> RevListResult:
        """Update a revocation list on the registry."""
        revocation_registry_definition = await self.get_revocation_registry_definition(
            profile,
            curr_list.rev_reg_def_id,
        )
        resource_name = revocation_registry_definition.revocation_registry_metadata.get(
            "resourceName"
        )
        resource_type = "anonCredsStatusList"
        rev_status_list = {
            "name": resource_name,
            "type": resource_type,
            "data": dict_to_b64(
                {
                    "revocationList": curr_list.revocation_list,
                    "currentAccumulator": curr_list.current_accumulator,
                    "revRegDefId": curr_list.rev_reg_def_id,
                }
            ),
            "version": str(uuid4()),
        }

        resource_state = await self._create_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            rev_reg_def.issuer_id,
            rev_status_list,
        )
        job_id = resource_state.get("jobId")
        resource = resource_state.get("resource")
        resource_id = resource.get("id")

        return RevListResult(
            job_id=job_id,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=curr_list,
            ),
            registration_metadata={},
            revocation_list_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
        )

    @staticmethod
    async def _create_and_publish_resource(
        profile: Profile, registrar_url: str, resolver_url: str, did: str, options: dict
    ) -> dict:
        """Create, Sign and Publish a Resource."""
        cheqd_manager = CheqdDIDManager(profile, registrar_url, resolver_url)
        async with profile.session() as session:
            wallet = session.inject_or(BaseWallet)
            if not wallet:
                raise WalletError("No wallet available")
            try:
                # request create resource operation
                create_request_res = await cheqd_manager.registrar.create_resource(
                    did, options
                )

                job_id: str = create_request_res.get("jobId")
                resource_state = create_request_res.get("resourceState")

                LOGGER.debug("JOBID %s", job_id)
                if resource_state.get("state") == "action":
                    signing_requests = resource_state.get("signingRequest")
                    if not signing_requests:
                        raise Exception("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )

                    # publish resource
                    publish_resource_res = await cheqd_manager.registrar.create_resource(
                        did,
                        {
                            "jobId": job_id,
                            "secret": {"signingResponse": signed_responses},
                        },
                    )
                    resource_state = publish_resource_res.get("resourceState")
                    if resource_state.get("state") != "finished":
                        raise AnonCredsRegistrationError(
                            f"Error publishing Resource {resource_state.get("reason")}"
                        )
                    return resource_state
                else:
                    raise AnonCredsRegistrationError(
                        f"Error publishing Resource {resource_state.get("reason")}"
                    )
            except Exception as err:
                raise AnonCredsRegistrationError(f"{err}")
