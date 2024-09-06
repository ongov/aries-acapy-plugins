"""MSO_MDOC Crendential Handler Plugin."""

from importlib.util import find_spec

from aries_cloudagent.config.injection_context import InjectionContext
from mso_mdoc.cred_processor import MsoMdocCredProcessor
from oid4vc.cred_processor import CredProcessors

cwt = find_spec("cwt")
pycose = find_spec("pycose")
cbor2 = find_spec("cbor2")
cbor_diag = find_spec("cbor_diag")
if not all((cwt, pycose, cbor2, cbor_diag)):
    raise ImportError("`mso_mdoc` extra required")


async def setup(context: InjectionContext):
    """Setup the plugin."""
    processors = context.inject(CredProcessors)
    mso_mdoc = MsoMdocCredProcessor()
    processors.register(mso_mdoc)
