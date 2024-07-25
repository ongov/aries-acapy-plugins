import pytest

from aries_cloudagent.admin.request_context import AdminRequestContext

from oid4vci.models.exchange import OID4VCIExchangeRecord
from oid4vci.models.supported_cred import SupportedCredential
from oid4vci.public_routes import PopResult


@pytest.fixture
def body():
    yield {
        "format": "mso_mdoc",
        "doctype": "org.iso.18013.5.1.mDL",
        "proof": {
            "proof_type": "jwt",
            "jwt": "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkJHVU5OTlpFSm9Cd05UU25NOW93WGVCdTBOTFJEVjR4d1llTm9kMVpxQUEiLCJ5IjoiZjlJTVhQS2xlU0FGb2tRdTc1Qlk3Nkl0QWpjVUxHWDlCeVZ0ZFVINEs0YyJ9LCJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJpYXQiOjE3MjA3MzMxMTAsImV4cCI6MTcyMDczNDkxMCwiYXVkIjoiaHR0cHM6Ly9vaWQ0dmNpLnN0Zy5uZ3Jvay5pbyIsIm5vbmNlIjoiWWM4em9odk9XREFTVzh6QnA5Y1MxZyIsImlzcyI6ImRpZDprZXk6NjZhVVVobzhQdjNVaU16ZHBxdUFGVHJWa01DeEpocUJTN3BVdjFqQzhleHdFZ2FndVRNUEppa3NlV2N1U0RqYUtlMzZKanM3cnlVWnZKQVp4UGZZVUVKIn0.1ozjqUDtYzBecSEln9dANpSNBXNxEkws2ZWWaYim5B07QmlELi0nvoh3ooUUeu4Q_7ru_FXjQCIM7xgAVCrbxw",
        },
    }


@pytest.fixture
def supported():
    yield SupportedCredential(format_data={"doctype": "org.iso.18013.5.1.mDL"})


@pytest.fixture
def ex_record():
    yield OID4VCIExchangeRecord(
        state=OID4VCIExchangeRecord.STATE_OFFER_CREATED,
        verification_method="did:key:z6Mkn6z3Eg2mrgQmripNPGDybZYYojwZw1VPjRkCzbNV7JfN#0",
        issuer_id="did:key:z6Mkn6z3Eg2mrgQmripNPGDybZYYojwZw1VPjRkCzbNV7JfN",
        supported_cred_id="456",
        credential_subject={"name": "alice"},
        nonce="789",
        pin="000",
        code="111",
        token="222",
    )


@pytest.fixture
def pop():
    yield PopResult(
        headers=None,
        payload=None,
        verified=True,
        holder_kid="did:key:example-kid#0",
        holder_jwk=None,
    )


@pytest.fixture
def context():
    """Test AdminRequestContext."""
    yield AdminRequestContext.test_context()


@pytest.fixture
def jwk():
    yield {
        "kty": "OKP",
        "crv": "ED25519",
        "x": "cavH81X96jQL8vj3gbLQBkeE7p9cyVu8MJcC5N6lXOU=",
        "d": "NsSTmfmS-D15umO64Ongi22HYcHBr7l1nl7OGurQReA",
    }


@pytest.fixture
def did():
    yield {
        "did": "did:key:z6Mkn6z3Eg2mrgQmripNPGDybZYYojwZw1VPjRkCzbNV7JfN",
        "verkey": "8eizeRnLX8vJkDyfhhG8kTzYzAfiX8F33QqHAKQUC5sz",
        "private_key": "NsSTmfmS-D15umO64Ongi22HYcHBr7l1nl7OGurQReA",
        "public_key": "cavH81X96jQL8vj3gbLQBkeE7p9cyVu8MJcC5N6lXOU=",
    }


@pytest.fixture
def headers():
    yield {
        "doctype": "org.iso.18013.5.1.mDL",
        "deviceKey": "12345678123456781234567812345678",
    }


@pytest.fixture
def payload():
    yield {
        "did": "did:key:z6Mkn6z3Eg2mrgQmripNPGDybZYYojwZw1VPjRkCzbNV7JfN",
        "headers": {"deviceKey": "12345678123456781234567812345678"},
        "payload": {
            "org.iso.18013.5.1": {
                "expiry_date": "2029-03-31",
                "issue_date": "2024-04-01",
                "issuing_country": "CA",
                "issuing_authority": "Ontario Ministry of Transportation",
                "family_name": "Doe",
                "given_name": "John",
                "birth_date": "1990-03-31",
                "document_number": "DJ123-45678-90123",
                "un_distinguishing_sign": "CDN",
            }
        },
    }


@pytest.fixture
def issuer_auth():
    """mso.encode()"""
    yield "5904c7d28459012da301270458206196787ec61cf41d9f4cfa97dc4413907e8b8ff6c55694bc5ebd07c0d9b7950318215901023081ff3081b2a003020102021412978ff28a5d42d94382c1cfdcac025b9fc49e8d300506032b65703020310b300906035504061302434e3111300f06035504030c084c6f63616c204341301e170d3234303731373033343331335a170d3234303732373033343331335a3020310b300906035504061302434e3111300f06035504030c084c6f63616c204341302a300506032b657003210071abc7f355fdea340bf2f8f781b2d0064784ee9f5cc95bbc309702e4dea55ce5300506032b657003410080fe1045fc0ef68af9c3ddf53de8934826c78fb45f4c8d82e79b1f2673bb1e485ce2e7b482be6f398497ca56d2c2e192a8f8b39b05bb21fe7aa2d61cc5655506a118215901023081ff3081b2a003020102021412978ff28a5d42d94382c1cfdcac025b9fc49e8d300506032b65703020310b300906035504061302434e3111300f06035504030c084c6f63616c204341301e170d3234303731373033343331335a170d3234303732373033343331335a3020310b300906035504061302434e3111300f06035504030c084c6f63616c204341302a300506032b657003210071abc7f355fdea340bf2f8f781b2d0064784ee9f5cc95bbc309702e4dea55ce5300506032b657003410080fe1045fc0ef68af9c3ddf53de8934826c78fb45f4c8d82e79b1f2673bb1e485ce2e7b482be6f398497ca56d2c2e192a8f8b39b05bb21fe7aa2d61cc5655506590248a66776657273696f6e63312e306f646967657374416c676f726974686d667368613235366c76616c756544696765737473a1716f72672e69736f2e31383031332e352e31a90058200f80559d7f614f73cb8feb11d6fa6889c6cb3cce2e6116f2762e6bb18fe98686015820e7c276c74760d3004bb227627cf6bafb7d8260e8cdee7dd1e7417a1e5e4565a4025820d6701ca377cfd49b16c662abba87610e458e95163093d46004de3bc072976880035820c060377bc483de60cfc5a19ef0c61b5485127af944355d1eb64617972b9cf7c604582030d6f95910e800d2849992b0eba7de32998e2de1e91036fd3498c472a583c9a2055820155c35da62e635ab1b2ba78c7eea82c93436696643efe4ec86b9854711131602065820bdec6c1e2afea89273eaed5319379e89f04f816c647cdfe0dd50128fb69802a907582016e7d7f6d2c59d30851d8b9444456500790ddda6a2d9206c0081a5cad8087637085820cb52b000d1086b14f97f760f9c3ecc73c128db19579841f12a9b7c4e865ab7736d6465766963654b6579496e666fa1696465766963654b65797820313233343536373831323334353637383132333435363738313233343536373867646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fa3667369676e656456c074323032342d30372d31375430333a34333a31335a6976616c696446726f6d56c074323032342d30372d31375430333a34333a31335a6a76616c6964556e74696c56c074323032352d30372d31375430333a34333a31335a58409de675d2fd0f64de7fd4ed6900344b3e04561324b616961b61e0caeb4d39d581226ae6131c87f6713af599f20183d777e1f260b56fb0f42212bd7f188e5c760c"


@pytest.fixture
def mso_mdoc():
    yield "a36776657273696f6e63312e3069646f63756d656e747381a267646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c6973737565725369676e6564a26a6e616d65537061636573a1716f72672e69736f2e31383031332e352e3189d818586ea4686469676573744944006672616e646f6d582061f2f331ac88ad719976a6cc9f0940f23851a601c001430511424ceee35afbc171656c656d656e744964656e74696669657276756e5f64697374696e6775697368696e675f7369676e6c656c656d656e7456616c75656343444ed8185866a4686469676573744944016672616e646f6d582099ce495059e7e0ae8a044774a8596247d5b33a02b9d35133e2dff8b49839d88e71656c656d656e744964656e7469666965726f69737375696e675f636f756e7472796c656c656d656e7456616c7565624341d818586ca4686469676573744944026672616e646f6d5820a43e5279c96bc9864f0ee21048d8d46ef5ad553be3c8d41ef95161f736f9cc3071656c656d656e744964656e7469666965726a69737375655f646174656c656c656d656e7456616c7565d903ec6a323032342d30342d3031d8185889a4686469676573744944036672616e646f6d5820bb9f9145a1aa4d4a7a984893908ccc6e3db77b9de80db82d55c96028bc24ffa671656c656d656e744964656e7469666965727169737375696e675f617574686f726974796c656c656d656e7456616c756578224f6e746172696f204d696e6973747279206f66205472616e73706f72746174696f6ed818586ca4686469676573744944046672616e646f6d5820f4e468dd304e1ca775d3ca2398983bbad56671bc54547b38d04b61bd9d0edc6271656c656d656e744964656e7469666965726a62697274685f646174656c656c656d656e7456616c7565d903ec6a313939302d30332d3331d8185875a4686469676573744944056672616e646f6d58200b7412d206bc6e92e10bdf5f9c1b93a52d5d42c5052423bccaa595bea8e46e1a71656c656d656e744964656e7469666965726f646f63756d656e745f6e756d6265726c656c656d656e7456616c756571444a3132332d34353637382d3930313233d8185863a4686469676573744944066672616e646f6d5820c5901315a7a97b9af60e78965ce0fd0e3465e7dbb5d1f60b5ddb7f4bd1b783c871656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456616c756563446f65d818586da4686469676573744944076672616e646f6d582060c7538805bfee9fbdb4ece8cb1e83dbdb17b99ca6fdc51dc3806ae791e6dbb171656c656d656e744964656e7469666965726b6578706972795f646174656c656c656d656e7456616c7565d903ec6a323032392d30332d3331d8185863a4686469676573744944086672616e646f6d5820db795a0aefad87042012dbc8adb7cad0c734cf66049570666f0b42555364cb5e71656c656d656e744964656e7469666965726a676976656e5f6e616d656c656c656d656e7456616c7565644a6f686e6a697373756572417574688459012da3012704582078872c0f24908935938c69960b05bab2766904db2ac26ed9928a08d232662ab818215901023081ff3081b2a00302010202147a498062fa06687807d711a26af37ef36811d5a9300506032b65703020310b300906035504061302434e3111300f06035504030c084c6f63616c204341301e170d3234303731373031323334315a170d3234303732373031323334315a3020310b300906035504061302434e3111300f06035504030c084c6f63616c204341302a300506032b657003210071abc7f355fdea340bf2f8f781b2d0064784ee9f5cc95bbc309702e4dea55ce5300506032b65700341001538625bdd0f1ded7b80ce7aed09ec00ec666283811b58c1034f735bd6d92d68b218ad91065ce36af8eacbd8ec9cd185c0ae77620af777b27b784af0af399d0ea118215901023081ff3081b2a00302010202147a498062fa06687807d711a26af37ef36811d5a9300506032b65703020310b300906035504061302434e3111300f06035504030c084c6f63616c204341301e170d3234303731373031323334315a170d3234303732373031323334315a3020310b300906035504061302434e3111300f06035504030c084c6f63616c204341302a300506032b657003210071abc7f355fdea340bf2f8f781b2d0064784ee9f5cc95bbc309702e4dea55ce5300506032b65700341001538625bdd0f1ded7b80ce7aed09ec00ec666283811b58c1034f735bd6d92d68b218ad91065ce36af8eacbd8ec9cd185c0ae77620af777b27b784af0af399d0e59024dd818590248a66776657273696f6e63312e306f646967657374416c676f726974686d667368613235366c76616c756544696765737473a1716f72672e69736f2e31383031332e352e31a90058208cd10d0dccfa82ae19f69d9fae862bd96fe9ada4408eca7a9b0bac23aa76c35801582052095b1cc5a77eb8c1a424c9b0800b3ca928eb4199cf2d27237076aaa3c410d402582071fbf717bf874cef36cdee8c50edb686e8f9eca3618634298f1dbc99cd590094035820b493bef6da0728d971243012ab9bd8514f910c5787dd899c2eadecda7c846d3704582032aeab097b60bf5698dd31e44349a9af03c968cc28b6f9ce35812846224b2c780558203c3bde3dd6499fad865079e968fabc547666014eaa5301bbdf194774017cb0380658202a493ea48cb7b6112a75e0f97988da30e161469071f2e2537b96931352201c230758203c747db61a07c1049738ddf8d4d493920c9ff712a7cb87b6f60f9ef3734b6c100858205feb7eae0e91f2959a633de186a933beac7efdf4effb2fe02aa27724e04c15686d6465766963654b6579496e666fa1696465766963654b65797820313233343536373831323334353637383132333435363738313233343536373867646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fa3667369676e656456c074323032342d30372d31375430313a32333a34315a6976616c696446726f6d56c074323032342d30372d31375430313a32333a34315a6a76616c6964556e74696c56c074323032352d30372d31375430313a32333a34315a5840de150a918590a131a9188e0a2cb49d0a7eaae28447c322441512cd7cb77a77ede5d58f21a99c7fe7199b965b7a8b94e46960d898e0a880dd492a0786fad032036673746174757300"
