"""Authenticated OMF linker identity; executable coordinate semantics stay untouched."""
from dataclasses import replace
from pathlib import Path

import pytest

from tools.signatures.omf_pat import (
    PatFixupKind,
    PatLinkerIdentityVerdict,
    PatPublicName,
    PatReferenceDecodeVerdict,
    PatReferenceDecoding,
    _compile_pat_module_to_cached_regex,
    _decode_x86_16_near_rel16_field,
    _omf_fixup_kind,
    format_pat_module_line,
    generate_pat_from_omf_lib,
    match_pat_modules,
    parse_pat_file,
    parse_pat_line,
)
from tools.signatures.signature_catalog import (
    _decode_signature_catalog_match,
    _encode_signature_catalog_match,
)

pytestmark = pytest.mark.signatures


def _record(kind: int, payload: bytes) -> bytes:
    header = bytes([kind]) + (len(payload) + 1).to_bytes(2, 'little')
    return header + payload + bytes([(-sum(header + payload)) & 255])


def _name(text: str) -> bytes:
    data = text.encode('latin1')
    return bytes([len(data)]) + data


def _modules(tmp_path: Path):
    """Produce arbitrary catalog identities from a real minimal OMF library."""
    body = bytes.fromhex('b80200e90000') + bytes(range(0x30, 0x3f))
    obj = b''.join((
        _record(0x80, _name('identity.obj')),
        _record(0x96, _name('CODE') + _name('CODE')),
        _record(0x98, b'\x00' + len(body).to_bytes(2, 'little') + b'\x01\x02\x00'),
        _record(0x90, b'\x00\x01' + _name('_stubx') + b'\x00\x00\x00'
                + _name('ANCHORX') + b'\x06\x00\x00'),
        _record(0x8c, _name('ANCHORX') + b'\x00'),
        _record(0xa0, b'\x01\x00\x00' + body),
        _record(0x9c, bytes.fromhex('8404060101')),
        _record(0x8a, b''),
    ))
    page = 512
    padded = obj + bytes((-len(obj)) % page)
    header = bytearray(page)
    header[0] = 0xf0
    header[1:3] = (page - 3).to_bytes(2, 'little')
    header[3:7] = (page + len(padded)).to_bytes(4, 'little')
    header[7:9] = (1).to_bytes(2, 'little')
    lib = tmp_path / 'identity.lib'
    lib.write_bytes(bytes(header) + padded + bytes(page))
    catalog = tmp_path / 'identity.pat'
    assert generate_pat_from_omf_lib(lib, catalog) == 2
    modules = parse_pat_file(catalog)
    return next(m for m in modules if m.module_name == '_stubx'), next(m for m in modules if m.module_name == 'ANCHORX')


def _image(stubs=(0x100, 0x200, 0x600), anchor=0x400, targets=(0x106, 0x222, 0x400)):
    image = bytearray(b'\xcc' * (max((*stubs, anchor)) + 64))
    image[anchor:anchor + 15] = bytes(range(0x30, 0x3f))
    for offset, target in zip(stubs, targets, strict=True):
        image[offset:offset + 6] = bytes.fromhex('b80200e9') + (target - offset - 6).to_bytes(2, 'little', signed=True)
    return bytes(image)


def _match(image, modules, base=0x10000, architecture='x86_16'):
    return match_pat_modules(image, base, modules, backend='python_regex', architecture=architecture)


@pytest.mark.parametrize('cached', [False, True])
@pytest.mark.parametrize('base', [0x10000, 0x23400])
def test_authenticated_shifted_identity_and_cache_parity(tmp_path, cached, base):
    stub, anchor = _modules(tmp_path)
    modules = (stub, anchor)
    if cached:
        modules = tuple(_compile_pat_module_to_cached_regex(m) for m in modules)
    result = _match(_image(), modules, base)
    assert result.code_labels[base + 0x600] == 'stubx'
    assert result.code_ranges[base + 0x600] == (base + 0x600, base + 0x606)
    assert result.code_ranges[base + 0x400] == (base + 0x400, base + 0x40f)
    assert base + 0x100 not in result.code_labels and base + 0x200 not in result.code_labels
    proven = [e for e in result.linker_evidence if e.verdict is PatLinkerIdentityVerdict.PROVEN]
    assert len(proven) == 1 and proven[0].encoded_signed_displacement == -0x206
    assert _decode_signature_catalog_match(_encode_signature_catalog_match(result)) == result
    assert parse_pat_line(format_pat_module_line(stub)) == stub


@pytest.mark.parametrize('architecture', [None, 'x86_32', 'unregistered'])
def test_unregistered_architecture_refuses_repeated_identity(tmp_path, architecture):
    stub, anchor = _modules(tmp_path)
    result = _match(_image(), (stub, anchor), architecture=architecture)
    assert 0x10600 not in result.code_labels
    assert result.code_ranges[0x10400] == (0x10400, 0x1040f)


def test_default_architecture_does_not_admit_reference(tmp_path):
    modules = _modules(tmp_path)
    result = match_pat_modules(_image(), 0x10000, modules)
    assert 0x10600 not in result.code_labels


def test_unavailable_registered_decoder_refuses(tmp_path, monkeypatch):
    import tools.signatures.omf_pat as owner

    monkeypatch.setitem(owner._PAT_REFERENCE_FIELD_DECODERS, 'x86_16',
                        lambda *args: PatReferenceDecoding(PatReferenceDecodeVerdict.UNAVAILABLE))
    result = _match(_image(), _modules(tmp_path))
    assert 'stubx' not in result.code_labels.values()


@pytest.mark.parametrize('body,field', [
    (bytes.fromhex('b8e9ffff9090'), 2),
    (bytes.fromhex('b80200e900'), 4),
    (bytes.fromhex('b802009affff0000'), 4),
])
def test_decoder_refuses_nonboundary_truncated_or_far_field(body, field):
    result = _decode_x86_16_near_rel16_field(body, field, 0x10000 + field, 0, len(body))
    assert result.verdict is PatReferenceDecodeVerdict.REFUSED


def test_loader_resolved_offset_kind_is_unsupported():
    assert _omf_fixup_kind(True, 5, 2) is PatFixupKind.UNSUPPORTED


def test_truncated_explicit_addend_is_not_zero_evidence():
    from tools.signatures.omf_pat import _OMFDataRecordContext, _parse_fixupp_refs

    refs = _parse_fixupp_refs(bytes.fromhex('8404020101'),
                             _OMFDataRecordContext(1, 0, 6), ['', 'ANCHORX'], {}, {})
    assert refs == []


@pytest.mark.parametrize('field,value', [
    ('kind', PatFixupKind.UNSUPPORTED), ('width_bytes', 4),
    ('explicit_target_displacement', 7), ('source_library_sha256', ''),
    ('source_object_sha256', 'b' * 64), ('source_segment_index', 2),
    ('source_segment_offset', 5), ('fixupp_record_offset', 0),
    ('raw_fixupp_subrecord', bytes.fromhex('c404060101')),
    ('target_public_identity', 'forged'), ('offset', 3),
])
def test_forged_projection_refuses_otherwise_unique_hit(tmp_path, field, value):
    stub, anchor = _modules(tmp_path)
    forged = replace(stub, linker_references=(replace(stub.linker_references[0], **{field: value}),))
    result = _match(_image(stubs=(0x600,), targets=(0x400,)), (forged, anchor))
    assert 0x10600 not in result.code_labels
    assert result.code_ranges[0x10400] == (0x10400, 0x1040f)


def test_invalid_unique_projection_cannot_anchor(tmp_path):
    stub, _anchor = _modules(tmp_path)
    forged = replace(stub, public_names=(PatPublicName(0, 'ANCHORX'),))
    result = _match(_image(stubs=(0x100, 0x200, 0x600), targets=(0x600, 0x222, 0x400)), (stub, forged))
    assert result.code_labels == {} and result.code_ranges == {}


@pytest.mark.parametrize('targets', [(0x106, 0x222, 0x500), (0x400, 0x222, 0x400)])
def test_wrong_target_or_two_survivors_refuse(tmp_path, targets):
    result = _match(_image(targets=targets), _modules(tmp_path))
    assert all(name != 'stubx' for name in result.code_labels.values())


def test_ambiguous_anchor_and_cycles_do_not_bootstrap(tmp_path):
    stub, anchor = _modules(tmp_path)
    image = bytearray(_image())
    image[0x450:0x45f] = bytes(range(0x30, 0x3f))
    result = _match(bytes(image), (stub, anchor))
    assert result.code_labels == {}
    assert _match(_image(), (stub,)).code_labels == {}


def test_unwrapped_delta_refuses_65536_alias(tmp_path):
    stub, anchor = _modules(tmp_path)
    image = bytearray(b'\xcc' * 0x10500)
    image[0x10400:0x1040f] = bytes(range(0x30, 0x3f))
    image[0x600:0x606] = bytes.fromhex('b80200e9fafd')
    image[0x700:0x706] = bytes.fromhex('b80200e9fafc')
    result = _match(bytes(image), (stub, anchor))
    assert all(name != 'stubx' for name in result.code_labels.values())
    assert any(e.verdict is PatLinkerIdentityVerdict.DISPLACEMENT_OUT_OF_RANGE for e in result.linker_evidence)


@pytest.mark.parametrize('projection', ['', 'v1:', 'v2:forged', 'v1:bad'])
def test_malformed_projection_cannot_downgrade_to_legacy(tmp_path, projection):
    stub, _anchor = _modules(tmp_path)
    line = format_pat_module_line(stub).split(' | refs=')[0] + ' | refs=' + projection
    assert parse_pat_line(line) is None


def test_source_freshness_invalidates_projection(tmp_path):
    modules = _modules(tmp_path)
    assert 'stubx' in _match(_image(), modules).code_labels.values()
    Path(modules[0].source_path).write_bytes(b'not the producing library')
    assert 'stubx' not in _match(_image(), modules).code_labels.values()


def test_provenance_source_is_read_once_per_invocation_and_rechecked(tmp_path, monkeypatch):
    """Repeated modules share one fresh source fingerprint, never a stale one."""
    stub, anchor = _modules(tmp_path)
    modules = (stub, stub, stub, anchor)
    _match(_image(), modules)  # Warm the existing authoritative producer cache.
    source = Path(stub.source_path)
    original_read = Path.read_bytes
    reads = []

    def tracked_read(path):
        if path == source:
            reads.append(path)
        return original_read(path)

    monkeypatch.setattr(Path, 'read_bytes', tracked_read)
    assert 'stubx' in _match(_image(), modules).code_labels.values()
    assert len(reads) == 1
    source.write_bytes(b'changed source')
    assert 'stubx' not in _match(_image(), modules).code_labels.values()
    assert len(reads) == 2


def test_legacy_repeated_body_remains_refused(tmp_path):
    stub, anchor = _modules(tmp_path)
    stub = replace(stub, linker_references=())
    result = _match(_image(), (stub, anchor))
    assert 'stubx' not in result.code_labels.values()


def test_authentic_cmp16_private_regeneration(tmp_path):
    binary = Path('.cache/compiler-coverage/first16-independent-20261007/row-00/case-000/CMP16.EXE')
    library = Path('/home/xor/inertia_player/dos_compilers/Microsoft C v5.1/lib/SLIBCE.LIB')
    if not binary.is_file() or not library.is_file():
        pytest.skip('pinned fixtures unavailable')
    catalog = tmp_path / 'msc51.pat'
    assert generate_pat_from_omf_lib(library, catalog) > 0
    modules = tuple(m for m in parse_pat_file(catalog) if m.module_name in ('__fptrap', '__amsg_exit'))
    data = binary.read_bytes()
    image = data[int.from_bytes(data[8:10], 'little') * 16:]
    result = _match(image, modules)
    assert result.code_ranges[0x104a5] == (0x104a5, 0x104b4)
    assert result.code_ranges[0x10644] == (0x10644, 0x1064a)
    assert 0x1004e not in result.code_labels and 0x10208 not in result.code_labels
