import pytest
from antivenom.core.chunk import Chunk


def test_chunk_basic():
    c = Chunk(text="hello world", source_id="doc.pdf")
    assert c.text == "hello world"
    assert c.source_id == "doc.pdf"


def test_chunk_frozen():
    c = Chunk(text="test")
    with pytest.raises((AttributeError, TypeError)):
        c.text = "changed"  # type: ignore[misc]


def test_chunk_default_metadata():
    c = Chunk(text="test")
    assert c.metadata == {}


def test_chunk_type_guard():
    with pytest.raises(TypeError):
        Chunk(text=123)  # type: ignore[arg-type]
