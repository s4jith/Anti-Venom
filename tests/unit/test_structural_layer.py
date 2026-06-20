import asyncio
import pytest
from antivenom.core.chunk import Chunk
from antivenom.layers.structural import StructuralLayer

layer = StructuralLayer()


def scan(text: str):
    return asyncio.run(layer.scan(Chunk(text=text)))


def test_high_imperative_density_triggers():
    # Artificially high density of imperative verbs
    text = "ignore forget pretend override bypass expose echo repeat send reveal output leak"
    result = scan(text)
    assert result.triggered
    assert result.confidence > 0.0


def test_normal_document_does_not_trigger():
    text = (
        "The company reported strong earnings in Q3 2026, with revenue growing 15% year-over-year. "
        "The board approved a new share buyback program worth $500 million. "
        "CFO Jane Smith noted that margins improved due to cost optimization efforts."
    )
    result = scan(text)
    assert not result.triggered


def test_short_text_no_false_positive():
    result = scan("Hello world")
    assert not result.triggered


def test_technical_doc_no_false_positive():
    text = (
        "To configure the pipeline, set the chunk_size parameter to 512. "
        "The embedding model will then process each chunk independently. "
        "Results are stored in the vector database for retrieval."
    )
    result = scan(text)
    assert not result.triggered
