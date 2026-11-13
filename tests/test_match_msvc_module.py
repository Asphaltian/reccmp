"""Tests MSVC match strategies that pair a file-static function or its local static by object"""

import pytest
from reccmp.types import EntityType, ImageId
from reccmp.compare.db import EntityDb, ReccmpEntity
from reccmp.compare.match_msvc import match_functions, match_variables


@pytest.fixture(name="db")
def fixture_db() -> EntityDb:
    return EntityDb()


def get_entity(db: EntityDb, image_id: ImageId, addr: int) -> ReccmpEntity:
    ent = db.get(image_id, addr)
    assert ent is not None
    return ent


def test_match_functions_module(db: EntityDb):
    """A file-static function defined in several objects pairs within the
    object the original row names."""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 100, type=EntityType.FUNCTION, name="sync", module="b.obj"
        )
        batch.set(
            ImageId.ORIG, 101, type=EntityType.FUNCTION, name="sync", module="a.obj"
        )
        batch.set(
            ImageId.RECOMP,
            200,
            type=EntityType.FUNCTION,
            name="sync",
            module=r"C:\build\a.cpp.obj",
        )
        batch.set(
            ImageId.RECOMP,
            201,
            type=EntityType.FUNCTION,
            name="sync",
            module=r"C:\build\b.cpp.obj",
        )

    match_functions(db)

    assert get_entity(db, ImageId.ORIG, 100).recomp_addr == 201
    assert get_entity(db, ImageId.ORIG, 101).recomp_addr == 200


def test_match_functions_module_then_name(db: EntityDb):
    """A row with a module takes its copy first, so a row without one does
    not claim it."""
    with db.batch() as batch:
        batch.set(ImageId.ORIG, 100, type=EntityType.FUNCTION, name="sync")
        batch.set(
            ImageId.ORIG, 101, type=EntityType.FUNCTION, name="sync", module="a.obj"
        )
        batch.set(
            ImageId.RECOMP, 200, type=EntityType.FUNCTION, name="sync", module="a.obj"
        )
        batch.set(
            ImageId.RECOMP, 201, type=EntityType.FUNCTION, name="sync", module="b.obj"
        )

    match_functions(db)

    assert get_entity(db, ImageId.ORIG, 101).recomp_addr == 200
    assert get_entity(db, ImageId.ORIG, 100).recomp_addr == 201


def test_match_variables_static_by_module(db: EntityDb):
    """A function-local static of a file-static function defined in several
    objects pairs by its full symbol within the named object."""
    with db.batch() as batch:
        batch.set(
            ImageId.ORIG, 100, type=EntityType.DATA, name="s___sync", module="b.obj"
        )
        batch.set(
            ImageId.RECOMP,
            200,
            type=EntityType.DATA,
            name="s",
            symbol="s___sync",
            module="a.obj",
        )
        batch.set(
            ImageId.RECOMP,
            201,
            type=EntityType.DATA,
            name="s",
            symbol="s___sync",
            module="b.obj",
        )

    match_variables(db)

    assert get_entity(db, ImageId.ORIG, 100).recomp_addr == 201
