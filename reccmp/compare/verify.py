"""Part of the core analysis/comparison logic of `reccmp`.
These functions report problems with the current entities that limit or block further analysis.
"""

import logging
import struct
from reccmp.formats.pe import PEImage
from reccmp.types import EntityType, ImageId
from .db import EntityDb

logger = logging.getLogger(__name__)


def _code_ranges(image: PEImage) -> list[tuple[int, int]]:
    return [(r.addr, r.addr + r.size) for r in image.get_code_regions()]


def _vtable_slots(image: PEImage, addr: int, limit: int, ranges) -> int:
    """Length of the vtable in slots: the run of pointers into executable code.
    Anything else, a null or the next object's data, ends the table."""
    limit = 4 * (max(limit, 0) // 4)
    if limit == 0:
        return 0

    try:
        table = image.read(addr, limit)
    except Exception:  # pylint: disable=broad-except
        return 0

    if table is None:
        return 0

    slots = 0
    for (ptr,) in struct.iter_unpack("<L", table):
        if not any(lo <= ptr < hi for lo, hi in ranges):
            break
        slots += 1

    return slots


def check_vtables(db: EntityDb, orig_bin: PEImage, recomp_bin: PEImage):
    """Alert to cases where the recomp vtable is larger than the one in the orig binary.

    Both sides are measured the same way, by counting the run of pointers into
    code. Comparing a recorded size against the orig bytes does not work: the
    size of a vtable symbol is the gap to the next symbol, so it includes any
    trailing alignment, and reading that many bytes runs into whatever follows.
    """
    orig_ranges = _code_ranges(orig_bin)
    recomp_ranges = _code_ranges(recomp_bin)

    for match in db.get_matches_by_type(EntityType.VTABLE):
        assert (
            match.name is not None
            and match.orig_addr is not None
            and match.recomp_addr is not None
        )

        # Bound each side by the distance to the next entity in its own image.
        # Without that the count runs straight into the following vtable, whose
        # slots are valid code pointers too.
        orig_limit = match.max_size(ImageId.ORIG)
        recomp_limit = match.max_size(ImageId.RECOMP)
        if orig_limit is None or recomp_limit is None:
            continue

        orig_slots = _vtable_slots(orig_bin, match.orig_addr, orig_limit, orig_ranges)
        recomp_slots = _vtable_slots(
            recomp_bin, match.recomp_addr, recomp_limit, recomp_ranges
        )

        if recomp_slots > orig_slots:
            logger.warning(
                "Recomp vtable is larger than orig vtable for %s", match.name
            )
