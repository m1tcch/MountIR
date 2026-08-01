#!/usr/bin/env python3
"""Handler registry: maps ImageType -> handler class."""

from detector import ImageType
from handlers.base import BaseHandler
from handlers.ewf import EwfHandler
from handlers.raw import RawHandler
from handlers.vmdk import VmdkHandler
from handlers.vhd import VhdHandler
from handlers.iso import IsoHandler
from handlers.aff import AffHandler
from handlers.aff4 import Aff4Handler
from handlers.qcow import QcowHandler
from handlers.split_raw import SplitRawHandler
from handlers.vdi import VdiHandler
from handlers.ova import OvaHandler
from handlers.dmg import DmgHandler
from handlers.sparseimage import SparseImageHandler
from handlers.xva import XvaHandler


# Registry mapping ImageType -> handler instance factory
HANDLER_REGISTRY = {
    ImageType.E01: lambda: EwfHandler(),
    ImageType.L01: lambda: EwfHandler(),
    ImageType.VMDK: lambda: VmdkHandler(),
    ImageType.VHD: lambda: VhdHandler(is_vhdx=False),
    ImageType.VHDX: lambda: VhdHandler(is_vhdx=True),
    ImageType.RAW: lambda: RawHandler(),
    ImageType.ISO: lambda: IsoHandler(),
    ImageType.AFF: lambda: AffHandler(),
    ImageType.AFF4: lambda: Aff4Handler(),
    ImageType.QCOW2: lambda: QcowHandler(),
    ImageType.SPLIT_RAW: lambda: SplitRawHandler(),
    ImageType.VDI: lambda: VdiHandler(),
    ImageType.OVA: lambda: OvaHandler(),
    ImageType.DMG: lambda: DmgHandler(),
    ImageType.SPARSEIMAGE: lambda: SparseImageHandler(),
    ImageType.XVA: lambda: XvaHandler(),
}

# All handler classes (for 'check' command)
ALL_HANDLER_CLASSES = [
    EwfHandler, RawHandler, VmdkHandler, VhdHandler,
    IsoHandler, AffHandler, Aff4Handler, QcowHandler,
    SplitRawHandler, VdiHandler, OvaHandler, DmgHandler,
    SparseImageHandler, XvaHandler,
]

# Image types that don't have partition tables (mount directly to filesystem)
NO_PARTITION_TYPES = {ImageType.ISO, ImageType.L01}


def get_handler(image_type: ImageType) -> BaseHandler:
    """Return the appropriate handler instance for an image type."""
    factory = HANDLER_REGISTRY.get(image_type)
    if not factory:
        raise ValueError(f"No handler for image type: {image_type}")
    return factory()
