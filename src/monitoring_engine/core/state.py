# state.py
from dataclasses import dataclass
from typing import Optional


@dataclass
class NetPrevState:
    ts: Optional[float] = None
    bytes_sent: Optional[int] = None
    bytes_recv: Optional[int] = None
    iface_name: Optional[str] = None


NET_PREV = NetPrevState()