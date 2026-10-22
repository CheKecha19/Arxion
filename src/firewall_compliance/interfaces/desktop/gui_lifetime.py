"""Циклические Tk-объекты освобождаются только потоком владельца GUI."""

import gc
from threading import get_ident


class GuiGarbageCollector:
    """Отключает автоматическую сборку; GUI периодически вызывает collect."""

    def __init__(self) -> None:
        self.owner = get_ident()
        gc.disable()

    def collect(self) -> None:
        if get_ident() != self.owner:
            raise RuntimeError("Сборка Tk-объектов разрешена только в GUI-потоке")
        gc.collect()
