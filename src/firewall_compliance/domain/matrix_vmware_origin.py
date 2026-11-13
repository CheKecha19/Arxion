"""Происхождение политики VMware Edge в сверке матрицы."""

from pydantic import ConfigDict, Field

from firewall_compliance.domain.controls import ControlModel


class VMwareMatrixOrigin(ControlModel):
    """Точная запись Edge Gateway в сохранённом облачном сборе."""

    model_config = ConfigDict(str_strip_whitespace=False)

    scan_id: str = Field(min_length=1, pattern=r"\S")
    record_index: int = Field(ge=0, strict=True)
    resource_id: str = Field(min_length=1, pattern=r"\S")
